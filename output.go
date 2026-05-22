package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// sink writes records in a chosen format. emit receives the (possibly
// enriched) record as an ordered map. close flushes any framing.
type sink interface {
	emit(map[string]json.RawMessage) error
	close() error
}

func newSink(w io.Writer, format string, fields []string, useExport bool, entity string) (sink, error) {
	switch format {
	case "jsonl", "ndjson":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return &jsonlSink{w: w, enc: enc}, nil
	case "json":
		return &jsonArraySink{w: w}, nil
	case "csv":
		return &csvSink{
			w:         csv.NewWriter(w),
			fields:    fields,
			useExport: useExport,
			entity:    entity,
		}, nil
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

// jsonl: one JSON object per line, in original field order from the API.
type jsonlSink struct {
	w   io.Writer
	enc *json.Encoder
}

func (s *jsonlSink) emit(rec map[string]json.RawMessage) error {
	// Encode the map directly. Field order is not preserved for jsonl; that's
	// acceptable for newline-delimited JSON consumers.
	return s.enc.Encode(rec)
}

func (s *jsonlSink) close() error { return nil }

// json: a single pretty-ish array.
type jsonArraySink struct {
	w     io.Writer
	first bool
	open  bool
}

func (s *jsonArraySink) emit(rec map[string]json.RawMessage) error {
	if !s.open {
		if _, err := s.w.Write([]byte("[\n")); err != nil {
			return err
		}
		s.open = true
		s.first = true
	}
	if !s.first {
		if _, err := s.w.Write([]byte(",\n")); err != nil {
			return err
		}
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := s.w.Write(buf); err != nil {
		return err
	}
	s.first = false
	return nil
}

func (s *jsonArraySink) close() error {
	if !s.open {
		_, err := s.w.Write([]byte("[]\n"))
		return err
	}
	_, err := s.w.Write([]byte("\n]\n"))
	return err
}

// csv: header row inferred from first record (or --fields), one row per record.
// Nested values get JSON-encoded. Enrichment results get summarized to a
// human-friendly string when possible.
type csvSink struct {
	w          *csv.Writer
	fields     []string // explicit column order; empty = infer from first record
	useExport  bool
	entity     string
	headerDone bool
}

func (s *csvSink) emit(rec map[string]json.RawMessage) error {
	if !s.headerDone {
		if len(s.fields) == 0 {
			s.fields = defaultColumns(s.entity, rec, s.useExport)
		}
		if err := s.w.Write(s.fields); err != nil {
			return err
		}
		s.headerDone = true
	}

	row := make([]string, len(s.fields))
	for i, col := range s.fields {
		raw, ok := rec[col]
		if !ok {
			row[i] = ""
			continue
		}
		row[i] = formatCell(raw)
	}
	return s.w.Write(row)
}

func (s *csvSink) close() error {
	s.w.Flush()
	return s.w.Error()
}

// defaultColumns picks a sensible CSV header order. For known entities we
// hand-pick a useful subset; otherwise we union all keys present in the first
// record. Any gen_* field present in the record but not in the base list is
// always appended so AI-generated content (gen_impact, gen_mitigations, etc.)
// is exported out of the box.
func defaultColumns(entity string, rec map[string]json.RawMessage, useExport bool) []string {
	var cols []string
	switch entity {
	case "vulnerabilities":
		cols = []string{
			"uuid", "cve_id", "state", "published_at",
			"description",
			"cvss_base_score", "cvss_version", "cvss_vector", "cvss_type",
			"epss_score", "epss_percentile",
			"cisa_kev_added_at",
			"mentions_count", "exploits_count", "exploitations_count",
		}
		if useExport {
			cols = append(cols, "impacted_products_count", "impacted_products",
				"exploits_summary", "advisories_summary")
		}
	case "actors":
		cols = []string{"uuid", "internal_name", "display_name", "description",
			"motivation", "sponsor", "family_name",
			"source_countries", "targeted_countries", "targeted_industries",
			"attack_patterns_count", "mentions_count",
			"created_at", "updated_at"}
	case "malware":
		cols = []string{"uuid", "internal_name", "display_name", "description",
			"mentions_count", "created_at", "updated_at"}
	default:
		keys := make([]string, 0, len(rec))
		for k := range rec {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		cols = reorderColumns(keys, []string{
			"uuid", "cve_id", "name", "display_name", "internal_name",
			"description",
			"cvss_base_score", "cvss_version", "cvss_vector", "cvss_type",
			"epss_score", "epss_percentile",
			"state", "cisa_kev_added_at", "published_at",
			"created_at", "updated_at", "enriched_at",
		})
	}
	return appendGenFields(cols, rec)
}

// appendGenFields appends every gen_* key from rec that isn't already in cols.
// They're sorted so the column order is stable across runs.
func appendGenFields(cols []string, rec map[string]json.RawMessage) []string {
	existing := make(map[string]bool, len(cols))
	for _, c := range cols {
		existing[c] = true
	}
	var gens []string
	for k := range rec {
		if strings.HasPrefix(k, "gen_") && !existing[k] {
			gens = append(gens, k)
		}
	}
	sort.Strings(gens)
	return append(cols, gens...)
}

func reorderColumns(have []string, preferred []string) []string {
	idx := make(map[string]bool, len(have))
	for _, h := range have {
		idx[h] = true
	}
	out := make([]string, 0, len(have))
	seen := make(map[string]bool, len(have))
	for _, p := range preferred {
		if idx[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	for _, h := range have {
		if !seen[h] {
			out = append(out, h)
		}
	}
	return out
}

// formatCell turns a raw JSON value into a CSV cell string.
//   - null  -> ""
//   - string -> the string (unquoted; csv writer handles escaping)
//   - number/bool -> compact form
//   - arrays/objects -> compact JSON
func formatCell(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	case 't', 'f':
		return string(raw)
	case '[', '{':
		// Try to summarize arrays of objects with display_name/name fields.
		var arr []map[string]json.RawMessage
		if raw[0] == '[' && json.Unmarshal(raw, &arr) == nil {
			parts := make([]string, 0, len(arr))
			for _, item := range arr {
				parts = append(parts, summarizeItem(item))
			}
			return joinNonEmpty(parts, "; ")
		}
		return string(raw)
	default:
		// number
		var n json.Number
		if err := json.Unmarshal(raw, &n); err == nil {
			return string(n)
		}
	}
	return string(raw)
}

func summarizeItem(item map[string]json.RawMessage) string {
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := item[k]; ok {
				if s := formatCell(v); s != "" {
					return s
				}
			}
		}
		return ""
	}
	primary := pick("display_name", "name", "title", "cve_id", "id")
	org := pick("organization_display_name", "organization_name")
	switch {
	case primary != "" && org != "":
		return org + " " + primary
	case primary != "":
		return primary
	}
	// Fall back to a uuid or stringified blob.
	if v, ok := item["uuid"]; ok {
		return formatCell(v)
	}
	buf, _ := json.Marshal(item)
	return string(buf)
}

func joinNonEmpty(parts []string, sep string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}

