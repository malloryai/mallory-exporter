package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// exportPrimaryKey maps a list-endpoint entity name to the wrapper key used
// inside the /export response that holds the entity itself.
var exportPrimaryKey = map[string]string{
	"actors":                        "actor",
	"breaches":                      "breach",
	"exploits":                      "exploit",
	"malware":                       "malware",
	"organizations":                 "organization",
	"products":                      "product",
	"stories":                       "story",
	"technology_product_advisories": "technology_product_advisory",
	"vulnerabilities":               "vulnerability",
}

func entitySupportsExport(entity string) bool {
	_, ok := exportPrimaryKey[strings.Trim(entity, "/ ")]
	return ok
}

// exportOne fetches /v1/<entity>/<uuid>/export for the given record and returns
// the parsed bundle. If the record has no uuid, returns (nil, nil).
func (c *client) exportOne(ctx context.Context, entity string, rec map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	id := stringField(rec, "uuid")
	if id == "" {
		id = stringField(rec, "cve_id")
	}
	if id == "" {
		return nil, nil
	}
	path := fmt.Sprintf("%s/v1/%s/%s/export", c.baseURL, strings.Trim(entity, "/ "), id)
	body, err := c.doGET(ctx, path)
	if err != nil {
		return nil, err
	}
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, fmt.Errorf("decode export bundle: %w", err)
	}
	return bundle, nil
}

func stringField(rec map[string]json.RawMessage, key string) string {
	raw, ok := rec[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// flattenExport reshapes an /export bundle into a flat top-level map suitable
// for CSV/JSON output. For vulnerabilities it surfaces an impacted_products
// column derived from vulnerable_configurations[].vendor + product name.
func flattenExport(entity string, bundle map[string]json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}

	primaryKey := exportPrimaryKey[strings.Trim(entity, "/ ")]
	if raw, ok := bundle[primaryKey]; ok {
		var primary map[string]json.RawMessage
		if err := json.Unmarshal(raw, &primary); err == nil {
			for k, v := range primary {
				out[k] = v
			}
		}
	}

	// Carry the bundle's own top-level fields (uuid, related arrays) without
	// overwriting fields already promoted from the primary record.
	for k, v := range bundle {
		if k == primaryKey {
			continue
		}
		if _, taken := out[k]; taken {
			continue
		}
		out[k] = v
	}

	// Entity-specific summaries.
	switch strings.Trim(entity, "/ ") {
	case "vulnerabilities":
		if raw, ok := bundle["vulnerable_configurations"]; ok {
			out["impacted_products"] = json.RawMessage(quoteJSON(summarizeConfigurations(raw)))
			out["impacted_products_count"] = json.RawMessage(fmt.Sprintf("%d", countArray(raw)))
		}
		if raw, ok := bundle["exploits"]; ok {
			out["exploits_summary"] = json.RawMessage(quoteJSON(summarizeNamed(raw)))
		}
		if raw, ok := bundle["advisories"]; ok {
			out["advisories_summary"] = json.RawMessage(quoteJSON(summarizeNamed(raw)))
		}
	}
	return out
}

// summarizeConfigurations turns vulnerable_configurations into a deduped
// "Vendor Product" list, with version ranges when present.
func summarizeConfigurations(raw json.RawMessage) string {
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return ""
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range arr {
		vendor := pickStr(item, "vendor_display_name", "vendor")
		product := pickStr(item, "product_display_name", "product_name")
		label := strings.TrimSpace(vendor + " " + product)
		if label == "" {
			continue
		}
		ve := pickStr(item, "version_end_excluding")
		vei := pickStr(item, "version_end_including")
		vs := pickStr(item, "version_start_including")
		vse := pickStr(item, "version_start_excluding")
		var range_ string
		switch {
		case vs != "" && vs != "ANY" && ve != "":
			range_ = fmt.Sprintf(" %s..<%s", vs, ve)
		case vs != "" && vs != "ANY" && vei != "":
			range_ = fmt.Sprintf(" %s..%s", vs, vei)
		case ve != "":
			range_ = fmt.Sprintf(" <%s", ve)
		case vei != "":
			range_ = fmt.Sprintf(" <=%s", vei)
		case vse != "":
			range_ = fmt.Sprintf(" >%s", vse)
		}
		key := label + range_
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

// summarizeNamed joins display_name/name fields from an array of objects.
func summarizeNamed(raw json.RawMessage) string {
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return ""
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range arr {
		s := pickStr(item, "display_name", "name", "title", "cve_id", "id")
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

func pickStr(item map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if v, ok := item[k]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" && s != "ANY" {
				return s
			}
		}
	}
	return ""
}

func countArray(raw json.RawMessage) int {
	var arr []json.RawMessage
	_ = json.Unmarshal(raw, &arr)
	return len(arr)
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
