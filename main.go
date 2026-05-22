package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultBaseURL = "https://api.mallory.ai"
	defaultLimit   = 100
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func userAgent() string { return "mallory-exporter/" + version }

// knownEntities lists collection endpoints under /v1/<name> that return a
// paginated list. The CLI also accepts any other path the user supplies.
// Some user-facing names are aliases (see entityAliases) for verbose API paths.
var knownEntities = []string{
	"actors",
	"advisories",
	"attack_patterns",
	"breaches",
	"content_chunks",
	"detection_signatures",
	"exploitations",
	"exploits",
	"geographies",
	"industries",
	"integrations",
	"malware",
	"mentions",
	"observables",
	"opinions",
	"organizations",
	"packages",
	"products",
	"references",
	"sources",
	"stories",
	"vulnerabilities",
	"vulnerable_product_configurations",
	"weaknesses",
}

// entityAliases maps short, user-friendly names to the actual API path segment.
var entityAliases = map[string]string{
	"advisories":                        "technology_product_advisories",
	"vulnerable_product_configurations": "vulnerable_technology_product_configuration_sets",
}

func resolveEntity(name string) string {
	if alias, ok := entityAliases[name]; ok {
		return alias
	}
	return name
}

type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

type config struct {
	entity        string
	baseURL       string
	token         string
	filter        string
	sort          string
	order         string
	limit         int
	max           int
	offset        int
	workspace     string
	includeMerged bool
	since         string
	until         string
	params        stringSlice
	format        string
	output        string
	fields        string
	noExport      bool
	concurrency   int
	timeout       time.Duration
	verbose       bool
	dryRun        bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfg          config
		listEntities bool
		showHelp     bool
		showAuthHelp bool
		showVersion  bool
	)

	fs := flag.NewFlagSet("mallory-exporter", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we'll print our own usage
	fs.StringVar(&cfg.baseURL, "base-url", envOr("MALLORY_BASE_URL", defaultBaseURL), "API base URL")
	fs.StringVar(&cfg.token, "token", os.Getenv("MALLORY_API_KEY"), "API key (or env MALLORY_API_KEY)")
	fs.StringVar(&cfg.filter, "filter", "", "Search string (typed-prefix syntax; see -h)")
	fs.StringVar(&cfg.filter, "q", "", "Alias for --filter")
	fs.StringVar(&cfg.sort, "sort", "", "Field to sort by")
	fs.StringVar(&cfg.order, "order", "", "asc|desc")
	fs.IntVar(&cfg.limit, "limit", defaultLimit, "Page size (per request)")
	fs.IntVar(&cfg.max, "max", 0, "Stop after N records (0 = all)")
	fs.IntVar(&cfg.offset, "offset", 0, "Starting offset")
	fs.StringVar(&cfg.workspace, "workspace", "", "Workspace UUIDs (comma-separated)")
	fs.BoolVar(&cfg.includeMerged, "include-merged", false, "Include entities merged into others")
	fs.StringVar(&cfg.since, "since", "", "Convenience: created_at__gte (ISO 8601 or YYYY-MM-DD)")
	fs.StringVar(&cfg.until, "until", "", "Convenience: created_at__lt (ISO 8601 or YYYY-MM-DD)")
	fs.Var(&cfg.params, "f", "Raw filter: key=value (repeatable). e.g. -f mentions_count__gte=5")
	fs.StringVar(&cfg.format, "format", "jsonl", "Output format: jsonl|json|ndjson|csv")
	fs.StringVar(&cfg.output, "output", "-", "Output file (- for stdout)")
	fs.StringVar(&cfg.output, "o", "-", "Alias for --output")
	fs.StringVar(&cfg.fields, "fields", "", "CSV column order: comma-separated field names (csv only; default = inferred)")
	fs.BoolVar(&cfg.noExport, "no-export", false, "Disable per-record /export fetch (faster, less detail)")
	fs.IntVar(&cfg.concurrency, "concurrency", 1, "Parallel page fetches (>=1)")
	fs.DurationVar(&cfg.timeout, "timeout", 60*time.Second, "Per-request HTTP timeout")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Log each request to stderr")
	fs.BoolVar(&cfg.verbose, "v", false, "Alias for --verbose")
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "Print the first request URL and exit")
	fs.BoolVar(&listEntities, "list-entities", false, "Print known entity types and exit")
	fs.BoolVar(&showAuthHelp, "auth-help", false, "Print instructions for getting an API key and exit")
	fs.BoolVar(&showVersion, "version", false, "Print version and exit")
	fs.BoolVar(&showHelp, "h", false, "Show help")
	fs.BoolVar(&showHelp, "help", false, "Show help")

	if err := fs.Parse(reorderArgs(os.Args[1:], fs)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(os.Stdout)
			return nil
		}
		return err
	}

	if showHelp {
		usage(os.Stdout)
		return nil
	}
	if showVersion {
		fmt.Println("mallory-exporter", version)
		return nil
	}
	if showAuthHelp {
		fmt.Print(apiKeyHelp)
		return nil
	}
	if listEntities {
		for _, e := range knownEntities {
			fmt.Println(e)
		}
		return nil
	}

	rest := fs.Args()
	if len(rest) < 1 {
		usage(os.Stderr)
		return errors.New("entity argument required (try: mallory-exporter --list-entities)")
	}
	cfg.entity = resolveEntity(strings.Trim(rest[0], "/ "))
	if cfg.entity == "" {
		return errors.New("entity must not be empty")
	}
	if cfg.limit < 1 {
		return errors.New("--limit must be >= 1")
	}
	if cfg.concurrency < 1 {
		cfg.concurrency = 1
	}
	if cfg.token == "" {
		fmt.Fprint(os.Stderr, apiKeyHelp)
		return errors.New("missing API key")
	}
	switch cfg.format {
	case "json", "jsonl", "ndjson", "csv":
	default:
		return fmt.Errorf("unsupported --format %q (json|jsonl|csv)", cfg.format)
	}

	// Build base query from convenience flags + raw params.
	base, err := buildBaseQuery(&cfg)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	c := &client{
		baseURL: strings.TrimRight(cfg.baseURL, "/"),
		token:   cfg.token,
		http:    &http.Client{Timeout: cfg.timeout},
		verbose: cfg.verbose,
	}

	if cfg.dryRun {
		u := c.urlFor(cfg.entity, base, cfg.offset, cfg.limit)
		fmt.Println(u)
		return nil
	}

	out := os.Stdout
	if cfg.output != "-" {
		f, err := os.Create(cfg.output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	useExport := !cfg.noExport && entitySupportsExport(cfg.entity)
	sink, err := newSink(out, cfg.format, splitFields(cfg.fields), useExport, cfg.entity)
	if err != nil {
		return err
	}

	written := 0
	emit := func(item json.RawMessage) error {
		obj := map[string]json.RawMessage{}
		if err := json.Unmarshal(item, &obj); err != nil {
			return fmt.Errorf("parse record: %w", err)
		}
		if useExport {
			bundle, ferr := c.exportOne(ctx, cfg.entity, obj)
			if ferr != nil {
				if cfg.verbose {
					fmt.Fprintf(os.Stderr, "export %s failed: %v (falling back to list record)\n", string(obj["uuid"]), ferr)
				}
			} else if bundle != nil {
				obj = flattenExport(cfg.entity, bundle)
			}
		}
		written++
		return sink.emit(obj)
	}

	err = c.paginate(ctx, cfg.entity, base, cfg.offset, cfg.limit, cfg.max, emit)
	if closeErr := sink.close(); closeErr != nil && err == nil {
		err = closeErr
	}

	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "exported %d records\n", written)
	}
	return err
}

func splitFields(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func buildBaseQuery(cfg *config) (url.Values, error) {
	q := url.Values{}
	if cfg.filter != "" {
		q.Set("filter", cfg.filter)
	}
	if cfg.sort != "" {
		q.Set("sort", cfg.sort)
	}
	if cfg.order != "" {
		q.Set("order", cfg.order)
	}
	if cfg.workspace != "" {
		q.Set("workspace_uuids", cfg.workspace)
	}
	if cfg.includeMerged {
		q.Set("include_merged", "true")
	}
	if cfg.since != "" {
		q.Set("created_at__gte", normalizeTime(cfg.since))
	}
	if cfg.until != "" {
		q.Set("created_at__lt", normalizeTime(cfg.until))
	}
	for _, kv := range cfg.params {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("bad -f value %q (expected key=value)", kv)
		}
		q.Add(kv[:eq], kv[eq+1:])
	}
	return q, nil
}

// normalizeTime accepts YYYY-MM-DD and promotes it to RFC3339; otherwise passes through.
func normalizeTime(s string) string {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return s
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// reorderArgs moves positional arguments to the end so flags can appear on
// either side of the entity name. It needs the flag set so it can tell which
// flags expect a value.
func reorderArgs(args []string, fs *flag.FlagSet) []string {
	boolFlags := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			boolFlags[f.Name] = true
		}
	})

	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			// Strip leading dashes and any =value to find the flag name.
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				flags = append(flags, a)
				continue
			}
			flags = append(flags, a)
			if !boolFlags[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func usage(w io.Writer) {
	fmt.Fprint(w, helpText)
}

const apiKeyHelp = `
Getting a Mallory API key:
  1. Sign up at https://mallory.ai
  2. Open your dashboard and generate an API key
  3. Export it in your shell:

       export MALLORY_API_KEY=<your_key>

     Or, for a one-off:

       MALLORY_API_KEY=<your_key> mallory-exporter <entity> ...

  The key is sent as: Authorization: Bearer <key>

`

const helpText = `mallory-exporter — export entities from the Mallory API (https://api.mallory.ai)

Usage:
  mallory-exporter [flags] <entity>

Examples:
  # 1000 most recent CVEs published in 2024
  mallory-exporter vulnerabilities \
      --filter "cve:CVE-2024" --sort published_at --order desc --max 1000

  # All threat actors whose family name matches "APT", as JSONL
  mallory-exporter actors --filter "name:APT" -o actors.jsonl

  # Trending malware in the last day, top 50
  mallory-exporter malware --sort trending_1d --max 50

  # Vulnerabilities with EPSS >= 0.9 and at least one observed exploitation
  mallory-exporter vulnerabilities -f epss_score__gte=0.9 -f exploitations_count__gt=0

  # Stories created since 2026-01-01, written as one big JSON array
  mallory-exporter stories --since 2026-01-01 --format json -o stories.json

Entity types (also accept any other /v1/<entity> path):
  actors, attack_patterns, breaches, detection_signatures, exploitations,
  exploits, malware, mentions, observables, opinions, organizations, packages,
  products, references, sources, stories, advisories,
  vulnerabilities, weaknesses, ...   (full list: --list-entities)

  Aliases:
    advisories                          ->  technology_product_advisories
    vulnerable_product_configurations   ->  vulnerable_technology_product_configuration_sets

Authentication:
  Pass --token <key> or set MALLORY_API_KEY. Sent as: Authorization: Bearer <key>
  No key yet? Run with --auth-help for sign-up instructions.

Search syntax (--filter / -q):
  Each entity exposes a single 'filter' query string that supports typed
  prefixes "<field>:<value>". With no prefix, a sensible default is used.

  Vulnerabilities:
    cve:CVE-2024-1234        match by CVE ID
    uuid:<uuid>              match by Mallory UUID
    internal_name:<slug>     exact internal name
    desc:<text>              search description (default with no prefix)
    gen_display_name:<text>  search generated display name
    cisa_kev:true            in CISA KEV catalog
    state:<state>            workflow state

  Actors / Malware / Organizations / Products / Breaches / etc:
    name:<text>              filter by name (default for actors/malware)
    uuid:<uuid>              match by UUID
    internal_name:<slug>     exact internal name
    desc:<text>              search description

  Plain text with no prefix falls back to the entity's default
  (description for vulnerabilities, name/display_name for most others).

Field-level filters (-f key=value, repeatable):
  Mallory exposes per-field operators on every index. Suffixes:
    __gt   __gte  __lt   __lte  __neq
    __in   __not_in       (comma-separated)
    __like __ilike        (SQL LIKE / case-insensitive LIKE)
    __isnull __exists     (boolean)

  Examples:
    -f epss_score__gte=0.9
    -f cvss_base_score__gte=7.0 -f cvss_base_score__lt=10
    -f mentions_count__gt=10
    -f published_at__gte=2024-01-01T00:00:00Z
    -f source_countries__in=RU,CN,KP
    -f attack_patterns__mitre_attack_id__ilike=T15%%

  Any unknown -f key is forwarded verbatim. Refer to:
    https://api.mallory.ai/openapi.json
  for the exact filter fields available on each entity.

Sort & order:
  --sort   name | created_at | updated_at | enriched_at |
           trending_all_time | trending_<N>{m,h,d}  (e.g. trending_5h)
           plus entity-specific fields (e.g. published_at, cvss_base_score)
  --order  asc | desc  (default: desc)

  Trending windows can be scoped explicitly with:
    -f mentions_published_at__gte=<ISO> -f mentions_published_at__lt=<ISO>

Pagination:
  --limit       per-page request size (default 100)
  --offset      starting offset (default 0)
  --max         stop after N total records (0 = all available)
  --concurrency parallel page fetches once total is known (default 1)

Convenience filters:
  --since <date>    -> created_at__gte (accepts YYYY-MM-DD or ISO 8601)
  --until <date>    -> created_at__lt
  --workspace UUIDS -> workspace_uuids (scope to one or more workspaces)
  --include-merged  -> include entities that have been merged

Output:
  --format jsonl|ndjson  one JSON object per line (default; streamable)
  --format json          single JSON array
  --format csv           CSV with a sensible default column set per entity
  --fields a,b,c         override CSV column order
  --output, -o FILE      write to FILE (default stdout)

Per-record /export bundles (default):
  For entities that expose /v1/<entity>/{id}/export — vulnerabilities, actors,
  malware, organizations, products, exploits, breaches, stories, advisories —
  each record is automatically enriched with the full export bundle.
  For vulnerabilities this adds:

    impacted_products         deduped vendor + product (+ version range)
    impacted_products_count   number of vulnerable configurations
    exploits_summary         comma-joined exploit names
    advisories_summary       comma-joined vendor advisory IDs

  Pass --no-export to skip the per-record fetch and use only the list payload
  (faster, less detail).

Flags:
  --base-url URL    override API base (default https://api.mallory.ai)
  --timeout DUR     per-request HTTP timeout (default 60s)
  --no-export       skip the per-record /export enrichment
  --dry-run         print the first request URL and exit
  --verbose, -v     log every request and final count to stderr
  --list-entities   print the known entity list and exit
  -h, --help        show this help
`
