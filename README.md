# mallory-exporter

A small Go CLI that exports any entity type from the
[Mallory API](https://api.mallory.ai/openapi.json) with full access to the
filter, sort, and pagination parameters the API exposes.

```
mallory-exporter [flags] <entity>
```

Run `mallory-exporter --help` for the full flag reference. The sections below
are a quick-reference.

## Install

```
go build -o mallory-exporter .
export MALLORY_API_KEY=sk_...     # or pass --token
```

## Quick start

```bash
# 1000 most recent CVEs published in 2024
mallory-exporter vulnerabilities \
    --filter "cve:CVE-2024" --sort published_at --order desc --max 1000

# All threat actors whose name matches "APT", as JSONL
mallory-exporter actors --filter "name:APT" -o actors.jsonl

# Top 50 trending malware in the last 24h
mallory-exporter malware --sort trending_1d --max 50

# High-EPSS vulns that have at least one observed exploitation
mallory-exporter vulnerabilities \
    -f epss_score__gte=0.9 -f exploitations_count__gt=0

# Stories since the start of the year, written as a single JSON array
mallory-exporter stories --since 2026-01-01 --format json -o stories.json

# Top 25 CISA KEV vulnerabilities by EPSS as CSV with description, CVSS,
# impacted systems, and CWE (uses /export per record)
mallory-exporter vulnerabilities \
    --filter "cisa_kev:true" --sort epss_score --order desc --max 25 \
    --format csv -o vulns.csv

# Show the request URL without making the call
mallory-exporter vulnerabilities --filter "cisa_kev:true" --dry-run
```

## Search syntax (`--filter` / `-q`)

Mallory exposes a single typed `filter` string per index. Use a `prefix:value`
to pick the field; bare strings fall back to the entity's default field.

| Entity                 | Typed prefixes                                                                            | Default (no prefix)        |
| ---------------------- | ----------------------------------------------------------------------------------------- | -------------------------- |
| `vulnerabilities`      | `cve:`, `uuid:`, `internal_name:`, `desc:`, `gen_display_name:`, `cisa_kev:`, `state:`    | description text search    |
| `actors`               | `name:`, `uuid:`, `internal_name:`, `desc:`                                               | display_name / name search |
| `malware`              | `name:`, `uuid:`, `internal_name:`, `desc:`                                               | name search                |
| `organizations`        | `name:`, `uuid:`, `internal_name:`, `desc:`                                               | name search                |
| `products`, `breaches` | `name:`, `uuid:`, `internal_name:`, `desc:`                                               | name search                |

(See the OpenAPI spec for the full per-entity list — the same shape applies to
every index.)

## Field-level filters (`-f key=value`, repeatable)

Every index also exposes per-field operators. The CLI forwards `-f` values
verbatim, so anything in the OpenAPI spec works:

| Suffix       | Meaning                                |
| ------------ | -------------------------------------- |
| `__gt`       | strictly greater than                  |
| `__gte`      | greater than or equal                  |
| `__lt`       | strictly less than                     |
| `__lte`      | less than or equal                     |
| `__neq`      | not equal                              |
| `__in`       | in comma-separated list                |
| `__not_in`   | not in comma-separated list            |
| `__like`     | SQL `LIKE`                             |
| `__ilike`    | case-insensitive `LIKE`                |
| `__isnull`   | boolean: field is null                 |
| `__exists`   | boolean: field is present              |

Examples:

```bash
-f epss_score__gte=0.9
-f cvss_base_score__gte=7.0 -f cvss_base_score__lt=10
-f mentions_count__gt=10
-f published_at__gte=2024-01-01T00:00:00Z
-f source_countries__in=RU,CN,KP
-f attack_patterns__mitre_attack_id__ilike=T15%
```

## Sort and order

```
--sort   name | created_at | updated_at | enriched_at |
         trending_all_time | trending_<N>{m,h,d}        (e.g. trending_5h)
         plus entity-specific fields (e.g. published_at, cvss_base_score)
--order  asc | desc                                     (default: desc)
```

Scope a custom trending window with:

```
-f mentions_published_at__gte=<ISO> -f mentions_published_at__lt=<ISO>
```

## Pagination

```
--limit        page size per request          (default 100)
--offset       starting offset                (default 0)
--max          stop after N total records     (0 = all available)
```

The CLI follows the API's `total` / `offset` / `limit` contract and stops
automatically when the server reports no more data.

## Convenience flags

```
--since <date>    -> created_at__gte    (accepts YYYY-MM-DD or ISO 8601)
--until <date>    -> created_at__lt
--workspace UUIDS -> workspace_uuids    (scope to one or more workspaces)
--include-merged  -> include entities merged into others
```

## Output

```
--format jsonl|ndjson   one JSON object per line (default; streamable)
--format json           single JSON array
--format csv            CSV with a sensible default column set per entity
--fields a,b,c          override CSV column order
--output, -o FILE       write to FILE (default stdout)
```

## /export bundle (default)

For entities that expose `/v1/<entity>/{id}/export` — `vulnerabilities`,
`actors`, `malware`, `organizations`, `products`, `exploits`, `breaches`,
`stories`, `advisories` — each list record is automatically
enriched with the full export bundle so the CSV/JSON has related data inline.

For vulnerabilities this adds:

| column                   | source                                                          |
| ------------------------ | --------------------------------------------------------------- |
| `impacted_systems`       | deduped `vendor_display_name + product_display_name + version`  |
| `impacted_systems_count` | length of `vulnerable_configurations`                           |
| `exploits_summary`       | comma-joined exploit names from the bundle's `exploits[]`       |
| `advisories_summary`     | comma-joined advisory IDs from the bundle's `advisories[]`      |

Pass `--no-export` to skip the per-record fetch and use only the list payload
(faster, less detail).

## Entity types

`mallory-exporter --list-entities` prints the built-in list. The CLI just
GETs `/v1/<entity>` so any other path the API exposes also works — e.g.
`mallory-exporter sources` or `mallory-exporter mentions/actors`.

| Entity                              | `/export` bundle | Notes                                                                 |
| ----------------------------------- | :--------------: | --------------------------------------------------------------------- |
| `actors`                            | ✅                | Threat actors                                                         |
| `advisories`                        | ✅                | Alias for `technology_product_advisories`                             |
| `attack_patterns`                   |                  | MITRE ATT&CK patterns                                                 |
| `breaches`                          | ✅                | Disclosed breach events                                               |
| `content_chunks`                    |                  | Indexed document chunks (use `/v1/content_chunks/search` for search)  |
| `detection_signatures`              |                  | Sigma / YARA / vendor signatures                                      |
| `exploitations`                     |                  | Observed exploitation events                                          |
| `exploits`                          | ✅                | Public exploit references                                             |
| `geographies`                       |                  | Country / region lookup                                               |
| `industries`                        |                  | Industry sector lookup                                                |
| `integrations`                      |                  | Tenant integrations                                                   |
| `malware`                           | ✅                | Malware families                                                      |
| `mentions`                          |                  | Article/news mentions tagged to entities                              |
| `observables`                       |                  | IOCs (domains, IPs, hashes, etc.)                                     |
| `opinions`                          |                  | Analyst / community opinions on observables                           |
| `organizations`                     | ✅                | Vendors and other named organizations                                 |
| `packages`                          |                  | Software packages (npm, PyPI, etc.)                                   |
| `products`                          | ✅                | Technology products                                                   |
| `references`                        |                  | Source documents (CVEs, advisories, articles, …)                      |
| `sources`                           |                  | Upstream feed metadata                                                |
| `stories`                           | ✅                | Mallory-generated threat stories                                      |
| `vulnerabilities`                   | ✅                | CVEs / vulnerabilities (richest filter set)                           |
| `vulnerable_product_configurations` |                  | Alias for `vulnerable_technology_product_configuration_sets` (CPE-style affected configs) |
| `weaknesses`                        |                  | CWE-style weakness taxonomy                                           |

Entities marked `/export` get auto-enriched with the per-record bundle by
default — pass `--no-export` to skip that fetch.

### Per-entity filter examples

```bash
# Vulnerabilities
mallory-exporter vulnerabilities --filter "cve:CVE-2024-1234"
mallory-exporter vulnerabilities --filter "cisa_kev:true" -f epss_score__gte=0.9
mallory-exporter vulnerabilities -f cvss_base_score__gte=7 -f published_at__gte=2024-01-01T00:00:00Z

# Threat actors
mallory-exporter actors --filter "name:lazarus"
mallory-exporter actors -f motivation__in=financial,espionage -f source_countries__in=RU,CN

# Malware / breaches / organizations / products / advisories
mallory-exporter malware --filter "name:LockBit" --sort trending_1d
mallory-exporter breaches --since 2026-01-01
mallory-exporter organizations --filter "name:Cisco"
mallory-exporter products --filter "name:Confluence"
mallory-exporter advisories --filter "name:Cisco"
```

## Authentication

Pass `--token <key>` or set the `MALLORY_API_KEY` environment variable. The
key is sent as `Authorization: Bearer <key>`.

```bash
export MALLORY_API_KEY=<your_key>
mallory-exporter vulnerabilities --filter "cisa_kev:true"
```

Don't have a key yet?

1. Sign up at [https://mallory.ai](https://mallory.ai)
2. Open your dashboard and generate an API key
3. Export it in your shell as `MALLORY_API_KEY`

Run `mallory-exporter --auth-help` for the same instructions on the CLI.
