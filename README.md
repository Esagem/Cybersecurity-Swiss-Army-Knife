# CSAK — Cybersecurity Swiss Army Knife

Identify a target, run the right offensive-recon tools against it, ingest the output, score findings deterministically, and emit reports. The four-step product model is **intake → collect → triage → report**.

- **Slice 1** ships intake (file handoff), triage, and report — markdown, docx, and JSON renderers over a deterministic scoring + dedup core.
- **Slice 2** ships **collect** — `csak collect --target X` auto-detects the target type, routes to subfinder/httpx/nuclei per the [routing matrix](#target-types), runs each tool with adaptive rate limiting, and feeds output through the slice 1 ingest pipeline. Findings produced by `collect` are indistinguishable from findings produced by `ingest`.

No recursion, no async, no LLM. CLI-only.

## Install

```bash
pip install -e ".[dev]"
```

External tool binaries (subfinder, httpx, nuclei) are installed separately — see [`csak doctor`](#dependencies).

## Quick start

### Ingest (slice 1)

```bash
csak org create acmecorp
csak ingest --org acmecorp --tool nessus path/to/scan.nessus
csak report generate --org acmecorp --period 2026-04 --kind internal-review --format markdown,docx,json
```

### Collect (slice 2)

```bash
csak doctor                                                # check / install subfinder, httpx, nuclei
csak collect --org acmecorp --target acmecorp.com          # full pipeline, standard mode
csak collect --org acmecorp --target api.acmecorp.com --mode quick
csak collect --org acmecorp --target 10.0.0.0/24 --mode deep
csak collect --org acmecorp --target https://api.acmecorp.com/v2 \
             --nuclei-templates ~/my-templates --nuclei-rate-limit 30
csak findings list --org acmecorp                          # review what landed
```

`csak collect` blocks until done, prints per-stage progress, and exits non-zero on hard failure. Skipped and failed stages are recorded as Scans with reasons in `Scan.notes`.

## Modes

| Mode | Subfinder | httpx | Nuclei | Time |
|------|-----------|-------|--------|------|
| `quick` | passive sources only | default checks | skipped | seconds |
| `standard` (default) | all sources | default checks | severity ≥ low | minutes |
| `deep` | all + recursive | full check set | full templates incl. info | tens of minutes |

## Target types

`--target` is auto-classified; the appropriate tool subset runs.

| Input shape | Type | Subfinder | httpx | Nuclei |
|-------------|------|-----------|-------|--------|
| `acmecorp.com` | domain | ✓ | ✓ | ✓ |
| `api.acmecorp.com` | subdomain | ✗ | ✓ | ✓ |
| `10.0.0.42` | ip | ✗ | ✓ | ✓ |
| `10.0.0.0/24` | cidr | ✗ | ✓ | ✓ |
| `https://api.acmecorp.com/v2` | url | ✗ | ✗ | ✓ |

## Dependencies

`csak collect` depends on three Go binaries. `csak doctor` checks for them and offers a permission-prompted auto-install:

```bash
$ csak doctor
  [ok]   subfinder    v2.6.4 (>= 2.6.0)
  [warn] httpx        v1.3.7 (< 1.4.0, recommended upgrade)
  [miss] nuclei       not found on PATH

The following actions can be taken:
  - upgrade httpx    via: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  - install nuclei   via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Proceed? [y/N]:
```

`--yes` skips the prompt for scripting / CI. Go ≥ 1.21 is required.

## Test

```bash
pytest
```

185 tests across slice 1 + slice 2.

## Architecture

Six modules under `src/csak/`:

- `cli/` — thin click-based command dispatch
- `collect/` — target detection, routing, subprocess runner, per-tool catalog (slice 2)
- `ingest/` — per-tool parsers, scoring, dedup
- `storage/` — SQLite + content-addressed artifact store
- `query/` — read-side queries and report context builder
- `render/` — markdown, docx, and JSON renderers

See `cyber-wiki/wiki/architecture/overview.md` for the full map.
