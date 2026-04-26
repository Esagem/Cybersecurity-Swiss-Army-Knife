# CSAK — Cybersecurity Swiss Army Knife

Identify a target, run the right offensive-recon tools against it, ingest the output, score findings deterministically, and emit reports. The four-step product model is **intake → collect → triage → report**.

- **Slice 1** ships intake (file handoff), triage, and report — markdown, docx, and JSON renderers over a deterministic scoring + dedup core.
- **Slice 2** ships **collect** — `csak collect --target X` auto-detects the target type, routes to subfinder/httpx/nuclei per the [routing matrix](#target-types), runs each tool with adaptive rate limiting, and feeds output through the slice 1 ingest pipeline. Findings produced by `collect` are indistinguishable from findings produced by `ingest`.

No recursion, no async, no LLM. CLI-only.

## Install

```bash
git clone https://github.com/Esagem/Cybersecurity-Swiss-Army-Knife.git
cd Cybersecurity-Swiss-Army-Knife
python bootstrap.py
```

`bootstrap.py` runs `pip install -e ".[dev]"` against the cloned directory, then runs `csak doctor`. Doctor walks three checks in order, prompting before each:

1. **Go** — if `go` is missing, doctor offers to install it via the platform package manager (winget on Windows, Homebrew on macOS). Linux users get the `https://go.dev/dl/` download URL; the rest of the flow continues with tool installs skipped.
2. **PATH** — if csak's Scripts directory isn't on your User PATH, doctor offers to add it. Windows: persisted via `HKCU\Environment\Path`. POSIX: prints a copy-pasteable `export PATH=...` line.
3. **Tools** — for missing or outdated subfinder/httpx/nuclei, doctor asks `[a]ll / [n]one / [s]ome`. Picking `s` then prompts per tool.

Suppress a category or approve everything non-interactively:

```bash
python -m csak doctor --no-go       # don't offer to install Go
python -m csak doctor --no-path     # don't touch PATH
python -m csak doctor --no-tools    # don't install tools
python -m csak doctor --yes         # approve every offered action (CI / scripted)
```

Manual equivalent of bootstrap:

```bash
pip install -e ".[dev]"
python -m csak doctor               # use `python -m csak` until PATH is wired up
```

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

| Mode | Subfinder | httpx ports | Nuclei | Time |
|------|-----------|-------------|--------|------|
| `quick` | passive sources only | 5 most common HTTP(S) | skipped (recon-only) | seconds |
| `standard` (default) | all sources | 13 common HTTP/dev ports | severity ≥ info | minutes |
| `deep` | all + recursive | ~30 alternate-port HTTP ports | full templates incl. info, with `-irr` | tens of minutes |

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
