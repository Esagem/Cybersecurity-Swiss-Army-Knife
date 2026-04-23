# CSAK — Cybersecurity Swiss Army Knife

Ingest pre-collected security tool output, score findings deterministically, and emit reports.

Slice 1 is the pipeline from tool output → scored findings → rendered report (markdown, docx, JSON). No tool orchestration, no recursion, no LLM.

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
csak org create acmecorp
csak ingest --org acmecorp --tool nessus path/to/scan.nessus
csak report generate --org acmecorp --period 2026-04 --kind internal-review --format markdown,docx,json
```

## Test

```bash
pytest
```
