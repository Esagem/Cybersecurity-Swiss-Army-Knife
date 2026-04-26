# Example CSAK plugins

Drop these files into `~/.csak/tools/` (the default) or point at this
directory directly with `CSAK_PLUGIN_DIR=scripts/csak_plugins` to load
them in place. They're imported at `csak collect` startup and join the
same toolbox as built-ins; `csak tools list/show` and `csak doctor`
treat them no differently.

## What's here

* **`linkfinder.py`** — a working plugin. Registers a `linkfinder`
  tool whose binary is `python` (so it runs cross-platform without a
  separate install step) and whose helper crawls a URL, extracts links
  from HTML / sitemap / JSON, and writes them as JSONL. The `Tool`
  hooks (`accepts`, `produces`, `extract_outputs`) wire the result
  into the recursion frontier; pair it with `--recurse` to drive
  depth ≥ 2 against the test target deterministically.

  Use it like::

      CSAK_PLUGIN_DIR=scripts/csak_plugins \
        csak tools show linkfinder

      CSAK_PLUGIN_DIR=scripts/csak_plugins \
        csak collect --org demo --target 127.0.0.1 --recurse --max-depth 3

* **`asnmap_demo.py`** — declarative-only plugin. Registers a new
  target type (`asn`) plus a stub `asnmap_demo` tool. No binary call
  — useful only to demonstrate the plugin loading path, the new-type
  registration, and the live recursion graph (`csak tools show
  httpx` will list `asnmap_demo` as an upstream that produces
  `network_block`).

## Plugin contract

A plugin is any `*.py` file (no `_` prefix) that does either of:

1. Calls `register_tool(MyTool(), origin="plugin", source_path=__file__)`
   at import time. Same for `register_type` from
   `csak.collect.types`.
2. Defines `CSAK_TOOLS = [MyTool(), ...]` at module level. The plugin
   loader auto-registers each.

A broken plugin (syntax error, missing import) is reported by
`csak doctor` and skipped at collect time. One bad plugin doesn't
take CSAK down.

See `cyber-wiki/wiki/specs/slice-3.md §Plugin discovery` for the spec.
