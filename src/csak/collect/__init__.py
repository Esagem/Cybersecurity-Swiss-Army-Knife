"""CSAK collect package — slice 2.

Take a target string, identify its type, route it to the right subset
of orchestrated tools, run each tool as a subprocess, capture output
into Artifacts, and feed each Artifact into the slice 1 ingest
pipeline. The analyst types ``csak collect --target X`` and CSAK does
the rest.

The catalog (``csak/collect/tools/``) is the per-tool data layer; the
runner is the subprocess wrapper; the pipeline is the orchestrator.
The CLI commands ``csak collect`` and ``csak doctor`` live in
``csak/cli/``.
"""
from __future__ import annotations

# Importing the tools subpackage triggers tool registration — the
# router and doctor commands rely on ``ALL_TOOLS`` being populated.
from csak.collect import tools as _tools  # noqa: F401
