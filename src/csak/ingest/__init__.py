"""CSAK ingest package.

Importing this package triggers registration of every built-in parser,
so callers only need ``from csak.ingest.pipeline import ingest_path``.
"""
from __future__ import annotations

# Built-in parsers register themselves via side effects on import.
from csak.ingest import nuclei as _nuclei  # noqa: F401
from csak.ingest import nessus as _nessus  # noqa: F401
from csak.ingest import zeek as _zeek  # noqa: F401
from csak.ingest import osquery as _osquery  # noqa: F401
from csak.ingest import probe as _probe  # noqa: F401
