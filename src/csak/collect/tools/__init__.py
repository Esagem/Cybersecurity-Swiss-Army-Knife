"""Per-tool catalog modules.

Each module under here defines exactly one ``Tool`` subclass and an
instance singleton. The list ``ALL_TOOLS`` below is the canonical
ordered set used by the router and the doctor command.

Order matters: it's the pipeline execution order. Subfinder produces
hosts → httpx confirms which are live → Nuclei scans the live ones.
"""
from __future__ import annotations

from csak.collect.tools.subfinder import SUBFINDER
from csak.collect.tools.httpx import HTTPX
from csak.collect.tools.nuclei import NUCLEI

ALL_TOOLS = [SUBFINDER, HTTPX, NUCLEI]
