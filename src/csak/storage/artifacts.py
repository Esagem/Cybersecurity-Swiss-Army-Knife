"""Content-addressed storage for raw tool-output bytes.

Files are placed at ``<root>/<first two hex chars of hash>/<hash>`` so
the ``artifacts/`` directory stays browsable under a file manager
even with thousands of files.
"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

HASH_ALGO = "sha256"
_BUF_SIZE = 128 * 1024


def hash_file(path: str | Path) -> str:
    h = hashlib.new(HASH_ALGO)
    with open(path, "rb") as f:
        while chunk := f.read(_BUF_SIZE):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.new(HASH_ALGO, data).hexdigest()


def store_path(root: str | Path, hash_: str) -> Path:
    root = Path(root)
    return root / hash_[:2] / hash_


def store_file(root: str | Path, source: str | Path) -> tuple[str, Path]:
    """Copy ``source`` into the artifact store, returning (hash, path).

    A hash collision is treated as a no-op — the store is keyed on
    content, so the existing file is already correct.
    """
    source = Path(source)
    h = hash_file(source)
    dest = store_path(root, h)
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
    return h, dest


def read(root: str | Path, hash_: str) -> bytes:
    return store_path(root, hash_).read_bytes()
