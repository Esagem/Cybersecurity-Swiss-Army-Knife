"""Allow running csak via ``python -m csak ...`` even before the
``csak`` console script is on the user's PATH.

On a fresh ``pip install --user`` (Windows in particular), the
``csak.exe`` shim lands in a Scripts directory that isn't on the
default PATH. Users still need a way to invoke ``csak doctor`` to
fix that — running ``python -m csak doctor`` is the bootstrap.
"""
from csak.cli.main import main

if __name__ == "__main__":
    main()
