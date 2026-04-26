"""Heavy local target — re-exports the integration test target so
``python scripts/test_target_heavy.py`` keeps working for manual use.

The canonical definition (server logic + ground-truth manifest) lives
in ``tests/integration/targets/heavy.py``. The integration harness
imports it directly via ``from tests.integration.targets.heavy
import HEAVY_TARGET``.
"""
from __future__ import annotations

import argparse
import threading
import sys
from pathlib import Path

# Allow running this script directly from the repo root without installing
# the test package — add the repo root to sys.path if needed.
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from tests.integration.targets.heavy import (  # noqa: E402
    APP_FIXTURES,
    ADMIN_FIXTURES,
    AppHandler,
    AdminHandler,
)
from http.server import ThreadingHTTPServer  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-port", type=int, default=8080)
    parser.add_argument("--admin-port", type=int, default=8000)
    args = parser.parse_args()

    app = ThreadingHTTPServer(("127.0.0.1", args.app_port), AppHandler)
    admin = ThreadingHTTPServer(("127.0.0.1", args.admin_port), AdminHandler)
    threading.Thread(target=app.serve_forever, daemon=True).start()
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    print("csak heavy test target — bound to 127.0.0.1 only")
    print(f"  app:   http://127.0.0.1:{args.app_port}  "
          f"({len(APP_FIXTURES)} fixture endpoints + reflected /search + open-redirect /redir)")
    print(f"  admin: http://127.0.0.1:{args.admin_port}  "
          f"({len(ADMIN_FIXTURES)} fixture endpoints, basic auth: admin / admin)")
    print("  Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopping.")
        app.shutdown()
        admin.shutdown()


if __name__ == "__main__":
    main()
