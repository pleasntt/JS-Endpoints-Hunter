"""zipapp entrypoint for JS-Endpoints-Hunter: opens the local Web UI."""

from __future__ import annotations

import sys

from jsh.ui.app import run_ui

if __name__ == "__main__":
    run_ui()
    sys.exit(0)
