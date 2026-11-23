#!/usr/bin/env python3
"""Compatibility entry point for the packaged, read-only Linux capture."""

from pathlib import Path
import sys

# A source checkout also works without installing it; deployed copies use the
# installed rdp_guard package. The observation logic has one implementation.
source = Path(__file__).resolve().parents[1] / "src"
if (source / "rdp_guard" / "proxy_capture.py").is_file():
    sys.path.insert(0, str(source))

from rdp_guard.proxy_capture import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
