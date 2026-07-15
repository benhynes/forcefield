#!/usr/bin/env python3
"""Render dev.yaml with a canonical private state directory."""

import os
from pathlib import Path
import sys


PLACEHOLDER = "/REPLACE/WITH/PRIVATE/FORCEFIELD_DEV"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: render_dev_config.py STATE_DIR", file=sys.stderr)
        return 2

    state = Path(sys.argv[1]).expanduser().resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state, 0o700)

    template = Path(__file__).with_name("dev.yaml").read_text(encoding="utf-8")
    if template.count(PLACEHOLDER) != 3:
        print("dev template has an unexpected placeholder count", file=sys.stderr)
        return 1

    destination = state / "forcefield.yaml"
    destination.write_text(template.replace(PLACEHOLDER, str(state)), encoding="utf-8")
    os.chmod(destination, 0o600)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
