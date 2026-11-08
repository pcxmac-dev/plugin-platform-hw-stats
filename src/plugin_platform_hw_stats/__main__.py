"""`python -m plugin_platform_hw_stats status | view [recent|day] | charts [recent|day]`: the plugin from the
command line, two samples a second apart so the rates are there (the platform app samples on its own while the
plugin is attached)."""
from __future__ import annotations

import json
import sys
import time

from . import MACHINE

USAGE = "python -m plugin_platform_hw_stats status | view [recent|day] | charts [recent|day]"
PAUSE_S = 1.0


def main(argv: list[str] | None = None, pause=time.sleep) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    what, rest = (argv[0], argv[1:]) if argv else ("status", [])
    if what not in ("status", "view", "charts") or len(rest) > 1 or (rest and rest[0] not in ("recent", "day")):
        print(USAGE, file=sys.stderr)
        return 2
    MACHINE.monitor.sample()
    pause(PAUSE_S)
    MACHINE.monitor.sample()
    span = rest[0] if rest else "recent"
    out = MACHINE.status() if what == "status" else MACHINE.view(span) if what == "view" else MACHINE.charts(span)
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
