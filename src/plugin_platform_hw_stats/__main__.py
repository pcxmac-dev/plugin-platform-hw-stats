"""`python -m plugin_platform_hw_stats status | view [recent|day] | charts [recent|day] | ip | ports [PORTS] [--where W]`:
the plugin from the command line. status, view and charts take two samples a second apart, so the rates are there
(the platform app samples on its own while the plugin is attached); `ip` reads this network's public address now;
`ports` says what listens on each port here (the ports chosen unless given), and with `--where internet`, `out` or
`both` checks them as the page's Check ports does (from the internet: check-host.net is given the public address and
the ports)."""
from __future__ import annotations

import json
import sys
import time

from liminal_libs.ports import parse_ports

from . import MACHINE, WHERE

USAGE = ("python -m plugin_platform_hw_stats status | view [recent|day] | charts [recent|day] | ip | "
         "ports [PORTS] [--where here|internet|out|both]")
PAUSE_S = 1.0


def main(argv: list[str] | None = None, pause=time.sleep) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    what, rest = (argv[0], argv[1:]) if argv else ("status", [])
    if what == "ip":
        return _ip() if not rest else _usage()
    if what == "ports":
        return _ports(rest)
    if what not in ("status", "view", "charts") or len(rest) > 1 or (rest and rest[0] not in ("recent", "day")):
        return _usage()
    MACHINE.monitor.sample()
    pause(PAUSE_S)
    MACHINE.monitor.sample()
    span = rest[0] if rest else "recent"
    out = MACHINE.status() if what == "status" else MACHINE.view(span) if what == "view" else MACHINE.charts(span)
    print(json.dumps(out, indent=1))
    return 0


def _usage() -> int:
    print(USAGE, file=sys.stderr)
    return 2


def _ip() -> int:
    a = MACHINE.public_address()
    print(a["said"])
    for line in a["lines"]:
        print(f"  {line}")
    return 0 if a["ok"] else 1


def _ports(rest: list[str]) -> int:
    where = "here"
    if "--where" in rest:
        i = rest.index("--where")
        if i + 1 >= len(rest) or rest[i + 1] not in ("here", *WHERE):
            return _usage()
        where, rest = rest[i + 1], rest[:i] + rest[i + 2:]
    try:
        chosen = parse_ports(" ".join(rest)) if rest else MACHINE.selected().ports
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if where == "here":
        MACHINE.monitor.sample()  # Liminal's programs named by their app
        for p, o in MACHINE.listening(chosen).items():
            print(f"{p}: {o.said}")
        return 0
    try:
        rep = MACHINE.check_ports(" ".join(map(str, chosen)), where)
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1
    print(rep["said"])
    for line in rep["lines"]:
        print(f"  {line}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
