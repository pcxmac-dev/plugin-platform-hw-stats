"""Hardware stats for Liminal (the user, 2026-11-07: "i need the hardware monitoring that was in charts, it needs
to be windows and linux agnostic, ie it runs on both, the stats were on the charts app but they need a plugin
too, hw-stats platform plugin"): this machine's processor, memory, network, disks and their reads and writes, the data files, and every
Liminal app's processes (the charts app, the integrator, the login, the platform) with their CPU, memory, reads
and writes, threads and connections. The library's resources.Monitor samples them (Windows: kernel32, ntdll and
iphlpapi; Linux: /proc and /sys) every 30 s in the background and every 2 s while the platform's page shows
them, at most 5% of one core; it runs only while the plugin is attached to the platform app (nothing samples
when nothing uses it). The platform's page draws `status()`: the facts, the tables and the charts.

This network too (the user, 2026-11-08: "make sure platform hw stats is able to get the current public IP, and
verify that 'selected' ports are available or blocked"; "there should be a way to check ports"): its public
address, IPv4 and IPv6, asked of OpenDNS (else Google's name server) when the plugin is attached and every 15
minutes while it is; the ports chosen (HW_STATS_PORTS, read through the platform's login: the user's own setting
once the login app holds it; Liminal's own pages' ports unless set), each with what listens on it here; and, when the
user asks (Check ports), whether each answers from the internet at that address (check-host.net's servers connect
to it) or out from this machine (to portquiz.net). The services are named in `network`.

    python -m plugin_platform_hw_stats status | view [recent|day] | charts [recent|day] | ip | ports [PORTS] [--where W]
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from liminal_libs import dns, netpath
from liminal_libs.apps import EnvironmentLogin
from liminal_libs.machines.firewall import app_ports
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.ports import MAX_PORTS, Outcome, attempt, here as listening_here, listening_pids, parse_ports, reach_out, tally
from liminal_libs.ports import connect as connect_out
from liminal_libs.resources import Monitor, default_probe, framework_role, is_framework
from liminal_libs.sources.keys import KeyVar

from .network import OUT_HOST, PUBLIC_SERVERS, TRACE_TO, CheckHost, Net

__version__ = "0.3.1"
OWN = ("platform", "Platform")  # this process's role when its command line names no Liminal app (a test, a one-off)
UNITS = ("B", "KB", "MB", "GB", "TB", "PB")
SYSTEMS = {"windows": "Windows", "linux": "Linux", "other": sys.platform}
PORTS_VAR = "HW_STATS_PORTS"
KEYS = (KeyVar(PORTS_VAR, label="Ports to check", secret=False,
               hint=f"the ports listed under Ports and filled into Check ports: 25, 80, 443, 8765-8768 (at most {MAX_PORTS}); "
                    "unset, Liminal's own pages' ports"),)
PUBLIC_S = 900.0  # this network's public address read again every 15 minutes while attached
HERE_S = 10.0  # what listens on the ports read again at most this often
WHERE = {"internet": "from the internet", "out": "out from this machine", "both": "from the internet and out from this machine"}
PRESETS = {  # the ports the Ports table may list, chosen on the page beside Liminal's own and HW_STATS_PORTS
    "web": ("Web", (80, 443)),
    "mail": ("Mail", (25, 465, 587, 993)),
    "remote": ("Remote access", (22, 3389)),
}
KEPT = "until the platform restarts (the login will keep it once it holds the plugins' settings)"
SETTLE_S = 0.3  # a listener or a connection given time to land before it is looked for
LATE_S = 1.5  # packets of the check from the internet still on their way, waited for
PACKETS_SHOWN = 40  # the path check's traffic rows shown


class Chosen(NamedTuple):
    """The ports the Ports table lists and where they come from: liminal (Liminal's own pages'), setting
    (HW_STATS_PORTS), web, mail or remote (a set chosen on the page), chosen (ports typed on the page); and what is
    wrong with the setting, if anything."""
    ports: tuple[int, ...]
    source: str
    problem: str | None = None


# -- the figures in words, as the charts app's Resources view gave them ------------------------------------
def size(n) -> str:
    if n is None:
        return "–"
    v, i = abs(float(n)), 0
    while v >= 1024 and i < len(UNITS) - 1:
        v /= 1024
        i += 1
    return f"{'−' if n < 0 else ''}{v:.0f} {UNITS[i]}" if i == 0 or v >= 100 else f"{'−' if n < 0 else ''}{v:.1f} {UNITS[i]}"


def rate(n) -> str:
    return "–" if n is None else f"{size(n)}/s"


def share(f) -> str:
    return "–" if f is None else f"{f * 100:.0f}%"


def core(f) -> str:
    """A share of one core (a program's CPU)."""
    return "–" if f is None else f"{f * 100:.1f}%" if f < 0.1 else f"{f * 100:.0f}%"


def growth(n) -> str:
    return "–" if n is None else f"{'+' if n > 0 else ''}{size(n)}/h"


def link(bps) -> str:
    return "" if not bps else f"{bps / 1e9:.1f} Gb/s" if bps >= 1e9 else f"{round(bps / 1e6)} Mb/s"


def when(iso) -> str:
    """An ISO time as this machine's local time (the platform runs here)."""
    if not iso:
        return "–"
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone().strftime("%b %d %H:%M")
    except ValueError:
        return str(iso)


def clock(seconds: float) -> str:
    """A time (seconds since 1970) as this machine's local time (in UTC where Windows cannot localize it: a time
    near 1970, which Python before 3.13 cannot take to local time there)."""
    if not seconds:
        return "–"
    try:
        return datetime.fromtimestamp(seconds).astimezone().strftime("%b %d %H:%M")
    except (OSError, OverflowError, ValueError):
        return datetime.fromtimestamp(seconds, timezone.utc).strftime("%b %d %H:%M UTC")


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def own_ports() -> dict[int, str]:
    """Liminal's own pages' ports, each with its app (the variables moving them: LIMINAL_CHARTS_PORT ...)."""
    return {port: name for name, port in app_ports().items()}


# -- what the platform's page shows: the summary, the facts, the tables, the charts --------------------------
def summary(view: dict) -> str:
    m, programs = view.get("machine"), view.get("processes") or []
    if not view.get("sampledAt"):  # attached a moment ago: the sampler's first sample is under way
        return "sampling: the first sample is under way"
    if not m:
        return f"{plural(len(programs), 'Liminal program')}; the machine's figures are not read on {sys.platform}"
    if m.get("cpu") is None:
        return f"sampling: {m['cpus']} cores, {size(m['memoryTotal'])} of memory, {plural(len(programs), 'Liminal program')}"
    return (f"CPU {share(m['cpu'])} of {m['cpus']} cores · memory {share(m['memoryUsed'] / m['memoryTotal'] if m['memoryTotal'] else None)}"
            f" · {plural(len(programs), 'Liminal program')}")


def facts(view: dict) -> dict:
    """The specifics, in words, in the order shown."""
    m, net, links, files, mon = (view.get(k) for k in ("machine", "network", "connections", "files", "monitor"))
    out = {"system": SYSTEMS.get(view.get("system", "other"), sys.platform)}
    if m:
        out["processor"] = f"{share(m['cpu'])} of {m['cpus']} cores"
        out["memory"] = f"{size(m['memoryUsed'])} of {size(m['memoryTotal'])} · {share(m['memoryUsed'] / m['memoryTotal'] if m['memoryTotal'] else None)}"
        out["committed"] = f"{size(m['commitUsed'])} of {size(m['commitTotal'])}"
    if net:
        out["network"] = f"{rate(net['in'])} in, {rate(net['out'])} out"
        out["adapters"] = ", ".join(net["adapters"]) or "none up"
        if net.get("link"):
            out["link"] = link(net["link"])
    disk = view.get("disk")
    if disk:
        out["diskIo"] = f"{rate(disk['read'])} read, {rate(disk['write'])} written"
    if links:
        out["connections"] = (f"Liminal's {links['app']} · the machine's {links['established']} established, "
                              f"{links['listening']} listening")
    if files:
        grown = [g["growth"] for g in files["groups"]]
        count = f"{files['count']:,}+ files" if files["capped"] else plural(files["count"], "file")
        out["dataFiles"] = f"{size(files['total'])} in {count}"
        out["dataGrowth"] = growth(sum(grown)) if grown and all(g is not None for g in grown) else "after a minute of samples"
        out["dataFolder"] = files["root"]
    out["sampledAt"] = when(view.get("sampledAt"))
    cadence = view.get("cadence") or {}
    out["sampled"] = f"every {cadence.get('viewing', 2):g} s while shown, every {cadence.get('background', 30):g} s otherwise"
    if mon:
        out["monitor"] = (f"{core(mon['cpu'])} of a core (its limit {core(mon['limit'])}); {size(mon['memory'])} of samples "
                          f"(at most {size(mon['memoryCap'])})")
        if mon.get("error"):
            out["lastSampleFailed"] = mon["error"]
    return out


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def drive(text: str) -> str:
    """A Windows drive by its letter, "C:" ("C:\\" and "c:" alike); anything else as it is."""
    m = re.match(r"^([A-Za-z]):", str(text))
    return f"{m.group(1).upper()}:" if m else str(text)


def devices_of(path: str) -> set[str]:
    """The block devices holding `path` on Linux: its partition and the disk it is on (where /sys/dev/block/MAJOR:MINOR
    leads among the devices), so a disk's space and its reads and writes meet in one row; none elsewhere."""
    if not sys.platform.startswith("linux"):
        return set()
    try:
        st = os.stat(path)
        parts = Path(os.path.realpath(f"/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}")).parts
    except (OSError, ValueError):
        return set()
    return set(parts[-2:])


def io_cell(d: dict | None, rate_key: str, total_key: str):
    """A disk's reads (or writes) a second, with the bytes since start beneath; "–" for a disk whose are not read."""
    return cell(rate(d[rate_key]), f"{size(d[total_key])} since start") if d else "–"


def disks_table(space: list[dict], io: list[dict], devices=devices_of) -> dict | None:
    """The disks in one table (the user, 2026-11-08: "disk io is redundant as 'DISKS'"): each one's space (the disks
    holding the data, the app and the system) and its reads and writes a second, with the bytes since start, in one
    row when they are the same disk (a drive's letter on Windows, the device holding the mount on Linux); a disk with
    only one of them in a row of its own."""
    if not space and not io:
        return None
    left, rows = list(io), []
    for s in space:
        keys = {drive(s["path"]), *devices(s["path"])}
        d = next((x for x in left if drive(x["name"]) in keys), None)
        if d is not None:
            left.remove(d)
        rows.append([s["path"], ", ".join(s["holds"]), cell(size(s["used"]), share(s["used"] / s["total"] if s["total"] else None)),
                     size(s["free"]), size(s["total"]), io_cell(d, "read", "readTotal"), io_cell(d, "write", "writtenTotal")])
    rows += [[d["name"], "–", "–", "–", "–", io_cell(d, "read", "readTotal"), io_cell(d, "write", "writtenTotal")] for d in left]
    return {"title": "Disks", "rows": rows,
            "columns": [{"title": "Disk"}, {"title": "Holds"}, {"title": "Used", "num": True}, {"title": "Free", "num": True},
                        {"title": "Total", "num": True}, {"title": "Read", "num": True}, {"title": "Written", "num": True}]}


def tables(view: dict) -> list[dict]:
    """Liminal's programs, the disks, the data folders: a title, the columns (num: a figure, right aligned),
    the rows (a cell is its text, or {text, sub} with a second line)."""
    out = []
    programs = view.get("processes") or []
    out.append({"title": "Liminal's programs", "empty": "None of the apps is running.",
                "columns": [{"title": "Program"}, {"title": "Processes", "num": True}, {"title": "CPU", "num": True},
                            {"title": "Memory", "num": True}, {"title": "Disk", "num": True},
                            {"title": "Connections", "num": True}, {"title": "Threads · handles", "num": True}, {"title": "Started"}],
                "rows": [[cell(g["label"] + (" (this one)" if g.get("self") else ""), g.get("command") or None),
                          " · ".join(str(p) for p in g["pids"]), core(g["cpu"]),
                          cell(size(g["memory"]), f"{size(g['private'])} private"),
                          cell(f"{rate(g['readRate'])} read", f"{rate(g['writeRate'])} written"),
                          cell(str((g.get("connections") or {}).get("established", 0)),
                               f"{g['connections']['listening']} listening" if (g.get("connections") or {}).get("listening") else None),
                          f"{g['threads']:,} · {g['handles']:,}", when(g["started"])] for g in programs]})
    files = view.get("files") or {}
    disks = disks_table(files.get("disks") or [], (view.get("disk") or {}).get("disks") or [])
    if disks:
        out.append(disks)
    groups = files.get("groups") or []
    if groups:
        out.append({"title": "Data folders", "note": files.get("root", ""),
                    "columns": [{"title": "Folder"}, {"title": "Files", "num": True}, {"title": "Size", "num": True},
                                {"title": "Growth", "num": True}, {"title": "Largest"}],
                    "rows": [[g["name"] + "/" if g["name"] != "." else "(top folder)", f"{g['count']:,}", size(g["size"]), growth(g["growth"]),
                              cell(g["files"][0]["path"], size(g["files"][0]["size"])) if g.get("files") else "–"] for g in groups[:12]]})
    return out


def charts(view: dict) -> dict:
    """The line charts the page draws over the same times (t: seconds since 1970): the processor (a share of the
    machine), the memory in use (of the total), the network (in and out on one axis, in bytes a second), the disks'
    reads and writes (bytes a second, all disks together) and
    each Liminal program's processor (a share of one core). `unit`: share | bytes | bytes/s; `max`: the axis's
    top when the figure has one; `interval`: the seconds until the next sample."""
    s, m = view.get("series") or {}, view.get("machine") or {}
    t = s.get("t") or []
    programs = view.get("processes") or []
    out = []
    if any(v is not None for v in s.get("cpu") or []):
        out.append({"key": "cpu", "title": "Processor", "unit": "share", "max": 1.0, "lines": [{"key": "cpu", "name": "CPU", "values": s["cpu"]}]})
    if any(v is not None for v in s.get("memory") or []):
        out.append({"key": "memory", "title": "Memory in use", "unit": "bytes", "max": m.get("memoryTotal"),
                    "lines": [{"key": "memory", "name": "in use", "values": s["memory"]}]})
    if any(v is not None for v in [*(s.get("in") or []), *(s.get("out") or [])]):
        out.append({"key": "network", "title": "Network", "unit": "bytes/s", "max": None,
                    "lines": [{"key": "in", "name": "in", "values": s["in"]}, {"key": "out", "name": "out", "values": s["out"]}]})
    if any(v is not None for v in [*(s.get("diskRead") or []), *(s.get("diskWrite") or [])]):
        out.append({"key": "disk", "title": "Disk I/O", "unit": "bytes/s", "max": None,
                    "lines": [{"key": "read", "name": "read", "values": s["diskRead"]},
                              {"key": "write", "name": "written", "values": s["diskWrite"]}]})
    per = s.get("processes") or {}
    lines = [{"key": g["role"], "name": g["label"], "values": per[g["key"]]["cpu"]} for g in programs
             if g["key"] in per and any(v is not None for v in per[g["key"]]["cpu"])]
    if lines:
        out.append({"key": "programs", "title": "Liminal's programs: processor", "unit": "share", "of": "one core", "max": None, "lines": lines})
    return {"span": view.get("span", "recent"), "t": t, "interval": view.get("interval"), "charts": out}


# -- this network: its public address, the ports chosen and checked ------------------------------------------
@dataclass(frozen=True)
class Address:
    """This network's public address of one IP version as last read: the address (None: none was found), whose
    answer it was or why there is none, when it was read (0: not yet)."""
    address: str | None = None
    said: str = ""
    at: float = 0.0


def address_words(a: Address, reading: bool) -> str:
    """A public address as the facts say it."""
    if not a.at:
        return "being read" if reading else "not read yet (it is read while the plugin is attached to the platform)"
    return f"{a.address} · {a.said}, {clock(a.at)}" if a.address else f"none · {a.said}"


def ip_line(version: int, a: Address) -> str:
    return f"IPv{version}: {a.address} ({a.said})" if a.address else f"IPv{version}: none ({a.said})"


def outcome_cell(o: Outcome | None, empty: str = "not checked"):
    """An outcome in a table's cell: its state, with why (and when, for a check) beneath."""
    if o is None:
        return cell("–", empty)
    why = o.why
    if o.state not in ("listening", "free"):
        why = f"{why} · {clock(o.at)}" if why else clock(o.at)
    return cell(o.state, why or None)


def whose(app: str) -> str:
    """One of Liminal's own pages in words: "Liminal's charts", "the integrator's login"."""
    return app if app.startswith("the ") else f"Liminal's {app}"


def port_name(port: int, own: dict[int, str]) -> str:
    return f"{port} ({whose(own[port])})" if port in own else str(port)


def chosen_words(chosen: Chosen, page: bool) -> str:
    """Where the ports listed come from, in words."""
    what = {"liminal": "Liminal's own", "setting": PORTS_VAR, "chosen": "typed"}.get(chosen.source) or PRESETS[chosen.source][0]
    if page:
        return f"{what}: chosen on the page, {KEPT}"
    return what if chosen.source == "setting" or chosen.problem else f"{what}: {PORTS_VAR} is not set"


def report(chosen, where: str, public: Address | None, results: dict, here: dict) -> dict:
    """A check's answer in words (the page's dialog says `said` and `lines`; `ok` False when a check failed or one
    of Liminal's own pages answers from the internet) with each port's outcomes."""
    own = own_ports()
    parts = []
    if where in ("internet", "both"):
        parts.append(f"from the internet at {public.address}: " + tally(r["in"] for r in results.values() if "in" in r))
    if where in ("out", "both"):
        parts.append("out from this machine: " + tally(r["out"] for r in results.values() if "out" in r))
    lines = []
    for p in chosen:
        seen = (("from the internet", results[p].get("in")), ("out", results[p].get("out")), ("here", here.get(p)))
        lines.append(" · ".join([port_name(p, own), *(f"{label}: {o.state}" + (f", {o.why}" if o.why else "") for label, o in seen if o)]))
    exposed = [p for p in chosen if p in own and results[p].get("in") and results[p]["in"].state == "open"]
    lines += [f"{whose(own[p])} page answers from the internet on {p}: Liminal's pages are for this machine only (look at the "
              "router's port forwarding and the firewall)" for p in exposed]
    failed = [p for p in chosen if any(o.state == "failed" for o in results[p].values())]
    return {"said": f"{plural(len(chosen), 'port')} checked " + "; ".join(parts), "lines": lines,
            "ok": not exposed and not failed,
            "ports": {str(p): {**{k: o.as_dict() for k, o in results[p].items()}, "here": here[p].as_dict()} for p in chosen}}


@dataclass
class PathRun:
    """One check of a port's way in from the internet (the user, 2026-11-08: "validate the computer, the router/gateway
    to the computer, then the internet to the computer, and graphically show traffic moving between the three"), as it
    goes and once done: what each hop showed, the packets seen, the conclusion."""
    port: int
    listen: bool
    started: float
    stage: str = "starting"  # starting, computer, router, internet, done
    running: bool = True
    lines: list = field(default_factory=list)  # what was found, in order
    lan: str | None = None  # this computer's address on its network
    gateway: str | None = None
    public: str | None = None
    here: Outcome | None = None  # what listened before the check
    listening: str = ""  # who listens during it: ours (the check's own listener), theirs, "" nobody
    local_only: bool = False  # what listens does so on this machine's own address only
    lan_try: Outcome | None = None  # a connection to this computer's address on its network
    gateway_ms: float | None = None
    hops: list | None = None
    wan: str | None = None  # the router's WAN address, when UPnP gives it
    hairpin: Outcome | None = None  # a connection to the public address from here, through the router
    came_back: bool = False  # ... seen arriving back at this computer (the router's NAT loopback to its DMZ)
    probe: Outcome | None = None  # the check from the internet
    prober: str = ""
    capture_why: str = ""  # why packets were not watched ("" when they were)
    packets: list = field(default_factory=list)
    from_outside: list = field(default_factory=list)  # connections asked from the internet, seen arriving
    answer: str = ""  # this computer's answer to them: accepted, refused, "" none
    arrivals: list = field(default_factory=list)  # connections that reached the check's own listener
    states: dict = field(default_factory=dict)  # each hop's and link's state once judged
    said: str = ""
    finished: float = 0.0
    live: object = None  # the capture while it runs


def local_words(o: Outcome) -> str:
    """A connection arriving at this computer, in words (no answer here is this computer's firewall dropping it)."""
    return {"open": "accepted it", "closed": "refused it: nothing listens on its network address",
            "blocked": "did not answer: Windows drops what nothing answers, or its firewall stopped it"}.get(o.state, o.said)


def judge(run: PathRun) -> tuple[dict, str]:
    """Each hop's and link's state (ok, warn, fail, unknown) and the conclusion, from what the path check found."""
    hop2 = run.hops[1] if run.hops and len(run.hops) > 1 else None
    behind = netpath.kind(run.wan) in ("private", "shared") if run.wan else netpath.kind(hop2) in ("private", "shared")
    s = {"computer": "warn", "router": "warn", "internet": "unknown", "internet-router": "unknown", "router-computer": "unknown"}
    if run.listening == "ours" or (run.listening == "theirs" and not run.local_only):
        s["computer"] = "ok" if run.lan_try and run.lan_try.state == "open" else "warn"
    if run.wan and netpath.kind(run.wan) != "public":
        s["router"] = "fail"
    elif run.came_back:
        s["router"], s["router-computer"] = "ok", "ok"
    p, watched = run.port, not run.capture_why
    if run.probe is None or run.probe.state == "failed":
        said = f"Port {p} could not be checked from the internet: {run.probe.why if run.probe else 'no public address'}."
        return s, said
    if run.probe.state == "open" or run.answer == "accepted":
        s.update({"internet": "ok", "internet-router": "ok", "router-computer": "ok", "computer": "ok"})
        if s["router"] != "fail":
            s["router"] = "ok"
        return s, f"Port {p} is reachable from the internet: {run.prober} connected to {run.public}:{p}, through the router, to this computer."
    if watched and run.from_outside:
        s.update({"internet-router": "ok", "router-computer": "ok", "router": "ok" if s["router"] != "fail" else "fail",
                  "internet": "warn", "computer": "fail" if run.listening else "warn"})
        reach = f"Traffic from the internet reaches this computer on port {p} (through the router), "
        if run.answer == "refused":
            return s, reach + "but nothing accepts it: the connection is refused (nothing listens on every address)."
        if not run.listening:
            return s, (reach + "but nothing listens on it, and Windows drops what nothing answers. Check again listening on "
                       "it, to see whether its firewall lets the traffic in.")
        who = "the check's own listener" if run.listening == "ours" else (run.here.why if run.here else "what listens")
        return s, (reach + f"but nothing answers it: this computer's firewall drops it before it reaches {who} (no rule "
                   "lets the port in, or the program is not allowed on this network's profile).")
    s["internet"] = "fail"
    if not watched:
        return s, (f"Port {p} is not reachable from the internet ({run.probe.why}); where the traffic stops is not known, since "
                   f"packets were not watched ({run.capture_why}).")
    if run.wan and behind:
        s["internet-router"] = "fail"
        return s, (f"Nothing from the internet reached this computer on port {p}. Your router's WAN address is {run.wan}, a "
                   f"{netpath.kind(run.wan)} one: your ISP's NAT (CGNAT) stands between the internet and your router, so its "
                   "DMZ never sees the traffic. A public address from the ISP (or IPv6) is the way out of it.")
    if behind:
        s["internet-router"] = "warn"
        s["router-computer"] = "warn"
        return s, (f"Nothing from the internet reached this computer on port {p}. After your router comes {hop2}, a "
                   f"{netpath.kind(hop2)} address: if the router's own WAN address (on its status page) is private too (10.x, "
                   "172.16-31.x, 192.168.x, 100.64-127.x), your ISP's NAT stands between the internet and the router; if it "
                   "is public, the router does not forward the port here (its DMZ or a port forward), or the ISP blocks it.")
    s["router-computer"] = "fail"
    return s, (f"Nothing from the internet reached this computer on port {p}: the router does not forward it here (its DMZ "
               "or a port forward), or the ISP blocks the port.")


def packet_role(pk, run: PathRun) -> str:
    """What a packet of the path check was, in words."""
    if pk.dst == run.lan and pk.dport == run.port:
        if netpath.kind(pk.src) == "public" and pk.src != run.public:
            return "from the internet"
        return "back through the router" if pk.src in (run.gateway, run.lan, run.public) else "to this computer"
    if pk.src == run.lan and pk.sport == run.port:
        return "this computer's answer"
    if pk.dst == run.public and pk.dport == run.port:
        return "out to the public address"
    return ""


class _Runtime:
    """What the plugin keeps while it lives, shared by its copies (the registry hands out a shallow one): the public
    addresses, the ports' last checks, what listened when read last, the thread reading the address."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reading = threading.Lock()  # one read of the public address at a time
        self.public = {4: Address(), 6: Address()}
        self.checked: dict[int, dict[str, Outcome]] = {}  # port -> {"in": ..., "out": ...}
        self.last: tuple[int, ...] = ()  # the ports of the last check (listed beside the ports chosen)
        self.choice: str | None = None  # the ports listed as chosen on the page (a Chosen source); None: not chosen
        self.custom: tuple[int, ...] = ()  # the ports typed on the page
        self.path: PathRun | None = None  # the last check of a port's way in (or the one running)
        self.here: tuple[float, tuple[int, ...], dict] | None = None  # (when, the ports, what listens on each)
        self.stop: threading.Event | None = None
        self.thread: threading.Thread | None = None


class HwStatsPlugin(MachinePlugin):
    """The hardware stats: present wherever the platform runs; sampling while attached."""

    name = "hw-stats"
    title = "Hardware stats"
    about = ("This machine's processor, memory, network, disks and data files, and every Liminal app's processes: "
             "on Windows and Linux alike; this network's public address and its ports, checked when asked")
    api = "2.1"
    order = 730
    ICON = "gauge"
    HOOKS = (*MachinePlugin.HOOKS, "view", "charts", "public_address", "check_ports", "choose_ports", "refresh_ports", "check_path")
    keys = KEYS

    def __init__(self, probe=None, data: Path | None = None, resolve=None, checker=None, connect=None, net=None, **monitor_options):
        self._probe = probe  # the probe (resources.WindowsProbe, LinuxProbe); this system's, every Liminal app's, unless given
        self._data = data  # the data folder whose files are listed; the framework's (layout.data_dir()) unless given
        self._options = monitor_options  # clock, wall, cpu_clock: a test's
        self._monitor: Monitor | None = None
        self._lock = threading.Lock()
        self._resolve = resolve  # version -> (address, whose): dns.public_address over network.PUBLIC_SERVERS unless given
        self._checker = checker  # the check from the internet (network.CheckHost unless given)
        self._connect = connect  # one connection out (liminal_libs.ports.connect unless given)
        self._net = net if net is not None else Net()  # the path check's route, ping, hops, capture, listener, probe
        self._wall = monitor_options.get("wall") or time.time
        self._rt = _Runtime()

    @property
    def monitor(self) -> Monitor:
        """The sampler, made when first wanted: every Liminal app's processes, this one's as the platform's."""
        with self._lock:
            if self._monitor is None:
                from liminal_libs import layout

                self._monitor = Monitor(self._data if self._data is not None else layout.data_dir(),
                                        probe=self._probe if self._probe is not None else default_probe(match=is_framework),
                                        roles=framework_role, own=OWN, **self._options)
            return self._monitor

    def attach(self, app, login=None) -> dict:
        """Attached by the platform: sampled in the background from now on (every 30 s; every 2 s while shown), and
        this network's public address read now and every 15 minutes."""
        interface = super().attach(app, login)
        self.monitor.start()
        self._watch()
        return interface

    def detach(self) -> None:
        """Detached (the platform ending, the plugin turned off): the sampling ends, the samples go, the address is
        no longer read, the ports' checks go."""
        with self._lock:
            monitor, self._monitor = self._monitor, None
        if monitor is not None:
            monitor.stop()
        with self._rt.lock:
            stop, self._rt.stop, self._rt.thread = self._rt.stop, None, None
            self._rt.checked, self._rt.last, self._rt.here = {}, (), None
        if stop is not None:
            stop.set()
        super().detach()

    @property
    def sampling(self) -> bool:
        with self._lock:
            m = self._monitor
        return m is not None and m._thread is not None and not m._stop.is_set()

    @property
    def watching(self) -> bool:
        """Whether the public address is being read on its own (while attached)."""
        with self._rt.lock:
            return self._rt.stop is not None and not self._rt.stop.is_set()

    def present(self) -> bool:
        return True  # the machine is always there; what can be read of it is in the status

    def view(self, span: str = "recent") -> dict:
        """The monitor's view (the charts app's Resources answer): `span` recent (ten minutes) or day."""
        return self.monitor.view("day" if span == "day" else "recent")

    def charts(self, span: str = "recent") -> dict:
        """The charts of `span` alone (the page's "last day")."""
        return charts(self.view(span))

    # -- the public address --------------------------------------------------------------------------------
    def _watch(self) -> None:
        """The public address read now and every PUBLIC_S while attached, on a thread of its own (a lookup waits on
        the network)."""
        with self._rt.lock:
            if self._rt.stop is not None and not self._rt.stop.is_set():
                return
            stop = self._rt.stop = threading.Event()

            def work():
                while not stop.is_set():
                    self._read_public()
                    stop.wait(PUBLIC_S)
            self._rt.thread = threading.Thread(target=work, name="hw-stats-public-address", daemon=True)
            self._rt.thread.start()

    def _read_public(self) -> dict[int, Address]:
        """This network's public addresses read now (IPv4, then IPv6) and kept; one read at a time (a second asker
        waits for it, then reads again)."""
        resolve = self._resolve or (lambda v: dns.public_address(v, PUBLIC_SERVERS[v]))
        with self._rt.reading:
            found = {}
            for v in (4, 6):
                try:
                    address, said = resolve(v)
                except Exception as e:  # noqa: BLE001 - a lookup failing says why; the plugin goes on
                    address, said = None, f"the lookup failed ({type(e).__name__})"
                found[v] = Address(address, said, self._wall())
            with self._rt.lock:
                self._rt.public.update(found)
            return found

    def public_address(self) -> dict:
        """This network's public addresses read now (the page's Read the public address again; `ip` on the command
        line)."""
        found = self._read_public()
        v4 = found[4]
        return {"said": f"this network's public address is {v4.address}" if v4.address else f"no public IPv4 address was found ({v4.said})",
                "lines": [ip_line(4, v4), ip_line(6, found[6])], "ok": bool(v4.address), "ipv4": v4.address, "ipv6": found[6].address}

    # -- the ports ------------------------------------------------------------------------------------------
    def _setting(self) -> tuple[tuple[int, ...], str | None]:
        """HW_STATS_PORTS as the login holds it (the platform's EnvironmentLogin today: the variable; the user's own
        setting once the login app is bound): (its ports, none when unset or wrong; what is wrong with it)."""
        try:
            value = ((self.login or EnvironmentLogin()).variables([PORTS_VAR]) or {}).get(PORTS_VAR, "")
        except Exception as e:  # noqa: BLE001 - a login that cannot say: no setting, and why
            return (), f"{PORTS_VAR} could not be read from the login ({type(e).__name__})"
        if not str(value or "").strip():
            return (), None
        try:
            return parse_ports(value), None
        except ValueError as e:
            return (), f"{PORTS_VAR}: {e}"

    def selected(self) -> Chosen:
        """The ports the Ports table lists: as chosen on the page (kept until the platform restarts: the login keeps
        it once it holds the plugins' settings), else HW_STATS_PORTS through the login, else Liminal's own pages'."""
        setting, problem = self._setting()
        with self._rt.lock:
            choice, custom = self._rt.choice, self._rt.custom
        if choice == "chosen" and custom:
            return Chosen(custom, "chosen", problem)
        if choice in PRESETS:
            return Chosen(PRESETS[choice][1], choice, problem)
        if setting and choice in (None, "setting"):
            return Chosen(setting, "setting", problem)
        if problem and choice is None:
            problem += "; Liminal's own ports are listed instead"
        return Chosen(tuple(sorted(own_ports())), "liminal", problem)

    def choose_ports(self, ports) -> dict:
        """The ports the Ports table lists, chosen on the page: liminal (Liminal's own), web, mail, remote, setting
        (HW_STATS_PORTS), chosen (the ports typed before) or ports as typed (at most 12). Kept until the platform
        restarts (the login keeps it once it holds the plugins' settings); what listens on them is read at once."""
        text = str(ports if ports is not None else "").strip()
        key = text.lower()
        with self._rt.lock:
            typed = self._rt.custom
        if key in ("liminal", "setting", *PRESETS):
            if key == "setting" and not self._setting()[0]:
                raise ValueError(f"{PORTS_VAR} is not set to ports: nothing to list from it")
            choice, custom = key, typed
        elif key == "chosen":
            if not typed:
                raise ValueError("no ports were typed yet: type them under Other ports")
            choice, custom = "chosen", typed
        else:
            choice, custom = "chosen", parse_ports(text)
        with self._rt.lock:
            self._rt.choice, self._rt.custom, self._rt.last = choice, custom, ()
        chosen = self.selected()
        found = self.listening(chosen.ports, fresh=True)
        own = own_ports()
        return {"said": "listing " + ", ".join(port_name(p, own) for p in chosen.ports),
                "lines": [*(f"{p}: {o.said}" for p, o in found.items()), f"kept {KEPT}"], "ok": True}

    def refresh_ports(self) -> dict:
        """What listens on each port listed, read now (the Ports table's Refresh); nothing is sent anywhere (a check
        from outside runs from Check ports)."""
        chosen = self.selected().ports
        with self._rt.lock:
            last = self._rt.last
        found = self.listening(tuple(sorted({*chosen, *last})), fresh=True)
        return {"said": f"read what listens on {plural(len(found), 'port')} now: {tally(found.values())}",
                "lines": [f"{p}: {o.said}" for p, o in found.items()], "ok": True}

    def listening(self, ports, view: dict | None = None, fresh: bool = True) -> dict[int, Outcome]:
        """What listens on each of `ports` here (read again at most every HERE_S unless `fresh`): a Liminal app by
        its label, another program by its executable's name."""
        ports = tuple(ports)
        now = self._wall()
        with self._rt.lock:
            kept = self._rt.here
        if not fresh and kept and kept[1] == ports and now - kept[0] < HERE_S:
            return kept[2]
        view = self.view("recent") if view is None else view
        probe = self.monitor.probe
        try:
            conns = probe.connections()
        except Exception:  # noqa: BLE001 - sockets not readable: nothing listens, as far as can be told
            conns = []
        liminal = {pid: g["label"] + (" (this one)" if g.get("self") else "")
                   for g in view.get("processes") or [] for pid in g.get("pids") or []}
        others = listening_pids(conns, ports) - set(liminal)
        try:
            named = probe.program_names(others) if others and hasattr(probe, "program_names") else {}
        except Exception:  # noqa: BLE001
            named = {}
        found = listening_here(conns, ports, {pid: f"{name} (pid {pid})" for pid, name in {**named, **liminal}.items()}, now)
        with self._rt.lock:
            self._rt.here = (now, ports, found)
        return found

    def check_ports(self, ports=None, where: str = "internet", address: str | None = None) -> dict:
        """Ports checked now (the page's Check ports; `ports` on the command line): `ports` as typed (the ports chosen
        unless given), `where` internet (check-host.net's servers try to connect to this network's public IPv4
        address, read again now: the address and the ports go to check-host.net), out (this machine connects to
        portquiz.net on each) or both; what listens on each here is read too. `address`, when given (the form shows
        the one it will check), must still be this network's. Each port's outcomes kept for the Ports table."""
        where = str(where or "internet").strip().lower()
        if where not in WHERE:
            raise ValueError(f"a port is checked from the internet, out or both, not {where!r}")
        chosen = parse_ports(ports) if ports not in (None, "", (), []) else self.selected().ports
        view = self.view("recent")
        results: dict[int, dict[str, Outcome]] = {p: {} for p in chosen}
        public = None
        if where in ("internet", "both"):
            public = self._read_public()[4]
            if not public.address:
                raise RuntimeError(f"this network's public IPv4 address could not be read ({public.said}): nothing was "
                                   "asked of check-host.net")
            if address not in (None, "") and str(address).strip() != public.address:
                raise ValueError(f"this network's public address is {public.address} now, not {address}: check again")
            for p, o in (self._checker or CheckHost()).check(public.address, chosen).items():
                results[p]["in"] = o
        if where in ("out", "both"):
            for p, o in reach_out(chosen, OUT_HOST, connect=self._connect or connect_out, clock=self._wall).items():
                results[p]["out"] = o
        with self._rt.lock:
            for p, r in results.items():
                self._rt.checked.setdefault(p, {}).update(r)
            self._rt.last = chosen
        return report(chosen, where, public, results, self.listening(chosen, view))

    # -- a port's way in, hop by hop -----------------------------------------------------------------------------
    def check_path(self, port, listen="yes") -> dict:
        """A port's way in checked hop by hop on a thread of its own (the page draws it as it goes): this computer
        (what listens, or the check's own listener when nothing does and `listen` is yes; a connection to its address
        on the network), the router (a ping, the first hops, its WAN address over UPnP, a connection to the public
        address turned back to this computer), then the internet (portchecker.io, else check-host.net, connecting to
        the public address); the port's packets watched at the network adapter throughout (Npcap or libpcap)."""
        ports = parse_ports(port)
        if len(ports) != 1:
            raise ValueError("the way in is checked one port at a time")
        listen = str(listen if listen is not None else "yes").strip().lower() not in ("no", "false", "0", "off")
        with self._rt.lock:
            if self._rt.path is not None and self._rt.path.running:
                raise ValueError(f"the way in to port {self._rt.path.port} is being checked: wait for it to end")
            run = self._rt.path = PathRun(ports[0], listen, self._wall())
        threading.Thread(target=self._run_path, args=(run,), name=f"hw-stats-path-{ports[0]}", daemon=True).start()
        return {"said": f"checking the way in to port {ports[0]}: this computer, the router, then the internet",
                "lines": ["the page draws it as it goes (about fifteen seconds)"], "ok": True}

    def _run_path(self, run: PathRun) -> None:
        net, wall, say = self._net, self._wall, run.lines.append
        connect = self._connect or connect_out
        cap = lis = None
        try:
            route = net.route()
            run.lan, run.gateway = route.address, route.gateway
            if not run.lan:
                raise RuntimeError("this computer's address on its network could not be read")
            run.public = self._read_public()[4].address
            try:
                cap = run.live = net.capture(run.lan, [run.port])
                say(f"watching port {run.port}'s packets at the network adapter")
            except Exception as e:  # noqa: BLE001 - CaptureError, OSError: the check goes on without them
                run.capture_why = str(e) or type(e).__name__
                say(f"port {run.port}'s packets are not watched: {run.capture_why}")
            # 1. this computer
            run.stage = "computer"
            run.here = here = self.listening((run.port,), fresh=True)[run.port]
            if here.state == "listening":
                run.listening = "theirs"
                run.local_only = all(d.endswith("this machine only") for d in here.detail)
                say(f"this computer: {here.why}")
            elif run.listen:
                try:
                    lis = net.listener(run.port)
                    run.listening = "ours"
                    say(f"this computer: nothing listened on {run.port}, so the check listens on it (every address) until it ends")
                except OSError as e:
                    say(f"this computer: nothing listens on {run.port}, and the check could not listen on it ({e.strerror or e})")
            else:
                say(f"this computer: nothing listens on {run.port} (the check does not listen on it)")
            time.sleep(SETTLE_S)
            run.lan_try = attempt(run.port, run.lan, timeout=2.0, connect=connect, clock=wall)
            say(f"a connection to {run.lan}:{run.port}, this computer's address on its network: " + local_words(run.lan_try))
            # 2. the router
            run.stage = "router"
            if run.gateway:
                run.gateway_ms = net.ping(run.gateway)
                say(f"the router {run.gateway} " + (f"answered a ping in {run.gateway_ms:g} ms" if run.gateway_ms is not None
                                                     else "did not answer a ping (some routers do not)"))
            run.hops = net.hops()
            if run.hops:
                say(f"the way out toward {TRACE_TO}: " + ", then ".join(f"{h} ({netpath.kind(h)})" if h else "no answer" for h in run.hops))
            run.wan = net.wan(run.lan)
            say(f"the router's own WAN address (UPnP): {run.wan}, {netpath.kind(run.wan)}" if run.wan
                else "the router's own WAN address: not given (its UPnP is off, or it did not answer)")
            if run.public:
                arrived, seen = len(lis.arrivals) if lis else 0, len(cap.packets) if cap else 0
                run.hairpin = attempt(run.port, run.public, timeout=3.0, connect=connect, clock=wall)
                time.sleep(SETTLE_S)
                back = (lis.arrivals[arrived:] if lis else []) + [
                    pk for pk in (cap.packets[seen:] if cap else []) if pk.syn and pk.dst == run.lan and pk.dport == run.port]
                run.came_back = bool(back)
                say(f"a connection to {run.public}:{run.port}, this network's public address: "
                    + ("the router turned it back to this computer, which " + local_words(run.hairpin) if run.came_back else
                       f"{run.hairpin.state}; it did not come back to this computer (many routers do not loop back)"))
            # 3. the internet
            run.stage = "internet"
            if run.public:
                seen = len(cap.packets) if cap else 0
                run.probe, run.prober = net.probe(run.public, run.port)
                say(f"from the internet ({run.prober or 'no service'}): {run.probe.said}")
                time.sleep(LATE_S)
                new = cap.packets[seen:] if cap else []
                run.from_outside = [pk for pk in new if pk.syn and pk.dst == run.lan and pk.dport == run.port
                                    and netpath.kind(pk.src) == "public" and pk.src != run.public]
                sources = {pk.src for pk in run.from_outside}
                answers = [pk for pk in new if pk.src == run.lan and pk.sport == run.port and pk.dst in sources]
                run.answer = ("accepted" if any(pk.flags.startswith("SYN ACK") for pk in answers) else
                              "refused" if any("RST" in pk.flags for pk in answers) else "")
                if not run.capture_why:
                    say(f"seen arriving from the internet: {len(run.from_outside)} connection request(s)"
                        + (f" from {', '.join(sorted(sources))}" if sources else "")
                        + (f"; this computer {run.answer} them" if run.answer else "; this computer did not answer" if sources else ""))
            else:
                run.probe = Outcome("failed", "failed: this network's public address is not known", wall())
        except Exception as e:  # noqa: BLE001 - a fault ends the check, said
            say(f"the check stopped: {e}")
            run.probe = run.probe or Outcome("failed", f"failed: the check stopped ({e})", wall())
        finally:
            if lis is not None:
                run.arrivals = lis.stop()
            if cap is not None:
                run.packets = cap.stop()
            run.live = None
            run.states, run.said = judge(run)
            run.finished, run.stage, run.running = wall(), "done", False

    def _path_view(self) -> dict | None:
        """The path check for the platform's page (liminal-platform 0.8.0, status.paths): three hops and the links
        between them, each with its state (idle, checking, ok, warn, fail, unknown), what it found beneath."""
        with self._rt.lock:
            run = self._rt.path
        if run is None:
            return None
        states = dict(run.states) if not run.running else {}
        if run.running:  # the hop being checked, and the links its traffic takes
            order = ("computer", "router", "internet")
            at = order.index(run.stage) if run.stage in order else -1
            for i, hop in enumerate(order):
                states[hop] = "checking" if i == at else ("done" if i < at else "idle")
            states["router-computer"] = "checking" if run.stage in ("router", "internet") else "idle"
            states["internet-router"] = "checking" if run.stage == "internet" else "idle"
        hop2 = run.hops[1] if run.hops and len(run.hops) > 1 else None
        listens = {"ours": "the check listens on it", "theirs": (run.here.why if run.here else "")}.get(run.listening, "nothing listens on it")
        router_sub = " · ".join(x for x in (
            run.gateway or "", f"ping {run.gateway_ms:g} ms" if run.gateway_ms is not None else "",
            f"WAN {run.wan}" if run.wan else (f"next {hop2} ({netpath.kind(hop2)})" if hop2 else "")) if x)
        nodes = [{"id": "internet", "title": "The internet", "state": states.get("internet", "idle"),
                  "sub": " · ".join(x for x in (run.public or "", run.prober) if x)},
                 {"id": "router", "title": "Router", "state": states.get("router", "idle"), "sub": router_sub},
                 {"id": "computer", "title": "This computer", "state": states.get("computer", "idle"),
                  "sub": " · ".join(x for x in (f"{run.lan}:{run.port}" if run.lan else f"port {run.port}", listens) if x)}]
        links = [{"from": "internet", "to": "router", "state": states.get("internet-router", "idle"), "title": "the internet to the router"},
                 {"from": "router", "to": "computer", "state": states.get("router-computer", "idle"), "title": "the router to this computer"}]
        return {"id": f"path-{run.port}", "title": f"Port {run.port}: the way in from the internet", "running": run.running,
                "stage": run.stage, "said": run.said if not run.running else "checking " + {
                    "computer": "this computer", "router": "the router", "internet": "the way in from the internet"}.get(run.stage, "what is needed") + "…",
                "lines": list(run.lines), "nodes": nodes, "links": links,
                "at": clock(run.started) + (f", done {clock(run.finished)}" if run.finished else "")}

    def _traffic_table(self) -> dict | None:
        """The path check's packets on its port (seen at the network adapter): when, from, to, flags, what each was."""
        with self._rt.lock:
            run = self._rt.path
        if run is None:
            return None
        packets = run.live.packets if run.running and run.live is not None else run.packets
        if not packets and run.capture_why:
            return {"title": f"Traffic on port {run.port}", "columns": [{"title": "Packets"}], "rows": [],
                    "empty": f"Not watched: {run.capture_why}"}
        rows = [[datetime.fromtimestamp(pk.at).strftime("%H:%M:%S.%f")[:-3], f"{pk.src}:{pk.sport}", f"{pk.dst}:{pk.dport}", pk.flags,
                 packet_role(pk, run)] for pk in packets[-PACKETS_SHOWN:]]
        return {"title": f"Traffic on port {run.port}", "note": "TCP packets seen at the network adapter (Npcap), before the firewall decides",
                "empty": "No packet on the port yet." if run.running else "No packet on the port was seen.",
                "columns": [{"title": "When"}, {"title": "From"}, {"title": "To"}, {"title": "Flags"}, {"title": "What"}], "rows": rows}

    def _path_form(self, chosen: Chosen, here: dict) -> dict:
        """Check the way in (status.forms): check_path's arguments in order, the confirmation saying what is asked of
        whom (the router, the services) and what listening means on a DMZ host."""
        free = [p for p in chosen.ports if (here.get(p) is not None and here[p].state == "free")]
        return {
            "id": "path", "hook": "check_path", "title": "Check the way in",
            "note": "One port: this computer, the router, then the internet; the page draws the traffic as it goes.",
            "fields": [
                {"name": "port", "label": "Port", "type": "number", "required": True, "min": 1, "max": 65535,
                 "value": (free or list(chosen.ports) or [8795])[0]},
                {"name": "listen", "label": "While checking", "type": "choice", "value": "yes", "choices": [
                    {"value": "yes", "title": "Listen on it when nothing does",
                     "note": "a connection then has somewhere to arrive, and is seen arriving; Windows may ask once whether Python may accept connections"},
                    {"value": "no", "title": "Do not listen", "note": "only what already listens answers; the packets still show what arrives"}]}],
            "submit": "Review",
            "confirm": {"title": "Check the way in to port {port}?",
                        "words": (f"This computer is checked first, then the router (a ping, the first routers toward {TRACE_TO}, its WAN "
                                  "address asked over UPnP, a connection to this network's public address), then the internet: "
                                  "portchecker.io (else check-host.net) connects to this network's public address on the port. "
                                  "The port's packets are watched at the network adapter meanwhile. Listening: Windows may ask "
                                  "whether Python may accept connections; this computer is the DMZ host, so allowing it on "
                                  "public networks lets the internet reach Python programs here while they listen."),
                        "yes": "Check"}}

    def _exposed(self) -> list[str]:
        """Liminal's own pages found answering from the internet (they are for this machine only)."""
        own = own_ports()
        with self._rt.lock:
            hits = sorted(p for p, r in self._rt.checked.items() if p in own and r.get("in") and r["in"].state == "open")
        return [f"{whose(own[p])} page answers from the internet on port {p}: Liminal's pages are for this machine only" for p in hits]

    def _ports_table(self, chosen: Chosen, here: dict) -> dict:
        """The Ports table (liminal-platform 0.7.0: a table's own choices and buttons): the ports listed chosen above
        its rows (Liminal's own, a set, HW_STATS_PORTS, the ports typed), Refresh, Other ports and Check ports under it."""
        with self._rt.lock:
            checked = {p: dict(r) for p, r in self._rt.checked.items()}
            v4, typed = self._rt.public[4].address, self._rt.custom
        own = own_ports()
        rows = [[cell(str(p), whose(own[p]) if p in own else None), outcome_cell(here.get(p), "not read"),
                 outcome_cell(checked.get(p, {}).get("in")), outcome_cell(checked.get(p, {}).get("out")),
                 {"form": "path", "title": "Way in", "values": {"port": p}, "label": f"Check the way in to port {p}"}] for p in sorted(here)]
        listed = " ".join(map(str, chosen.ports))
        setting = self._setting()[0]
        choices = [{"value": "liminal", "title": "Liminal's own", "note": " ".join(map(str, sorted(own)))},
                   *({"value": k, "title": title, "note": " ".join(map(str, ports))} for k, (title, ports) in PRESETS.items()),
                   *([{"value": "setting", "title": PORTS_VAR, "note": " ".join(map(str, setting))}] if setting else []),
                   *([{"value": "chosen", "title": "Typed", "note": " ".join(map(str, typed))}] if typed else [])]
        target = v4 or "this network's public address"
        return {"title": "Ports",
                "note": (f"Here: this machine's sockets now. From the internet: check-host.net's servers connecting to {target}. "
                         f"Out: this machine connecting to {OUT_HOST}. Those two only when asked (Check ports)."),
                "options": [{"title": "Ports listed", "hook": "choose_ports", "value": chosen.source, "choices": choices}],
                "columns": [{"title": "Port"}, {"title": "Here"}, {"title": "From the internet"}, {"title": "Out from this machine"},
                            {"title": "Hop by hop"}],
                "rows": rows,
                "actions": [{"hook": "refresh_ports", "args": [], "title": "Refresh",
                             "note": "reads what listens on each port now; nothing is sent anywhere"},
                            {"form": "choose", "title": "Other ports…", "values": {"ports": listed}},
                            {"form": "ports", "title": "Check ports…", "values": {"ports": listed}},
                            {"form": "path", "title": "Check the way in…"}]}

    def _choose_form(self, chosen: Chosen) -> dict:
        """Other ports (liminal-platform 0.7.0: confirm false, since it changes nothing on the machine): the ports the
        Ports table lists, typed; check_ports' sibling choose_ports asked with them once filled."""
        return {"id": "choose", "hook": "choose_ports", "title": "Ports listed", "confirm": False,
                "note": f"At most {MAX_PORTS}. Kept {KEPT}.",
                "fields": [{"name": "ports", "label": "Ports", "type": "text", "required": True, "value": " ".join(map(str, chosen.ports)),
                            "placeholder": "25, 80, 443, 8765-8768", "note": "separated by commas or spaces; a range as 8765-8768"}],
                "submit": "List them"}

    def _ports_form(self, chosen: Chosen) -> dict:
        """The Check ports form (liminal-platform 0.6.0, status.forms): the fields are check_ports' arguments in order."""
        with self._rt.lock:
            v4 = self._rt.public[4].address
        return {
            "id": "ports", "hook": "check_ports", "title": "Check ports",
            "note": f"At most {MAX_PORTS} at once. What listens on each here is read too; nothing on this machine is changed.",
            "fields": [
                {"name": "ports", "label": "Ports", "type": "text", "required": True, "value": " ".join(map(str, chosen.ports)),
                 "placeholder": "25, 80, 443, 8765-8768", "note": "separated by commas or spaces; a range as 8765-8768"},
                {"name": "where", "label": "Checked", "type": "choice", "value": "internet", "choices": [
                    {"value": "internet", "title": "From the internet",
                     "note": "check-host.net's servers (three, in different countries) try to connect to this network's public address on each port"},
                    {"value": "out", "title": "Out from this machine",
                     "note": f"this machine connects to {OUT_HOST}, which answers on every port: a firewall or the ISP blocking one shows"},
                    {"value": "both", "title": "Both", "note": "from the internet, then out from this machine"}]},
                {"name": "address", "label": "Public address", "type": "fixed", "value": v4, "when": {"where": ["internet", "both"]},
                 "empty": "read again when checked"}],
            "submit": "Review",
            "confirm": {"title": "Check these ports?",
                        "words": ("From the internet, check-host.net is given this network's public address and these ports, and "
                                  f"its servers try to connect to them; out from this machine, this machine connects to {OUT_HOST} on "
                                  "each. Nothing is changed here."),
                        "yes": "Check"}}

    def status(self) -> dict:
        view = self.view("recent")
        chosen = self.selected()
        with self._rt.lock:
            v4, v6, last, page = self._rt.public[4], self._rt.public[6], self._rt.last, self._rt.choice is not None
        reading = self.watching
        own = own_ports()
        network = {"publicAddress": address_words(v4, reading), "publicIpv6": address_words(v6, reading),
                   "ports": ", ".join(port_name(p, own) for p in chosen.ports) + f" ({chosen_words(chosen, page)})"}
        base = facts(view)
        after = next((k for k in ("link", "adapters", "network") if k in base), None)  # the last of the network's figures
        out: dict = {"present": True, "summary": summary(view)}
        for k, v in base.items():
            out[k] = v
            if k == after:
                out.update(network)
        if after is None:
            out.update(network)
        here = self.listening(tuple(sorted({*chosen.ports, *last})), view, fresh=False)
        tabs = tables(view)
        tabs[1:1] = [t for t in (self._ports_table(chosen, here), self._traffic_table()) if t]
        path = self._path_view()
        out.update({"sampling": self.sampling, "tables": tabs, "charts": charts(view), "paths": [path] if path else [],
                    "forms": [self._ports_form(chosen), self._choose_form(chosen), self._path_form(chosen, here)],
                    "actions": [{"hook": "public_address", "args": [], "title": "Read the public address again",
                                 "note": "asks OpenDNS (else Google's name server) for this network's address now"}]})
        trouble = ([chosen.problem] if chosen.problem else []) + self._exposed()
        if trouble:
            out["problem"] = "; ".join(trouble)
        return out


MACHINE = HwStatsPlugin()
