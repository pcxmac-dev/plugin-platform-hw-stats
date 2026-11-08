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

import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from liminal_libs import dns
from liminal_libs.apps import EnvironmentLogin
from liminal_libs.machines.firewall import app_ports
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.ports import MAX_PORTS, Outcome, here as listening_here, listening_pids, parse_ports, reach_out, tally
from liminal_libs.ports import connect as connect_out
from liminal_libs.resources import Monitor, default_probe, framework_role, is_framework
from liminal_libs.sources.keys import KeyVar

from .network import OUT_HOST, PUBLIC_SERVERS, CheckHost

__version__ = "0.2.0"
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
    """A time (seconds since 1970) as this machine's local time."""
    return datetime.fromtimestamp(seconds).astimezone().strftime("%b %d %H:%M") if seconds else "–"


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
    disks = files.get("disks") or []
    if disks:
        out.append({"title": "Disks", "columns": [{"title": "Disk"}, {"title": "Holds"}, {"title": "Used", "num": True},
                                                  {"title": "Free", "num": True}, {"title": "Total", "num": True}],
                    "rows": [[d["path"], ", ".join(d["holds"]), cell(size(d["used"]), share(d["used"] / d["total"] if d["total"] else None)),
                              size(d["free"]), size(d["total"])] for d in disks]})
    io = (view.get("disk") or {}).get("disks") or []
    if io:
        out.append({"title": "Disk I/O", "columns": [{"title": "Disk"}, {"title": "Read", "num": True},
                                                     {"title": "Written", "num": True}, {"title": "Read since start", "num": True},
                                                     {"title": "Written since start", "num": True}],
                    "rows": [[d["name"], rate(d["read"]), rate(d["write"]), size(d["readTotal"]), size(d["writtenTotal"])] for d in io]})
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


class _Runtime:
    """What the plugin keeps while it lives, shared by its copies (the registry hands out a shallow one): the public
    addresses, the ports' last checks, what listened when read last, the thread reading the address."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reading = threading.Lock()  # one read of the public address at a time
        self.public = {4: Address(), 6: Address()}
        self.checked: dict[int, dict[str, Outcome]] = {}  # port -> {"in": ..., "out": ...}
        self.last: tuple[int, ...] = ()  # the ports of the last check (listed beside the ports chosen)
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
    HOOKS = (*MachinePlugin.HOOKS, "view", "charts", "public_address", "check_ports")
    keys = KEYS

    def __init__(self, probe=None, data: Path | None = None, resolve=None, checker=None, connect=None, **monitor_options):
        self._probe = probe  # the probe (resources.WindowsProbe, LinuxProbe); this system's, every Liminal app's, unless given
        self._data = data  # the data folder whose files are listed; the framework's (layout.data_dir()) unless given
        self._options = monitor_options  # clock, wall, cpu_clock: a test's
        self._monitor: Monitor | None = None
        self._lock = threading.Lock()
        self._resolve = resolve  # version -> (address, whose): dns.public_address over network.PUBLIC_SERVERS unless given
        self._checker = checker  # the check from the internet (network.CheckHost unless given)
        self._connect = connect  # one connection out (liminal_libs.ports.connect unless given)
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
    def selected(self) -> tuple[tuple[int, ...], bool, str | None]:
        """The ports chosen: HW_STATS_PORTS as the login holds it (the platform's EnvironmentLogin today: the variable;
        the user's own setting once the login app is bound), else Liminal's own pages' ports. (the ports, whether
        the setting chose them, what is wrong with the setting)."""
        own = tuple(sorted(own_ports()))
        try:
            value = ((self.login or EnvironmentLogin()).variables([PORTS_VAR]) or {}).get(PORTS_VAR, "")
        except Exception as e:  # noqa: BLE001 - a login that cannot say: Liminal's own ports, and why
            return own, False, f"{PORTS_VAR} could not be read from the login ({type(e).__name__}): Liminal's own ports are listed"
        if not str(value or "").strip():
            return own, False, None
        try:
            return parse_ports(value), True, None
        except ValueError as e:
            return own, False, f"{PORTS_VAR}: {e}; Liminal's own ports are listed instead"

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
        chosen = parse_ports(ports) if ports not in (None, "", (), []) else self.selected()[0]
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

    def _exposed(self) -> list[str]:
        """Liminal's own pages found answering from the internet (they are for this machine only)."""
        own = own_ports()
        with self._rt.lock:
            hits = sorted(p for p, r in self._rt.checked.items() if p in own and r.get("in") and r["in"].state == "open")
        return [f"{whose(own[p])} page answers from the internet on port {p}: Liminal's pages are for this machine only" for p in hits]

    def _ports_table(self, chosen, here: dict) -> dict:
        with self._rt.lock:
            checked = {p: dict(r) for p, r in self._rt.checked.items()}
            v4 = self._rt.public[4].address
        own = own_ports()
        rows = [[cell(str(p), whose(own[p]) if p in own else None), outcome_cell(here.get(p), "not read"),
                 outcome_cell(checked.get(p, {}).get("in")), outcome_cell(checked.get(p, {}).get("out"))] for p in sorted(here)]
        target = v4 or "this network's public address"
        return {"title": "Ports",
                "note": (f"Here: this machine's sockets now. From the internet: check-host.net's servers connecting to {target}. "
                         f"Out: this machine connecting to {OUT_HOST}. Those two only when asked (Check ports)."),
                "columns": [{"title": "Port"}, {"title": "Here"}, {"title": "From the internet"}, {"title": "Out from this machine"}],
                "rows": rows,
                "actions": [{"form": "ports", "title": "Check ports…", "values": {"ports": " ".join(map(str, chosen))}}]}

    def _ports_form(self, chosen) -> dict:
        """The Check ports form (liminal-platform 0.6.0, status.forms): the fields are check_ports' arguments in order."""
        with self._rt.lock:
            v4 = self._rt.public[4].address
        return {
            "id": "ports", "hook": "check_ports", "title": "Check ports",
            "note": f"At most {MAX_PORTS} at once. What listens on each here is read too; nothing on this machine is changed.",
            "fields": [
                {"name": "ports", "label": "Ports", "type": "text", "required": True, "value": " ".join(map(str, chosen)),
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
        chosen, chose, problem = self.selected()
        with self._rt.lock:
            v4, v6, last = self._rt.public[4], self._rt.public[6], self._rt.last
        reading = self.watching
        own = own_ports()
        network = {"publicAddress": address_words(v4, reading), "publicIpv6": address_words(v6, reading),
                   "ports": ", ".join(port_name(p, own) for p in chosen) + (f" ({PORTS_VAR})" if chose else f" (Liminal's own: {PORTS_VAR} is not set)")}
        base = facts(view)
        after = next((k for k in ("link", "adapters", "network") if k in base), None)  # the last of the network's figures
        out: dict = {"present": True, "summary": summary(view)}
        for k, v in base.items():
            out[k] = v
            if k == after:
                out.update(network)
        if after is None:
            out.update(network)
        here = self.listening(tuple(sorted({*chosen, *last})), view, fresh=False)
        tabs = tables(view)
        tabs.insert(1, self._ports_table(chosen, here))
        out.update({"sampling": self.sampling, "tables": tabs, "charts": charts(view), "forms": [self._ports_form(chosen)],
                    "actions": [{"hook": "public_address", "args": [], "title": "Read the public address again",
                                 "note": "asks OpenDNS (else Google's name server) for this network's address now"}]})
        trouble = ([problem] if problem else []) + self._exposed()
        if trouble:
            out["problem"] = "; ".join(trouble)
        return out


MACHINE = HwStatsPlugin()
