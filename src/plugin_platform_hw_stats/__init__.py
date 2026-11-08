"""Hardware stats for Liminal (the user, 2026-11-07: "i need the hardware monitoring that was in charts, it needs
to be windows and linux agnostic, ie it runs on both, the stats were on the charts app but they need a plugin
too, hw-stats platform plugin"): this machine's processor, memory, network and disks, the data files, and every
Liminal app's processes (the charts app, the integrator, the login, the platform) with their CPU, memory, reads
and writes, threads and connections. The library's resources.Monitor samples them (Windows: kernel32, ntdll and
iphlpapi; Linux: /proc and /sys) every 30 s in the background and every 2 s while the platform's page shows
them, at most 5% of one core; it runs only while the plugin is attached to the platform app (nothing samples
when nothing uses it). The platform's page draws `status()`: the facts, the tables and the charts.

    python -m plugin_platform_hw_stats status | view [recent|day] | charts [recent|day]
"""
from __future__ import annotations

import sys
import threading
from datetime import datetime
from pathlib import Path

from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.resources import Monitor, default_probe, framework_role, is_framework

__version__ = "0.1.0"
OWN = ("platform", "Platform")  # this process's role when its command line names no Liminal app (a test, a one-off)
UNITS = ("B", "KB", "MB", "GB", "TB", "PB")
SYSTEMS = {"windows": "Windows", "linux": "Linux", "other": sys.platform}


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


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


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
    machine), the memory in use (of the total), the network (in and out on one axis, in bytes a second) and
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
    per = s.get("processes") or {}
    lines = [{"key": g["role"], "name": g["label"], "values": per[g["key"]]["cpu"]} for g in programs
             if g["key"] in per and any(v is not None for v in per[g["key"]]["cpu"])]
    if lines:
        out.append({"key": "programs", "title": "Liminal's programs: processor", "unit": "share", "of": "one core", "max": None, "lines": lines})
    return {"span": view.get("span", "recent"), "t": t, "interval": view.get("interval"), "charts": out}


class HwStatsPlugin(MachinePlugin):
    """The hardware stats: present wherever the platform runs; sampling while attached."""

    name = "hw-stats"
    title = "Hardware stats"
    about = ("This machine's processor, memory, network, disks and data files, and every Liminal app's processes: "
             "on Windows and Linux alike")
    api = "2.1"
    order = 730
    ICON = "gauge"
    HOOKS = (*MachinePlugin.HOOKS, "view", "charts")

    def __init__(self, probe=None, data: Path | None = None, **monitor_options):
        self._probe = probe  # the probe (resources.WindowsProbe, LinuxProbe); this system's, every Liminal app's, unless given
        self._data = data  # the data folder whose files are listed; the framework's (layout.data_dir()) unless given
        self._options = monitor_options  # clock, wall, cpu_clock: a test's
        self._monitor: Monitor | None = None
        self._lock = threading.Lock()

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
        """Attached by the platform: sampled in the background from now on (every 30 s; every 2 s while shown)."""
        interface = super().attach(app, login)
        self.monitor.start()
        return interface

    def detach(self) -> None:
        """Detached (the platform ending, the plugin turned off): the sampling ends, the samples go."""
        with self._lock:
            monitor, self._monitor = self._monitor, None
        if monitor is not None:
            monitor.stop()
        super().detach()

    @property
    def sampling(self) -> bool:
        with self._lock:
            m = self._monitor
        return m is not None and m._thread is not None and not m._stop.is_set()

    def present(self) -> bool:
        return True  # the machine is always there; what can be read of it is in the status

    def view(self, span: str = "recent") -> dict:
        """The monitor's view (the charts app's Resources answer): `span` recent (ten minutes) or day."""
        return self.monitor.view("day" if span == "day" else "recent")

    def charts(self, span: str = "recent") -> dict:
        """The charts of `span` alone (the page's "last day")."""
        return charts(self.view(span))

    def status(self) -> dict:
        view = self.view("recent")
        return {"present": True, "summary": summary(view), **facts(view), "sampling": self.sampling,
                "tables": tables(view), "charts": charts(view)}


MACHINE = HwStatsPlugin()
