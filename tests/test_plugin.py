"""Hardware stats: the plugin over a stand-in probe (nothing of this machine read): its status after two samples
(the summary, the facts, the tables, the charts), sampling only while attached, the hooks asked by name, the
command line; then once over this machine's own probe (Windows or Linux: CI runs both)."""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import plugin_platform_hw_stats as hw
import plugin_platform_hw_stats.__main__ as cli
from liminal_libs.resources import Conn, Disk, Machine, Net, Proc
from plugin_platform_hw_stats import HwStatsPlugin

GB = 2**30
MB = 2**20


class FakeProbe:
    """The charts app, the integrator and this process, and the machine, moving on at each `step()`."""

    def __init__(self):
        self.n = 0

    def step(self):
        self.n += 1

    def processes(self):
        n = self.n
        return [Proc(4242, 1, "pythonw.exe -m liminal_charts gui --no-browser --port 8765", 1_800_000_000.0, 10.0 + n * 0.5,
                     500 * MB, 400 * MB, 1000 + n * 2000, 10 + n * 1000, 24, 300),
                Proc(4300, 1, "pythonw.exe -m liminal_integrator service run --daemon", 1_800_000_100.0, 4.0 + n * 0.2,
                     200 * MB, 150 * MB, 0, 0, 12, 200),
                Proc(os.getpid(), 1, "python -m pytest", 1_800_000_200.0, 1.0, 50 * MB, 40 * MB, 0, 0, 4, 50)]

    def machine(self):
        return Machine(cpus=8, busy_s=100.0 + self.n * 4.0, total_s=1000.0 + self.n * 16.0, memory_total=32 * GB,
                       memory_available=24 * GB, commit_total=40 * GB, commit_available=30 * GB)

    def network(self):
        return Net(received=10_000 + self.n * 4096, sent=5_000 + self.n * 2048, link_bps=1_000_000_000, adapters=("Ethernet",))

    def disks(self):
        return [Disk("C:", 10 * GB + self.n * 4 * MB, 2 * GB + self.n * 2 * MB)]

    def connections(self):
        return [Conn(4242, "listening", "127.0.0.1:8765", ""), Conn(4242, "established", "127.0.0.1:8765", "127.0.0.1:50000"),
                Conn(9999, "established", "10.0.0.2:51000", "10.0.0.9:443")]


def stand_in(tmp_path):
    (tmp_path / "charts").mkdir()
    (tmp_path / "charts" / "liminal.db").write_bytes(b"x" * 3072)
    (tmp_path / "login").mkdir()
    (tmp_path / "login" / "users.db").write_bytes(b"x" * 1024)
    probe, t = FakeProbe(), [100.0]
    plugin = HwStatsPlugin(probe=probe, data=tmp_path, clock=lambda: t[0], wall=lambda: 1_800_010_000.0 + t[0], cpu_clock=lambda: 0.0)

    def later(seconds=2.0):
        probe.step()
        t[0] += seconds
    return plugin, later


def test_the_figures_in_words_as_the_charts_app_gave_them():
    assert (hw.size(0), hw.size(1536), hw.size(150 * MB), hw.size(3 * GB / 2), hw.size(None)) == ("0 B", "1.5 KB", "150 MB", "1.5 GB", "–")
    assert (hw.rate(2048), hw.rate(None), hw.share(0.254), hw.core(0.05), hw.core(0.25)) == ("2.0 KB/s", "–", "25%", "5.0%", "25%")
    assert (hw.link(1e9), hw.link(1e8), hw.link(0), hw.growth(2048), hw.growth(None)) == ("1.0 Gb/s", "100 Mb/s", "", "+2.0 KB/h", "–")
    assert hw.when(None) == "–" and hw.when("not a time") == "not a time" and len(hw.when("2026-11-07T19:03:12+00:00")) == 12
    assert hw.summary({"processes": [], "machine": None, "sampledAt": None}) == "sampling: the first sample is under way"


def test_the_status_says_the_machine_every_liminal_program_the_disks_and_the_data(tmp_path):
    p, later = stand_in(tmp_path)
    p.monitor.sample()
    later()
    p.monitor.sample()
    s = p.status()
    assert s["present"] and s["summary"] == "CPU 25% of 8 cores · memory 25% · 3 Liminal programs"
    assert (s["processor"], s["memory"], s["committed"]) == ("25% of 8 cores", "8.0 GB of 32.0 GB · 25%", "10.0 GB of 40.0 GB")
    assert (s["network"], s["adapters"], s["link"]) == ("2.0 KB/s in, 1.0 KB/s out", "Ethernet", "1.0 Gb/s")
    assert s["connections"] == "Liminal's 1 · the machine's 2 established, 1 listening"
    assert s["diskIo"] == "2.0 MB/s read, 1.0 MB/s written"  # the disks' I/O, hardware only
    assert s["dataFiles"] == "4.0 KB in 2 files" and s["dataFolder"] == str(tmp_path) and s["dataGrowth"] == "after a minute of samples"
    assert s["system"] in ("Windows", "Linux", sys.platform) and s["sampled"] == "every 2 s while shown, every 30 s otherwise"
    assert s["sampling"] is False  # not attached: nothing samples on its own
    programs, disks, io, folders = s["tables"]
    assert programs["title"] == "Liminal's programs" and [c["title"] for c in programs["columns"]][:3] == ["Program", "Processes", "CPU"]
    rows = {r[0]["text"] if isinstance(r[0], dict) else r[0]: r for r in programs["rows"]}
    assert set(rows) == {"Chart app · port 8765", "Integrator (daemon)", "Platform (this one)"}
    assert rows["Chart app · port 8765"][2] == "25%" and rows["Integrator (daemon)"][2] == "10%"
    assert rows["Chart app · port 8765"][3] == {"text": "500 MB", "sub": "400 MB private"} and rows["Chart app · port 8765"][5] == {"text": "1", "sub": "1 listening"}
    assert disks["title"] == "Disks" and disks["rows"] and folders["title"] == "Data folders"
    assert io["title"] == "Disk I/O" and io["rows"] == [["C:", "2.0 MB/s", "1.0 MB/s", "10.0 GB", "2.0 GB"]]
    assert [r[0] for r in folders["rows"]] == ["charts/", "login/"] and folders["rows"][0][4] == {"text": "charts/liminal.db", "sub": "3.0 KB"}
    c = s["charts"]
    assert c["span"] == "recent" and len(c["t"]) == 2 and [x["key"] for x in c["charts"]] == ["cpu", "memory", "network", "disk", "programs"]
    cpu, memory, network, disk, per = c["charts"]
    assert [(ln["name"], ln["values"]) for ln in disk["lines"]] == [("read", [None, 2.0 * MB]), ("written", [None, 1.0 * MB])] and disk["unit"] == "bytes/s"
    assert cpu["unit"] == "share" and cpu["max"] == 1.0 and cpu["lines"][0]["values"] == [None, 0.25]
    assert memory["max"] == 32 * GB and memory["lines"][0]["values"] == [8 * GB, 8 * GB]
    assert [(ln["key"], ln["values"]) for ln in network["lines"]] == [("in", [None, 2048.0]), ("out", [None, 1024.0])]
    assert [(ln["key"], ln["name"]) for ln in per["lines"]] == [("gui", "Chart app · port 8765"), ("integrator", "Integrator (daemon)"), ("platform", "Platform")]
    assert per["lines"][0]["values"] == [None, 0.25] and per["of"] == "one core"
    json.dumps(s)  # the platform's answer as it is


def test_sampling_runs_only_while_attached(tmp_path):
    p, _ = stand_in(tmp_path)

    class App:
        NAME = "platform"
    interface = p.attach(App(), None)
    assert p.sampling and p.app is not None and {"present", "status", "view", "charts"} <= set(interface["hooks"])
    first = p.monitor
    p.detach()
    assert not p.sampling and p.app is None and p._monitor is None and first._stop.is_set()
    p.attach(App(), None)
    assert p.sampling and p.monitor is not first  # a fresh sampler: a stopped one never starts again
    p.detach()


def test_the_hooks_asked_by_name_and_a_machine_without_figures(tmp_path):
    p, later = stand_in(tmp_path)
    assert p.ask("charts", "day")["span"] == "day" and p.ask("view")["span"] == "recent" and p.ask("present") is True
    with pytest.raises(LookupError):
        p.ask("setup_everything")

    class OwnOnly(FakeProbe):  # a system whose figures are not read (resources.OwnProbe): this process only
        def machine(self):
            return None

        def network(self):
            return None

        def connections(self):
            return []
    bare = HwStatsPlugin(probe=OwnOnly(), data=tmp_path)
    s = bare.status()
    assert "processor" not in s and "network" not in s and s["summary"].endswith(f"the machine's figures are not read on {sys.platform}")
    assert [x["key"] for x in s["charts"]["charts"]] == []  # one sample, no rates yet: nothing to chart


def test_the_command_line(tmp_path, monkeypatch, capsys):
    p, later = stand_in(tmp_path)
    monkeypatch.setattr(cli, "MACHINE", p)
    assert cli.main(["status"], pause=lambda s: later(s)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"].startswith("CPU 25% of 8 cores") and out["tables"][0]["title"] == "Liminal's programs"
    assert cli.main(["charts", "day"], pause=lambda s: later(s)) == 0 and json.loads(capsys.readouterr().out)["span"] == "day"
    assert cli.main(["view"], pause=lambda s: later(s)) == 0 and "machine" in json.loads(capsys.readouterr().out)
    assert cli.main(["week"]) == 2 and cli.main(["view", "week"]) == 2
    assert capsys.readouterr().err.count("python -m plugin_platform_hw_stats status | view") == 2


def test_this_machines_own_figures(tmp_path):
    """The real probe of the system the tests run on (Windows or Linux): read, never written."""
    p = HwStatsPlugin(data=tmp_path)
    p.monitor.sample()
    time.sleep(0.3)
    p.monitor.sample()  # the second: the rates
    s = p.status()
    assert s["present"] and s["tables"][0]["title"] == "Liminal's programs" and "Platform (this one)" in json.dumps(s["tables"][0])
    if sys.platform == "win32" or os.path.isdir("/proc"):
        assert s["system"] in ("Windows", "Linux") and "processor" in s and "memory" in s
        assert s["summary"].startswith("CPU ") and "of" in s["processor"]
        assert [x["key"] for x in s["charts"]["charts"]][:2] == ["cpu", "memory"]
