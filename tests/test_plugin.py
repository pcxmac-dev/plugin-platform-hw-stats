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
from liminal_libs.apps import EnvironmentLogin
from liminal_libs.ports import Outcome
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


HOME = "93.184.216.34"


def resolved(version):
    """This network's public address as a stand-in for the name servers: an IPv4 address, no IPv6 route."""
    return (HOME, "OpenDNS") if version == 4 else (None, "neither OpenDNS nor Google answered with a public IPv6 address")


class Checker:
    """check-host.net's check as a stand-in: each port's state as given (blocked otherwise); what was asked kept."""

    def __init__(self, states):
        self.states, self.asked = states, []

    def check(self, address, ports):
        self.asked.append((address, tuple(ports)))
        return {p: Outcome(self.states.get(p, "blocked"), f"{self.states.get(p, 'blocked')}: as the stand-in says", 1_800_000_500.0)
                for p in ports}


def stand_in(tmp_path, resolve=resolved, **services):
    (tmp_path / "charts").mkdir(parents=True, exist_ok=True)
    (tmp_path / "charts" / "liminal.db").write_bytes(b"x" * 3072)
    (tmp_path / "login").mkdir(exist_ok=True)
    (tmp_path / "login" / "users.db").write_bytes(b"x" * 1024)
    probe, t = FakeProbe(), [100.0]
    plugin = HwStatsPlugin(probe=probe, data=tmp_path, resolve=resolve, clock=lambda: t[0], wall=lambda: 1_800_010_000.0 + t[0],
                           cpu_clock=lambda: 0.0, **services)

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
    keys = list(s)
    assert keys[keys.index("network"):keys.index("network") + 6] == ["network", "adapters", "link", "publicAddress", "publicIpv6", "ports"]
    assert s["publicAddress"] == "not read yet (it is read while the plugin is attached to the platform)"
    assert s["ports"] == ("8765 (Liminal's charts), 8775 (Liminal's platform), 8785 (Liminal's integrator), 8795 (Liminal's login), "
                          "8796 (the integrator's login) (Liminal's own: HW_STATS_PORTS is not set)") and "problem" not in s
    programs, ports, disks, folders = s["tables"]  # the disks' space and I/O in one table (the user: "disk io is redundant")
    assert ports["title"] == "Ports" and [c["title"] for c in ports["columns"]] == ["Port", "Here", "From the internet", "Out from this machine",
                                                                                     "Hop by hop"]
    assert ports["rows"][0] == [{"text": "8765", "sub": "Liminal's charts"},
                                {"text": "listening", "sub": "Chart app · port 8765 (pid 4242), this machine only"},
                                {"text": "–", "sub": "not checked"}, {"text": "–", "sub": "not checked"},
                                {"form": "path", "title": "Way in", "values": {"port": 8765}, "label": "Check the way in to port 8765"}]
    assert ports["rows"][1][1] == {"text": "free", "sub": "nothing listens on it here"} and len(ports["rows"]) == 5
    assert ports["rows"][4][0] == {"text": "8796", "sub": "the integrator's login"}
    assert ports["actions"] == [{"hook": "refresh_ports", "args": [], "title": "Refresh", "note": "reads what listens on each port now; nothing is sent anywhere"},
                                {"form": "choose", "title": "Other ports…", "values": {"ports": "8765 8775 8785 8795 8796"}},
                                {"form": "ports", "title": "Check ports…", "values": {"ports": "8765 8775 8785 8795 8796"}},
                                {"form": "path", "title": "Check the way in…"}]
    form, choose, path = s["forms"]
    assert form["id"] == "ports" and form["hook"] == "check_ports" and form["fields"][0]["value"] == "8765 8775 8785 8795 8796"
    assert choose["id"] == "choose" and choose["hook"] == "choose_ports" and choose["confirm"] is False
    assert path["id"] == "path" and path["fields"][0]["value"] == 8775 and s["paths"] == []  # the first port nothing listens on
    assert s["actions"] == [{"hook": "public_address", "args": [], "title": "Read the public address again",
                             "note": "asks OpenDNS (else Google's name server) for this network's address now"}]
    assert programs["title"] == "Liminal's programs" and [c["title"] for c in programs["columns"]][:3] == ["Program", "Processes", "CPU"]
    rows = {r[0]["text"] if isinstance(r[0], dict) else r[0]: r for r in programs["rows"]}
    assert set(rows) == {"Chart app · port 8765", "Integrator (daemon)", "Platform (this one)"}
    assert rows["Chart app · port 8765"][2] == "25%" and rows["Integrator (daemon)"][2] == "10%"
    assert rows["Chart app · port 8765"][3] == {"text": "500 MB", "sub": "400 MB private"} and rows["Chart app · port 8765"][5] == {"text": "1", "sub": "1 listening"}
    assert disks["title"] == "Disks" and folders["title"] == "Data folders"
    assert [c["title"] for c in disks["columns"]] == ["Disk", "Holds", "Used", "Free", "Total", "Read", "Written"]
    [c_drive] = [r for r in disks["rows"] if r[5] != "–"]  # C:'s reads and writes, beside its space on Windows
    assert c_drive[5:] == [{"text": "2.0 MB/s", "sub": "10.0 GB since start"}, {"text": "1.0 MB/s", "sub": "2.0 GB since start"}]
    if sys.platform == "win32":
        assert c_drive[0] == "C:\\" and "data" in c_drive[1] and len(disks["rows"]) == 1
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
    assert p.sampling and p.app is not None and {"present", "status", "view", "charts", "public_address", "check_ports"} <= set(interface["hooks"])
    first = p.monitor
    p.detach()
    assert not p.sampling and p.app is None and p._monitor is None and first._stop.is_set() and not p.watching
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


def wait_until(test, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if test():
            return True
        time.sleep(0.02)
    return test()


class App:
    NAME = "platform"


def test_the_ports_chosen_are_read_through_the_login(tmp_path):
    p, _ = stand_in(tmp_path)
    assert [k.name for k in p.keys] == ["HW_STATS_PORTS"] and p.keys[0].pair == "hw-stats-ports" and not p.keys[0].secret
    p.login = EnvironmentLogin(env={"HW_STATS_PORTS": "443, 25 8765"})  # the platform's login (the login app's database later)
    assert p.selected() == hw.Chosen((25, 443, 8765), "setting", None)
    s = p.status()
    assert s["ports"] == "25, 443, 8765 (Liminal's charts) (HW_STATS_PORTS)"
    assert [r[0] if isinstance(r[0], str) else r[0]["text"] for r in s["tables"][1]["rows"]] == ["25", "443", "8765"]
    group = s["tables"][1]["options"][0]
    assert group["value"] == "setting" and group["choices"][-1] == {"value": "setting", "title": "HW_STATS_PORTS", "note": "25 443 8765"}
    p.login = EnvironmentLogin(env={"HW_STATS_PORTS": "25, mail"})
    assert p.selected() == hw.Chosen((8765, 8775, 8785, 8795, 8796), "liminal",
                                     "HW_STATS_PORTS: not a port: 'mail' (a number, or a range as 8765-8768); Liminal's own ports are listed instead")
    assert p.status()["problem"].startswith("HW_STATS_PORTS: not a port")

    class Unanswering(EnvironmentLogin):
        def variables(self, wanted):
            raise ConnectionError("the login app is not answering")
    p.login = Unanswering()
    assert p.selected().problem == "HW_STATS_PORTS could not be read from the login (ConnectionError); Liminal's own ports are listed instead"


def test_the_public_address_is_read_while_attached_and_when_asked(tmp_path):
    asked = []

    def resolve(version):
        asked.append(version)
        return resolved(version)
    p, _ = stand_in(tmp_path, resolve=resolve)
    assert p.status()["publicAddress"].startswith("not read yet") and asked == []  # nothing asked while not attached
    p.attach(App(), None)
    try:
        assert wait_until(lambda: p.status()["publicAddress"].startswith(HOME)) and p.watching
        s = p.status()
        assert s["publicAddress"].startswith(f"{HOME} · OpenDNS, ") and asked[:2] == [4, 6]
        assert s["publicIpv6"] == "none · neither OpenDNS nor Google answered with a public IPv6 address"
        assert p.ask("public_address") == {
            "said": f"this network's public address is {HOME}", "ok": True, "ipv4": HOME, "ipv6": None,
            "lines": [f"IPv4: {HOME} (OpenDNS)", "IPv6: none (neither OpenDNS nor Google answered with a public IPv6 address)"]}
        assert p.status()["forms"][0]["fields"][2]["value"] == HOME  # the form shows the address it will check
    finally:
        p.detach()
    assert not p.watching

    def failing(version):
        raise OSError("no nslookup here")
    q, _ = stand_in(tmp_path / "q", resolve=failing)
    a = q.ask("public_address")
    assert a["ok"] is False and a["said"] == "no public IPv4 address was found (the lookup failed (OSError))"


def test_ports_checked_from_the_internet_and_out_kept_for_the_table(tmp_path):
    checker, tried = Checker({8765: "open", 443: "closed"}), []

    def connect(host, port, timeout):
        tried.append((host, port))
        if port == 25:
            raise TimeoutError("timed out")
    p, _ = stand_in(tmp_path, checker=checker, connect=connect)
    rep = p.ask("check_ports", "8765 443 25", "both", HOME)
    assert checker.asked == [(HOME, (25, 443, 8765))]  # this network's own address, the ports asked
    assert tried[0] == ("portquiz.net", 80) and sorted(tried[1:]) == [("portquiz.net", 25), ("portquiz.net", 443), ("portquiz.net", 8765)]
    assert rep["said"] == f"3 ports checked from the internet at {HOME}: 1 open, 1 closed, 1 blocked; out from this machine: 2 open, 1 blocked"
    assert rep["lines"][0] == ("25 · from the internet: blocked, as the stand-in says · out: blocked, no answer from portquiz.net in 5 s "
                               "(dropped on the way out: a firewall or the ISP) · here: free, nothing listens on it here")
    assert rep["lines"][2].startswith("8765 (Liminal's charts) · from the internet: open") and rep["lines"][2].endswith(
        "here: listening, Chart app · port 8765 (pid 4242), this machine only")
    assert rep["ok"] is False and rep["lines"][-1].startswith("Liminal's charts page answers from the internet on 8765")
    assert rep["ports"]["8765"]["in"]["state"] == "open" and rep["ports"]["8765"]["here"]["state"] == "listening"
    s = p.status()
    rows = {r[0] if isinstance(r[0], str) else r[0]["text"]: r for r in s["tables"][1]["rows"]}
    assert list(rows) == ["25", "443", "8765", "8775", "8785", "8795", "8796"]  # the ports chosen and the ports checked
    assert rows["443"][2]["text"] == "closed" and rows["25"][3]["text"] == "blocked" and rows["8775"][2] == {"text": "–", "sub": "not checked"}
    assert rows["443"][2]["sub"].startswith("as the stand-in says · ")  # when it was checked
    assert s["problem"] == "Liminal's charts page answers from the internet on port 8765: Liminal's pages are for this machine only"
    out = p.ask("check_ports", None, "out")  # the ports chosen, out only
    assert out["said"] == "5 ports checked out from this machine: 5 open" and out["ok"] is True and len(checker.asked) == 1
    json.dumps(s)


def test_a_check_refused_or_failed_says_why_and_asks_nothing(tmp_path):
    import inspect

    checker = Checker({})
    p, _ = stand_in(tmp_path, checker=checker)
    [form] = [f for f in p.status()["forms"] if f["id"] == "ports"]
    assert [f["name"] for f in form["fields"]] == list(inspect.signature(p.check_ports).parameters) == ["ports", "where", "address"]
    assert [c["value"] for c in form["fields"][1]["choices"]] == ["internet", "out", "both"] and form["fields"][1]["value"] == "internet"
    assert form["fields"][2]["type"] == "fixed" and form["fields"][2]["when"] == {"where": ["internet", "both"]}
    assert "check-host.net is given this network's public address and these ports" in form["confirm"]["words"]
    with pytest.raises(ValueError, match="from the internet, out or both, not 'sideways'"):
        p.ask("check_ports", "80", "sideways")
    with pytest.raises(ValueError, match="not a port"):
        p.ask("check_ports", "http", "internet")
    with pytest.raises(ValueError, match=f"this network's public address is {HOME} now, not 203.0.113.9: check again"):
        p.ask("check_ports", "80", "internet", "203.0.113.9")
    nowhere, _ = stand_in(tmp_path / "b", resolve=lambda v: (None, f"neither OpenDNS nor Google answered with a public IPv{v} address"),
                          checker=checker)
    with pytest.raises(RuntimeError, match=r"could not be read \(neither OpenDNS .*nothing was asked of check-host.net"):
        nowhere.ask("check_ports", "80")
    assert checker.asked == []  # nothing asked of check-host.net


def test_the_command_line_reads_the_address_and_the_ports(tmp_path, monkeypatch, capsys):
    p, _ = stand_in(tmp_path, checker=Checker({443: "open", 8765: "open"}), connect=lambda host, port, timeout: None)
    monkeypatch.setattr(cli, "MACHINE", p)
    assert cli.main(["ip"]) == 0
    assert capsys.readouterr().out.splitlines() == [f"this network's public address is {HOME}", f"  IPv4: {HOME} (OpenDNS)",
                                                    "  IPv6: none (neither OpenDNS nor Google answered with a public IPv6 address)"]
    assert cli.main(["ports", "8765", "443"]) == 0  # here only: nothing sent
    assert capsys.readouterr().out.splitlines() == ["443: free: nothing listens on it here",
                                                    "8765: listening: Chart app · port 8765 (pid 4242), this machine only"]
    assert cli.main(["ports", "443", "--where", "internet"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == f"1 port checked from the internet at {HOME}: 1 open" and out[1].startswith("  443 · from the internet: open")
    assert cli.main(["ports", "--where", "out"]) == 0 and "5 ports checked out from this machine: 5 open" in capsys.readouterr().out
    assert cli.main(["ports", "8765", "--where", "internet"]) == 1  # Liminal's own page open from the internet: not all right
    assert "8765" in capsys.readouterr().out
    assert cli.main(["ports", "--where", "sideways"]) == 2 and cli.main(["ports", "mail"]) == 2 and cli.main(["ip", "now"]) == 2
    err = capsys.readouterr().err
    assert "refused: not a port: 'mail'" in err and err.count("python -m plugin_platform_hw_stats status | view") == 2


def test_one_disks_table_holds_each_disks_space_and_its_reads_and_writes():
    space = [{"path": "C:\\", "holds": ["data", "app", "system"], "used": 2048, "free": 8192, "total": 10240},
             {"path": "/srv", "holds": ["data"], "used": 1, "free": 1, "total": 2}]
    io = [{"name": "nvme0n1", "read": 2048.0, "write": 1024.0, "readTotal": 8192, "writtenTotal": 4096},
          {"name": "c:", "read": 1024.0, "write": None, "readTotal": 4096, "writtenTotal": 0},
          {"name": "D:", "read": 0.0, "write": 0.0, "readTotal": 1, "writtenTotal": 2}]
    t = hw.disks_table(space, io, devices=lambda path: {"nvme0n1p2", "nvme0n1"} if path == "/srv" else set())  # Linux: the mount's device
    rows = {r[0]: r for r in t["rows"]}
    assert list(rows) == ["C:\\", "/srv", "D:"]  # a disk with only its reads and writes in a row of its own
    assert rows["C:\\"][2:] == [{"text": "2.0 KB", "sub": "20%"}, "8.0 KB", "10.0 KB", {"text": "1.0 KB/s", "sub": "4.0 KB since start"},
                                {"text": "–", "sub": "0 B since start"}]
    assert rows["/srv"][5] == {"text": "2.0 KB/s", "sub": "8.0 KB since start"} and rows["D:"][1:5] == ["–", "–", "–", "–"]
    assert hw.disks_table(space[:1], [])["rows"][0][5:] == ["–", "–"] and hw.disks_table([], []) is None
    assert hw.drive("c:\\") == "C:" and hw.drive("sda") == "sda"
    if sys.platform.startswith("linux"):  # the root's partition and its disk, as /sys/dev/block names them (CI's Ubuntu)
        assert isinstance(hw.devices_of("/"), set) and hw.devices_of("/no/such/path") == set()
    else:
        assert hw.devices_of("C:\\") == set()  # a drive's letter matches on Windows


def test_the_ports_listed_are_chosen_on_the_page_and_read_again_on_refresh(tmp_path):
    p, _ = stand_in(tmp_path)
    ports = p.status()["tables"][1]
    [group] = ports["options"]
    assert group["title"] == "Ports listed" and group["hook"] == "choose_ports" and group["value"] == "liminal"
    assert [c["value"] for c in group["choices"]] == ["liminal", "web", "mail", "remote"]  # no setting, nothing typed yet
    assert group["choices"][2] == {"value": "mail", "title": "Mail", "note": "25 465 587 993"}
    a = p.ask("choose_ports", "web")
    assert a["said"] == "listing 80, 443" and a["lines"][-1] == f"kept {hw.KEPT}" and p.selected() == hw.Chosen((80, 443), "web")
    s = p.status()
    assert [r[0] if isinstance(r[0], str) else r[0]["text"] for r in s["tables"][1]["rows"]] == ["80", "443"]
    assert s["ports"] == f"80, 443 (Web: chosen on the page, {hw.KEPT})" and s["tables"][1]["options"][0]["value"] == "web"
    assert s["forms"][1]["fields"][0]["value"] == "80 443" and s["tables"][1]["actions"][2]["values"] == {"ports": "80 443"}
    assert p.ask("choose_ports", "25, 8765")["said"] == "listing 25, 8765 (Liminal's charts)"
    assert p.selected() == hw.Chosen((25, 8765), "chosen")
    assert p.status()["tables"][1]["options"][0]["choices"][-1] == {"value": "chosen", "title": "Typed", "note": "25 8765"}
    p.ask("choose_ports", "liminal")
    assert p.ask("choose_ports", "chosen")["said"] == "listing 25, 8765 (Liminal's charts)"  # the ports typed, chosen again
    with pytest.raises(ValueError, match="not a port"):
        p.ask("choose_ports", "smtp")
    with pytest.raises(ValueError, match="HW_STATS_PORTS is not set to ports"):
        p.ask("choose_ports", "setting")
    r = p.ask("refresh_ports")
    assert r["said"] == "read what listens on 2 ports now: 1 listening, 1 free" and r["lines"][1].startswith("8765: listening: Chart app")
    p.login = EnvironmentLogin(env={"HW_STATS_PORTS": "443"})
    assert p.selected().ports == (25, 8765)  # the page's choice stands over the setting while the platform runs
    p.ask("choose_ports", "setting")
    assert p.selected() == hw.Chosen((443,), "setting") and p.status()["ports"] == f"443 (HW_STATS_PORTS: chosen on the page, {hw.KEPT})"


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
