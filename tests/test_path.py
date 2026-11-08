"""A port's way in, hop by hop (check_path): this computer, the router, the internet, over a stand-in network that
plays each case seen or expected: the traffic arriving and dropped (as this PC showed on 2026-11-08: portchecker.io's
two SYNs seen arriving, unanswered), accepted, refused, nothing arriving behind a private hop, the ISP's NAT given by
UPnP, no capture, no service able to check. Nothing listens, captures or connects for real."""
from __future__ import annotations

import inspect
import os
import time

import pytest

import plugin_platform_hw_stats as hw
import plugin_platform_hw_stats.__main__ as cli
from liminal_libs import netpath
from liminal_libs.capture import CaptureError, Packet
from liminal_libs.ports import Arrival, Outcome
from liminal_libs.resources import Conn, Machine, Net, Proc
from plugin_platform_hw_stats import HwStatsPlugin, PathRun, judge

HOME, LAN, GATEWAY, PROBER = "93.184.216.34", "192.168.50.228", "192.168.50.1", "68.183.43.132"


class Probe:
    """The machine with the charts app listening on 8765, this machine only."""

    def processes(self):
        return [Proc(4242, 1, "pythonw.exe -m liminal_charts gui --no-browser --port 8765", 1_800_000_000.0, 10.0, 1, 1, 0, 0, 2, 2),
                Proc(os.getpid(), 1, "python -m pytest", 1_800_000_200.0, 1.0, 1, 1, 0, 0, 1, 1)]

    def machine(self):
        return Machine(8, 100.0, 1000.0, 8 * 2**30, 4 * 2**30, 8 * 2**30, 4 * 2**30)

    def network(self):
        return Net(1, 1, 0, ("Ethernet",))

    def disks(self):
        return []

    def connections(self):
        return [Conn(4242, "listening", "127.0.0.1:8765", "")]


class Seen:
    """A capture as a stand-in: the packets the stand-in network puts in it."""

    def __init__(self):
        self.packets = []

    def stop(self):
        return list(self.packets)


class Ear:
    """A listener as a stand-in."""

    def __init__(self):
        self.arrivals = []

    def stop(self):
        return list(self.arrivals)


class World:
    """The path check's network as a stand-in. `arrives`: what the check from the internet does (accepted: a SYN and
    this computer's SYN ACK; dropped: two SYNs unanswered; refused: a SYN and an RST; none); `loops`: the router turns a
    connection to the public address back here; `wan`: the router's UPnP answer; `hop2`: the hop after the router."""

    def __init__(self, arrives="dropped", loops=True, wan=None, hop2="172.29.152.1", capture=True, probe="blocked", listen=True):
        self.arrives, self.loops, self.wan_address, self.hop2 = arrives, loops, wan, hop2
        self.can_capture, self.probe_state, self.can_listen = capture, probe, listen
        self.seen, self.ear, self.t = Seen(), None, [1_800_020_000.0]

    def tick(self):
        self.t[0] += 0.1
        return self.t[0]

    def route(self):
        return netpath.Route(LAN, GATEWAY, "11")

    def ping(self, host):
        return 3.0

    def hops(self):
        return [GATEWAY, self.hop2, "159.111.243.68"]

    def wan(self, local):
        return self.wan_address

    def capture(self, address, ports):
        if not self.can_capture:
            raise CaptureError("Npcap is not installed (npcap.com; Wireshark installs it): packets cannot be watched")
        return self.seen

    def listener(self, port):
        if not self.can_listen:
            raise OSError(10013, "An attempt was made to access a socket in a way forbidden by its access permissions")
        self.ear = Ear()
        return self.ear

    def connect(self, host, port, timeout):
        if host == LAN:
            if self.ear is None:
                raise TimeoutError("timed out")  # Windows drops what nothing answers
            self.ear.arrivals.append(Arrival(LAN, 50000, self.tick()))
            return
        if host == HOME:
            self.seen.packets.append(Packet(self.tick(), LAN, 50001, HOME, port, "SYN"))
            if self.loops:
                self.seen.packets.append(Packet(self.tick(), GATEWAY, 50002, LAN, port, "SYN"))
                if self.ear is not None:
                    self.ear.arrivals.append(Arrival(GATEWAY, 50002, self.tick()))
                    return
            raise TimeoutError("timed out")
        raise AssertionError(f"connected to {host}")

    def probe(self, address, port):
        assert address == HOME
        if self.probe_state == "failed":
            return Outcome("failed", "failed: no service could check it from the internet: portchecker.io (HTTP 503)", self.tick()), ""
        if self.arrives in ("accepted", "dropped", "refused"):
            self.seen.packets.append(Packet(self.tick(), PROBER, 40001, LAN, port, "SYN"))
        if self.arrives == "accepted":
            self.seen.packets.append(Packet(self.tick(), LAN, port, PROBER, 40001, "SYN ACK"))
            return Outcome("open", "open: portchecker.io connected", self.tick()), "portchecker.io"
        if self.arrives == "dropped":
            self.seen.packets.append(Packet(self.tick(), PROBER, 40001, LAN, port, "SYN"))
        if self.arrives == "refused":
            self.seen.packets.append(Packet(self.tick(), LAN, port, PROBER, 40001, "ACK RST"))
        return Outcome("blocked", "blocked: portchecker.io could not connect within a second (refused, or no answer)", self.tick()), "portchecker.io"


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(hw, "SETTLE_S", 0.0)
    monkeypatch.setattr(hw, "LATE_S", 0.0)


def plugin(tmp_path, world: World) -> HwStatsPlugin:
    return HwStatsPlugin(probe=Probe(), data=tmp_path, net=world, connect=world.connect,
                         resolve=lambda v: (HOME, "OpenDNS") if v == 4 else (None, "none"),
                         clock=lambda: 100.0, wall=world.tick, cpu_clock=lambda: 0.0)


def run_path(p: HwStatsPlugin, port, listen="yes") -> PathRun:
    said = p.ask("check_path", port, listen)
    assert said["said"].startswith(f"checking the way in to port {port}")
    for _ in range(500):
        if not p._rt.path.running:
            break
        time.sleep(0.01)
    return p._rt.path


def test_traffic_from_the_internet_seen_arriving_and_dropped_as_this_pc_showed(tmp_path):
    w = World(arrives="dropped")
    run = run_path(plugin(tmp_path, w), 8795)
    assert run.listening == "ours" and run.lan_try.state == "open" and run.came_back and run.gateway_ms == 3.0
    assert [pk.src for pk in run.from_outside] == [PROBER, PROBER] and run.answer == ""
    assert run.states == {"computer": "fail", "router": "ok", "internet": "warn", "internet-router": "ok", "router-computer": "ok"}
    assert run.said.startswith("Traffic from the internet reaches this computer on port 8795 (through the router), but nothing answers it")
    assert "before it reaches the check's own listener" in run.said
    assert any("the router turned it back to this computer, which accepted it" in line for line in run.lines)
    assert any(line.startswith(f"seen arriving from the internet: 2 connection request(s) from {PROBER}") for line in run.lines)
    assert any("172.29.152.1 (private)" in line for line in run.lines)
    unlistened = run_path(plugin(tmp_path, World(arrives="dropped")), 8795, "no")
    assert unlistened.listening == "" and unlistened.states["computer"] == "warn" and "nothing listens on it, and Windows drops" in unlistened.said
    assert any("a connection to 192.168.50.228:8795, this computer's address on its network: did not answer" in line for line in unlistened.lines)


def test_reachable_refused_and_nothing_arriving(tmp_path):
    ok = run_path(plugin(tmp_path, World(arrives="accepted")), 8795)
    assert set(ok.states.values()) == {"ok"} and ok.said.startswith(f"Port 8795 is reachable from the internet: portchecker.io connected to {HOME}:8795")
    refused = run_path(plugin(tmp_path, World(arrives="refused")), 8795)
    assert refused.answer == "refused" and "nothing accepts it: the connection is refused" in refused.said
    behind = run_path(plugin(tmp_path, World(arrives="none", loops=False)), 8795)
    assert behind.states["internet"] == "fail" and behind.states["internet-router"] == "warn" and behind.states["router"] == "warn"
    assert "After your router comes 172.29.152.1, a private address: if the router's own WAN address" in behind.said
    assert any("it did not come back to this computer" in line for line in behind.lines)
    public_hop = run_path(plugin(tmp_path, World(arrives="none", hop2="159.111.243.1")), 8795)
    assert public_hop.states["router-computer"] == "fail" and "the router does not forward it here" in public_hop.said


def test_the_isps_nat_given_by_upnp_no_capture_and_no_service(tmp_path):
    cgnat = run_path(plugin(tmp_path, World(arrives="none", wan="100.64.12.34")), 8795)
    assert cgnat.states["router"] == "fail" and cgnat.states["internet-router"] == "fail"
    assert "Your router's WAN address is 100.64.12.34, a shared one: your ISP's NAT (CGNAT)" in cgnat.said
    blind = run_path(plugin(tmp_path, World(capture=False)), 8795)
    assert blind.capture_why.startswith("Npcap is not installed") and "packets were not watched (Npcap is not installed" in blind.said
    nobody = run_path(plugin(tmp_path, World(probe="failed")), 8795)
    assert nobody.states["internet"] == "unknown" and nobody.said.startswith("Port 8795 could not be checked from the internet")
    taken = run_path(plugin(tmp_path, World(listen=False)), 8795)
    assert taken.listening == "" and any("could not listen on it (An attempt was made" in line for line in taken.lines)


def test_a_port_that_listens_on_this_machine_only_is_said_so(tmp_path):
    run = run_path(plugin(tmp_path, World(arrives="none")), 8765)  # the charts app's page: 127.0.0.1 only
    assert run.listening == "theirs" and run.local_only and run.states["computer"] == "warn"
    assert any("this computer: Chart app · port 8765 (pid 4242), this machine only" in line for line in run.lines)


def test_the_page_draws_each_hop_as_it_goes_and_the_traffic_seen(tmp_path):
    w = World()
    p = plugin(tmp_path, w)
    p._rt.path = PathRun(8795, True, 1_800_020_000.0, stage="router", lan=LAN, gateway=GATEWAY, public=HOME, listening="ours")
    view = p.status()["paths"][0]
    assert view["running"] and [n["state"] for n in view["nodes"]] == ["idle", "checking", "done"]
    assert [lk["state"] for lk in view["links"]] == ["idle", "checking"] and view["said"] == "checking the router…"
    assert view["nodes"][2]["sub"] == f"{LAN}:8795 · the check listens on it"
    p._rt.path = None
    run = run_path(p, 8795)
    s = p.status()
    [view] = s["paths"]
    assert not view["running"] and [n["state"] for n in view["nodes"]] == ["warn", "ok", "fail"] and view["said"] == run.said
    assert view["nodes"][1]["sub"] == f"{GATEWAY} · ping 3 ms · next 172.29.152.1 (private)" and view["nodes"][0]["sub"] == f"{HOME} · portchecker.io"
    traffic = [t for t in s["tables"] if t["title"] == "Traffic on port 8795"][0]
    assert [r[4] for r in traffic["rows"]] == ["out to the public address", "back through the router", "from the internet", "from the internet"]
    assert traffic["rows"][2][1] == f"{PROBER}:40001" and traffic["rows"][2][3] == "SYN"
    with pytest.raises(ValueError, match="one port at a time"):
        p.ask("check_path", "80 443")
    p._rt.path.running = True
    with pytest.raises(ValueError, match="the way in to port 8795 is being checked"):
        p.ask("check_path", 80)
    p._rt.path.running = False
    form = [f for f in s["forms"] if f["id"] == "path"][0]
    assert [f["name"] for f in form["fields"]] == list(inspect.signature(p.check_path).parameters) == ["port", "listen"]
    assert "Windows may ask whether Python may accept connections" in form["confirm"]["words"]
    blind = plugin(tmp_path, World(capture=False))
    run_path(blind, 8795)
    empty = [t for t in blind.status()["tables"] if t["title"] == "Traffic on port 8795"][0]
    assert empty["rows"] == [] and empty["empty"].startswith("Not watched: Npcap is not installed")


def test_the_command_line_checks_the_way_in(tmp_path, monkeypatch, capsys):
    p = plugin(tmp_path, World())
    monkeypatch.setattr(cli, "MACHINE", p)
    assert cli.main(["path", "8795", "--no-listen"], pause=lambda s: time.sleep(0.01)) == 1
    out = capsys.readouterr().out
    assert "nothing listens on 8795 (the check does not listen on it)" in out and "from the internet" in out
    assert out.strip().splitlines()[-1].startswith("Traffic from the internet reaches this computer on port 8795")
    assert cli.main(["path"]) == 2 and cli.main(["path", "1 2"]) == 2


def test_judge_alone():
    run = PathRun(25, False, 0.0, lan=LAN, gateway=GATEWAY, public=HOME, hops=[GATEWAY, "159.111.243.1", "159.111.243.68"],
                  probe=Outcome("blocked", "blocked: x"), prober="portchecker.io")
    states, said = judge(run)
    assert states["router-computer"] == "fail" and "the router does not forward it here" in said
