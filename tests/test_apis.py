"""What the hardware stats attach to (plugin API 2.2): their cards are sound; they name every Win32 function, /proc and
/sys file and pcap function the library's code calls for the plugin, the system's commands it runs, the name servers'
questions, the services' endpoints it asks (through the plugin's own stand-ins) and portquiz.net's ports; the facts are
what the plugin kept, asked without a request; and the cards' pages answer (LIMINAL_VENDOR_PAGES=1 only, the one test
that reaches the network)."""
from __future__ import annotations

import inspect
import os
import re
import time
import types

import pytest

import plugin_platform_hw_stats as hw
from liminal_libs import capture, dns, netpath, ports, resources
from liminal_libs.sources.apis import dead_links, problems
from plugin_platform_hw_stats import MACHINE, HwStatsPlugin
from plugin_platform_hw_stats import apis as cards
from plugin_platform_hw_stats import network
from test_network import OPEN, FakeCheckHost
from test_path import HOME, Probe, World

LINUX_FILES = {  # the Linux card's files -> how the library's probe (or netpath) names them
    "/proc/stat": '{self.proc}/stat"', "/proc/meminfo": '{self.proc}/meminfo"', "/proc/<pid>/stat": '{self.proc}/{pid}/stat"',
    "/proc/<pid>/status": '{self.proc}/{pid}/status"', "/proc/<pid>/io": '{self.proc}/{pid}/io"',
    "/proc/<pid>/cmdline": '{self.proc}/{pid}/cmdline"', "/proc/<pid>/fd": '{self.proc}/{pid}/fd"',
    "/proc/<pid>/comm": '{self.proc}/{pid}/comm"', "/proc/diskstats": '{self.proc}/diskstats"', "/sys/block": 'block: str = "/sys/block"',
    "/proc/net/dev": '{self.proc}/net/dev"', "/sys/class/net/<interface>/operstate, device, speed": '{self.net}/{n}/operstate"',
    "/proc/net/tcp and /proc/net/tcp6": '{self.proc}/net/{name}"', "/proc/net/route": '"/proc/net/route"', "statvfs": "disk_usage(",
}


def named(api) -> set[str]:
    return {c.name.split()[0] for c in api.used}


def test_the_cards_are_sound_and_each_says_where_its_documentation_is():
    assert problems(MACHINE.apis) == [] and MACHINE.apis == cards.APIS
    assert [a.name for a in MACHINE.apis] == [
        "Windows (kernel32, ntdll, iphlpapi)", "Linux (/proc and /sys)", "ping, tracert or traceroute, and nslookup",
        "OpenDNS (myip.opendns.com)", "Google's name servers (o-o.myaddr.l.google.com)", "portchecker.io", "check-host.net",
        "portquiz.net", "UPnP Internet Gateway Device", "Npcap and libpcap"]
    assert all(a.docs and a.verified == "2026-11-11" and a.used and a.covered for a in MACHINE.apis)
    assert all(len(a.areas) > len(a.covered) for a in MACHINE.apis)  # more of each API than the plugin uses
    assert not any(c.writes or c.costs for a in MACHINE.apis for c in a.used)  # it changes nothing anywhere, starts no charge
    assert cards.CAPTURE.link("pricing") == "https://npcap.com/oem/" and "five installs" in cards.CAPTURE.costs
    assert "http://portquiz.net" in cards.PORTQUIZ.about and not any("portquiz.net" in x.url for x in cards.PORTQUIZ.links)


def test_the_windows_card_names_every_win32_function_the_librarys_probe_calls():
    src = inspect.getsource(resources.WindowsProbe)
    called = (set(re.findall(r"self\.(?:k32|nt|ip)\.(\w+)", src)) | set(re.findall(r'\("(\w+)", k\)', src))
              | set(re.findall(r"\bk\.([A-Z]\w+)\(", src)))
    assert "GetBestRoute" in inspect.getsource(netpath._gateway_windows) and "disk_usage(" in inspect.getsource(hw.disks_table) + \
        inspect.getsource(resources)
    assert called <= named(cards.WINDOWS), sorted(called - named(cards.WINDOWS))
    assert named(cards.WINDOWS) - called == {"GetBestRoute", "GetDiskFreeSpaceExW"}  # netpath's route; Python's disk_usage


def test_the_linux_card_names_every_file_the_librarys_probe_reads():
    src = inspect.getsource(resources.LinuxProbe) + inspect.getsource(netpath._gateway_linux) + inspect.getsource(resources)
    assert {c.name for c in cards.LINUX.used} == set(LINUX_FILES)
    assert [f for f, snippet in LINUX_FILES.items() if snippet not in src] == []


def test_the_capture_card_names_every_pcap_function_the_library_calls():
    called = set(re.findall(r"lib\.(pcap_\w+)", inspect.getsource(capture)))
    assert called == named(cards.CAPTURE), sorted(called ^ named(cards.CAPTURE))
    assert r"System32\Npcap" in cards.CAPTURE.base and capture.NPCAP.endswith(os.path.join("System32", "Npcap"))


def test_the_tools_card_names_the_systems_commands_as_the_library_runs_them(monkeypatch):
    seen: list[list[str]] = []

    def run(args, timeout):
        seen.append(list(args))
        return None
    for platform in ("win32", "linux"):  # netpath as each system runs it (its own sys stood in for)
        monkeypatch.setattr(netpath, "sys", types.SimpleNamespace(platform=platform))
        netpath.ping("192.168.50.1", run=run)
        netpath.hops(network.TRACE_TO, 3, run=run)
    words = [" ".join(a) for a in seen]
    rx = {c.name: re.compile(re.sub(r"<[^>]+>", r"\\S+", re.escape(c.name).replace(r"\<", "<").replace(r"\>", ">"))) for c in cards.TOOLS.used}
    for name, pattern in rx.items():
        if name.startswith("nslookup"):
            continue
        assert any(pattern.fullmatch(w) for w in words), name
    assert '["nslookup", f"-type={rtype}", *([f"-timeout={wait}", "-retry=1"]' in inspect.getsource(dns)  # its query
    assert network.TRACE_TO == "1.1.1.1"


def test_the_name_servers_cards_name_the_questions_the_plugin_asks():
    for version, servers in network.PUBLIC_SERVERS.items():
        for name, rtype, server, whose in servers:
            card = cards.OPENDNS if whose == "OpenDNS" else cards.GOOGLE
            assert f"nslookup -type={rtype} {name} {server}" in {c.name for c in card.used}, (version, whose)


def test_the_services_cards_name_the_endpoints_the_plugin_asks():
    asked: list[str] = []

    def get(url):
        asked.append(url)
        return HOME if url.endswith("/api/me") else "True"
    assert network.PortChecker(get=get).check(HOME, [8795])[8795].state == "open"
    assert asked == [network.PORTCHECKER + "/api/me", network.PORTCHECKER + "/api/me/8795"]
    assert {c.name for c in cards.PORTCHECKER.used} == {"GET /api/me", "GET /api/me/<port>"}
    fake = FakeCheckHost({80: OPEN})
    network.CheckHost(get=fake.get, sleep=fake.sleep, clock=lambda: fake.t[0], wall=lambda: 9.0).check(HOME, "80")
    paths = [u.removeprefix(network.CHECK_HOST) for u in fake.asked]
    assert paths[0] == f"/check-tcp?host={HOME}%3A80&max_nodes=3" and set(paths[1:]) == {"/check-result/r80"}
    assert {c.name for c in cards.CHECK_HOST.used} == {"GET /check-tcp?host=<address>:<port>&max_nodes=3",
                                                       "GET /check-result/<request id>"}


def test_the_portquiz_and_upnp_cards_name_what_the_plugin_sends():
    assert network.OUT_HOST == "portquiz.net" and ports.CONTROL == 80
    assert {c.name for c in cards.PORTQUIZ.used} == {"TCP connect portquiz.net:80", "TCP connect portquiz.net:<port>"}
    src = inspect.getsource(network.router_wan)
    assert "M-SEARCH" in src and "urn:schemas-upnp-org:device:InternetGatewayDevice:1" in network.IGD and "GetExternalIPAddress" in src
    assert network.SSDP == ("239.255.255.250", 1900) and "239.255.255.250:1900" in cards.UPNP_IGD.base


def test_its_facts_are_what_it_kept_and_asking_them_sends_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(hw, "SETTLE_S", 0.0)
    monkeypatch.setattr(hw, "LATE_S", 0.0)
    assert HwStatsPlugin(data=tmp_path).api_facts() == {}
    world, asked, tried = World(arrives="dropped", wan="100.64.12.9"), [], []

    def resolve(version):
        asked.append(version)
        return (HOME, "OpenDNS") if version == 4 else (None, "neither OpenDNS nor Google answered with a public IPv6 address")

    def connect(host, port, timeout):
        tried.append((host, port))
        world.connect(host, port, timeout) if host != "portquiz.net" else None
    p = HwStatsPlugin(probe=Probe(), data=tmp_path, net=world, connect=connect, resolve=resolve,
                      checker=type("Checker", (), {"check": lambda self, a, ps: {x: ports.Outcome("blocked", "blocked", 9.0) for x in ps}})(),
                      clock=lambda: 100.0, wall=world.tick, cpu_clock=lambda: 0.0)
    p.public_address()
    p.check_ports("8795", "both")
    p.ask("check_path", 8795, "yes")
    for _ in range(500):
        if not p._rt.path.running:
            break
        time.sleep(0.01)
    before = (len(asked), len(tried), len(world.seen.packets))
    facts = p.api_facts()
    assert (len(asked), len(tried), len(world.seen.packets)) == before  # nothing asked, nothing connected
    assert facts["OpenDNS (myip.opendns.com)"]["IPv4"].startswith(f"{HOME}, ")
    assert facts["OpenDNS (myip.opendns.com)"]["IPv6"].startswith("none (neither OpenDNS nor Google")
    assert facts["check-host.net"]["Last check from the internet"].startswith("1 blocked")
    assert facts["portquiz.net"]["Last check out"].startswith("1 open")
    assert facts["portchecker.io"]["Last path check"].startswith("port 8795: blocked")
    assert facts["UPnP Internet Gateway Device"]["The router's WAN address"].startswith("100.64.12.9, ")
    assert facts["Npcap and libpcap"]["Last path check"].endswith("seen on port 8795")
    assert facts["ping, tracert or traceroute, and nslookup"]["Gateway"] == "192.168.50.1, 3 ms"


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="reaches the makers' pages: LIMINAL_VENDOR_PAGES=1")
def test_the_cards_pages_answer():
    assert dead_links(MACHINE.apis) == []
