"""Who may ask what reaches beyond this machine (0.5.2, the sweep after the review's PLT-H1, 2026-11-25). Four hooks are
asked only from the plugin's page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and liminal-platform 0.34.0
read them): public_address (the name servers asked now), check_ports (this network's public address and the ports sent
to check-host.net, connections made to portquiz.net), check_path (a port listened on at every address, its packets
watched, the router and a service on the internet asked) and choose_ports (the ports the page lists). Another plugin's
ask is refused, and so is an ask that names no one; over HTTP the platform also asks its login whether you are at the
page. Before, any program on this machine asked them with two headers, with none of the page's confirmations. Its reads
send nothing anywhere and are asked by anyone, as before. Asked through the library's own App (its ask names who asks
as the platform's does), over stand-ins for the probe, the name servers, check-host.net, a connection out and the path
check's network: nothing is sent, nothing listens."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is asked only from its page before liminal-libs 1.66.0")

import plugin_platform_hw_stats as hw  # noqa: E402 - after the skip, as each of these
from liminal_libs import internal  # noqa: E402
from liminal_libs.apps import App, asking  # noqa: E402
from liminal_libs.apps.authorization import EnvironmentLogin  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from plugin_platform_hw_stats import MACHINE, HwStatsPlugin  # noqa: E402
from plugin_platform_hw_stats.network import OUT_HOST  # noqa: E402
from test_path import HOME, Probe, World  # noqa: E402
from test_plugin import Checker, wait_until  # noqa: E402

OUTSIDE = ("public_address", "check_ports", "choose_ports", "check_path")
READS = ("present", "status", "view", "charts", "refresh_ports")
ASKS = {"public_address": (), "check_ports": ("8765 443", "both", HOME), "choose_ports": ("web",),
        "check_path": (8795, "yes")}  # each as a program would send it


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking the hardware stats through its app as any plugin may (a firewall plugin,
    or the MCP plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of the hardware stats' asked through the app."""
        return self.app.ask("hw-stats", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("hw-stats", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("hw-stats", hook, *args)


class Outside:
    """Everything beyond this machine as stand-ins, each noting what it was asked: the name servers (`lookups`),
    check-host.net (`checker.asked`), a connection out (`tried`), and the path check's network (`world`: its listener
    `world.ear`, its capture `world.seen`)."""

    def __init__(self):
        self.lookups, self.tried = [], []
        self.checker, self.world = Checker({8765: "blocked", 443: "blocked"}), World(arrives="dropped")

    def resolve(self, version):
        self.lookups.append(version)
        return (HOME, "OpenDNS") if version == 4 else (None, "none")

    def connect(self, host, port, timeout):
        self.tried.append((host, port))
        if host != OUT_HOST:  # portquiz.net answers on every port; the rest is the path check's network
            self.world.connect(host, port, timeout)

    @property
    def touched(self) -> bool:
        """Whether anything was asked beyond the first read of the address, which the plugin's own attach makes."""
        return bool(self.lookups[2:] or self.tried or self.checker.asked or self.world.ear is not None
                    or self.world.seen.packets)


@pytest.fixture
def attached(tmp_path, monkeypatch):
    """The plugin over the stand-ins, attached with another plugin to an app (its own first read of the public address
    done: the name servers asked once for IPv4 and once for IPv6); let go after."""
    monkeypatch.setattr(hw, "SETTLE_S", 0.0)
    monkeypatch.setattr(hw, "LATE_S", 0.0)
    out = Outside()
    stats = HwStatsPlugin(probe=Probe(), data=tmp_path, net=out.world, connect=out.connect, resolve=out.resolve,
                          checker=out.checker, clock=lambda: 100.0, wall=out.world.tick, cpu_clock=lambda: 0.0)
    neighbour = Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env={}))
    app.attach(stats)
    app.attach(neighbour)
    try:
        assert wait_until(lambda: out.lookups == [4, 6])  # the read its attach began, done
        yield app, neighbour, stats, out
    finally:
        app.detach(neighbour.name)
        app.detach(stats.name)


def test_what_reaches_outside_is_said_to_be_asked_only_from_its_page_and_its_reads_by_anyone():
    assert set(ASKS) == set(OUTSIDE)
    assert set(internal.page_only(MACHINE)) == set(OUTSIDE)  # what the platform reads
    assert internal.plugin_only(MACHINE) == ()
    assert [p for p in internal.problems(MACHINE) if "_ONLY_HOOKS" in p] == []  # each a hook of its own, none in both
    assert set(MACHINE.HOOKS) >= {*OUTSIDE, *READS}
    for hook in OUTSIDE:
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"hw-stats's {hook} is asked only from its page, never "
                                                              "by another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_sends_nothing_anywhere_and_its_page_does(attached):
    app, neighbour, stats, out = attached
    for hook in OUTSIDE:
        args = ASKS[hook]
        for ask in (lambda: neighbour.wants(hook, *args), lambda: app.on_its_own(hook, *args)):
            with pytest.raises(asking.AskRefused, match=f"hw-stats's {hook} is asked only from its page") as refused:
                ask()
            assert refused.value.status == 403 and refused.value.hook == hook
    # no name server asked again, nothing sent to check-host.net or portquiz.net, no port listened on, no packet
    # watched, no path check begun, and the ports listed are Liminal's own still
    assert not out.touched and stats._rt.path is None and stats.selected().source == "liminal"
    assert neighbour.wants("present") is True and neighbour.wants("status")["present"] is True  # its reads, as before
    assert neighbour.wants("view")["span"] == "recent" and "span" in neighbour.wants("charts", "day")
    assert neighbour.wants("refresh_ports")["ok"] is True and not out.touched  # which send nothing anywhere

    assert app.from_page("public_address")["ipv4"] == HOME and out.lookups == [4, 6, 4, 6]  # its page's asks
    assert app.from_page("choose_ports", "web")["said"] == "listing 80, 443" and stats.selected().source == "web"
    checked = app.from_page("check_ports", "8765 443", "both", HOME)
    assert checked["said"].startswith(f"2 ports checked from the internet at {HOME}")
    assert out.checker.asked == [(HOME, (443, 8765))]  # this network's address and the ports, to check-host.net
    assert sorted(set(out.tried)) == [(OUT_HOST, 80), (OUT_HOST, 443), (OUT_HOST, 8765)]
    assert app.from_page("check_path", 8795, "yes")["said"].startswith("checking the way in to port 8795")
    assert wait_until(lambda: not stats._rt.path.running) and stats._rt.path.port == 8795
    assert out.world.ear is not None and stats._rt.path.listening == "ours"  # the check listened, where nothing did
