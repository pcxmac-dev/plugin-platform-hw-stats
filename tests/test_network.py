"""check-host.net's TCP check (network.CheckHost) over a stand-in for its API, in the shapes its API page gives
(https://check-host.net/about/api): a port asked of three servers, their answers asked for until each has one;
open, closed, blocked and failed; and its faults said in words. Nothing is sent anywhere."""
from __future__ import annotations

import urllib.error
import urllib.parse

import pytest

from liminal_libs.ports import Outcome
from plugin_platform_hw_stats import network
from plugin_platform_hw_stats.network import CheckError, CheckHost

HOME = "93.184.216.34"
SERVERS = {"us1.node.check-host.net": ["us", "USA", "Los Angeles", "5.253.30.82", "AS18978"],
           "ch1.node.check-host.net": ["ch", "Switzerland", "Zurich", "179.43.148.195", "AS50837"],
           "pt1.node.check-host.net": ["pt", "Portugal", "Viana", "185.83.213.25", "AS44222"]}
OPEN = {"us1.node.check-host.net": [{"time": 0.03, "address": HOME}], "ch1.node.check-host.net": [{"error": "Connection timed out"}],
        "pt1.node.check-host.net": [{"time": 0.2, "address": HOME}]}
CLOSED = {n: [{"error": "Connection refused"}] for n in SERVERS}
BLOCKED = {n: [{"error": "Connection timed out"}] for n in SERVERS}
SLOW = {"us1.node.check-host.net": [{"error": "No route to host"}], "ch1.node.check-host.net": None, "pt1.node.check-host.net": [None]}


class FakeCheckHost:
    """check-host.net's API in memory: /check-tcp answered with a request id and three servers, /check-result first
    with one server still checking (null), then with each server's answer."""

    def __init__(self, answers):
        self.answers, self.asked, self.polls, self.t = answers, [], {}, [0.0]

    def get(self, url):
        self.asked.append(url)
        if "/check-tcp?" in url:
            q = urllib.parse.parse_qs(url.split("?", 1)[1])
            port = int(q["host"][0].rsplit(":", 1)[1])
            assert q["max_nodes"] == ["3"]
            if port == 666:
                return {"ok": 0, "error": "bad_host"}
            if port == 667:
                raise CheckError("HTTP 503 Service Unavailable")
            if port == 999:
                return {"ok": 0, "error": "limit_exceeded"}  # as check-host.net answered this machine on 2026-11-08
            if port == 998:
                raise CheckError("HTTP 429 Too Many Requests")
            return {"ok": 1, "request_id": f"r{port}", "permanent_link": f"https://check-host.net/check-report/r{port}", "nodes": SERVERS}
        port = int(url.rsplit("/", 1)[1][1:])
        n = self.polls[port] = self.polls.get(port, 0) + 1
        final = self.answers[port]
        return {**final, "pt1.node.check-host.net": None} if n == 1 else final

    def sleep(self, seconds):
        self.t[0] += seconds


def test_check_host_s_servers_connecting_in_from_the_internet():
    fake = FakeCheckHost({80: OPEN, 25: CLOSED, 8765: BLOCKED})
    c = CheckHost(get=fake.get, sleep=fake.sleep, clock=lambda: fake.t[0], wall=lambda: 9.0)
    found = c.check(HOME, "8765 80 25 666 667")
    assert {p: o.state for p, o in found.items()} == {25: "closed", 80: "open", 666: "failed", 667: "failed", 8765: "blocked"}
    assert found[80].said == "open: 2 of 3 servers connected" and "Los Angeles, USA: connected in 0.03 s" in found[80].detail
    assert found[25].said.startswith("closed: refused at 3 of 3 servers (the address answers, nothing accepts this port")
    assert found[8765].said.startswith("blocked: no answer to 3 of 3 servers (dropped on the way")
    assert "Zurich, Switzerland: Connection timed out" in found[8765].detail and found[8765].at == 9.0
    assert found[666].said == "failed: check-host.net did not take it (bad_host)"
    assert found[667].said == "failed: check-host.net could not be asked (HTTP 503 Service Unavailable)"
    tcp = [u for u in fake.asked if "/check-tcp?" in u]
    assert tcp[0] == f"https://check-host.net/check-tcp?host={HOME}%3A25&max_nodes=3" and len(tcp) == 5
    assert fake.polls == {25: 2, 80: 2, 8765: 2}  # asked again only while a server was still checking
    assert fake.t[0] == pytest.approx(4 * 0.25 + 3.0 + 2.0)  # the gaps between the ports, the first wait, one more


def test_its_limit_reached_nothing_more_is_asked_of_it():
    for limit, words in ((999, "limit_exceeded"), (998, "HTTP 429 Too Many Requests")):
        fake = FakeCheckHost({80: OPEN})
        found = CheckHost(get=fake.get, sleep=fake.sleep, clock=lambda: fake.t[0], wall=lambda: 9.0).check(HOME, [80, limit, 8765, 9000])
        assert found[80].state == "open" and found[limit].said == f"failed: check-host.net's limit was reached ({words}): try again later"
        assert found[8765].said == found[9000].said == f"failed: not asked, check-host.net's limit was reached ({words}): try again later"
        assert [u for u in fake.asked if "/check-tcp?" in u][-1].endswith(f"%3A{limit}&max_nodes=3")  # 8765 and 9000 never asked


def test_a_server_still_checking_when_the_wait_ends_and_addresses_never_asked_of():
    fake = FakeCheckHost({443: SLOW})
    found = CheckHost(get=fake.get, sleep=fake.sleep, clock=lambda: fake.t[0], wall=lambda: 9.0, wait=10.0).check(HOME, [443])
    o = found[443]
    assert o.state == "blocked" and o.said.startswith("blocked: no answer to 1 of 3 servers")  # no route: dropped
    assert "Zurich, Switzerland: still checking when the wait ended" in o.detail and "Viana, Portugal: an answer it could not read" in o.detail
    assert fake.polls[443] >= 4 and fake.t[0] >= 10.0  # asked until the wait ended
    c = CheckHost(get=fake.get, sleep=fake.sleep)
    for address, words in (("192.168.1.5", "not a public address"), ("::1", "not a public address"), ("home.example.com", "not an address")):
        with pytest.raises(ValueError, match=words):
            c.check(address, "80")
    with pytest.raises(ValueError, match="at most 12"):
        c.check(HOME, "1-13")
    assert network.verdict({}, {}, 1.0) == Outcome("failed", "failed: no server answered", 1.0)
    assert network.verdict({"x1.node.check-host.net": [{"error": "Something odd"}]}, {}, 1.0).said == "failed: no server could tell (1 asked)"


def test_check_host_is_asked_in_json_and_its_faults_said(monkeypatch):
    class Answer:
        def __init__(self, body):
            self.body = body

        def read(self, n):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    seen = []

    def urlopen(request, timeout):
        seen.append((request.full_url, request.get_header("Accept"), request.get_header("User-agent"), timeout))
        return Answer(b'{"ok": 1}')
    monkeypatch.setattr(network.urllib.request, "urlopen", urlopen)
    assert network.get_json("https://check-host.net/check-result/r1") == {"ok": 1}
    assert seen == [("https://check-host.net/check-result/r1", "application/json", "Liminal (plugin-platform-hw-stats)", 15.0)]
    monkeypatch.setattr(network.urllib.request, "urlopen", lambda request, timeout: Answer(b"<html>"))
    with pytest.raises(CheckError, match="not JSON"):
        network.get_json("https://check-host.net/x")

    def too_many(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)
    monkeypatch.setattr(network.urllib.request, "urlopen", too_many)
    with pytest.raises(CheckError, match="HTTP 429 Too Many Requests"):
        network.get_json("https://check-host.net/x")

    def offline(request, timeout):
        raise urllib.error.URLError("no network")
    monkeypatch.setattr(network.urllib.request, "urlopen", offline)
    with pytest.raises(CheckError, match="no network"):
        network.get_json("https://check-host.net/x")
