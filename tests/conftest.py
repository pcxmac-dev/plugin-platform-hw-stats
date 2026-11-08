"""Nothing in these tests reaches the network: a connection out, a request to check-host.net and a name server's
lookup are refused (each test hands the plugin its stand-ins), and the variables a setting reads are cleared."""
from __future__ import annotations

import pytest

import plugin_platform_hw_stats.network as network
from liminal_libs import dns, ports


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(ports.socket, "create_connection", refused)
    monkeypatch.setattr(network.urllib.request, "urlopen", refused)
    monkeypatch.setattr(dns, "query", refused)
    for name in ("HW_STATS_PORTS", "LIMINAL_CHARTS_PORT", "LIMINAL_PLATFORM_PORT", "LIMINAL_FETCHER_PORT", "LIMINAL_LOGIN_PORT"):
        monkeypatch.delenv(name, raising=False)
