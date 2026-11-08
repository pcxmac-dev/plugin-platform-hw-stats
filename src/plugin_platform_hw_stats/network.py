"""The services the hw-stats plugin asks about this network (every outside host is its plugin's to name, never the
library's): the name servers answering with the asker's own address (this network's public address: the user,
2026-11-08, "make sure platform hw stats is able to get the current public IP"), the port tester answering on every
TCP port (a port checked out from this machine) and check-host.net, whose servers connect to this network's public
address on the ports asked (a port checked from the internet: "verify that 'selected' ports are available or
blocked"). The address and the ports go to check-host.net only when the user asks for a check from the internet."""
from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from liminal_libs.ports import Outcome, parse_ports

# asked directly (no resolver between) for the asker's own address: (the name, its type, the server, whose); an IPv6
# address is asked of a server's IPv6 address, so it comes over IPv6 or not at all
PUBLIC_SERVERS = {
    4: (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),  # resolver1.opendns.com
        ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google")),  # ns1.google.com: its text record holds it
    6: (("myip.opendns.com", "aaaa", "2620:119:35::35", "OpenDNS"),
        ("o-o.myaddr.l.google.com", "txt", "2001:4860:4802:32::a", "Google")),
}
OUT_HOST = "portquiz.net"  # an outgoing port tester: it answers on every TCP port
CHECK_HOST = "https://check-host.net"  # its API: /check-tcp?host=ADDRESS:PORT&max_nodes=N, then /check-result/ID
NODES = 3  # its servers asked for each port (in different countries)
GAP_S = 0.25  # between two ports asked of it
FIRST_S = 3.0  # its answers asked for after this long (a connection takes its servers a few seconds)
POLL_S = 2.0
WAIT_S = 25.0  # the longest its answers are waited for
USER_AGENT = "Liminal (plugin-platform-hw-stats)"
REFUSED = ("refused", "reset")
DROPPED = ("timed out", "timeout", "no route", "unreachable")


class CheckError(Exception):
    """check-host.net could not be asked, or answered with something that is not its answer."""


def get_json(url: str, timeout: float = 15.0):
    """A GET answered in JSON (check-host.net answers so when asked with Accept: application/json)."""
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as r:  # noqa: S310 - CHECK_HOST's https address only
            body = r.read(1 << 20)
    except urllib.error.HTTPError as e:
        raise CheckError(f"HTTP {e.code} {e.reason}") from None
    except (urllib.error.URLError, OSError) as e:
        raise CheckError(str(getattr(e, "reason", e))) from None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise CheckError("an answer that is not JSON") from None


def place(info) -> str:
    """A server's place ("Los Angeles, USA") from check-host.net's description of it ([cc, country, city, ip, asn])."""
    if isinstance(info, (list, tuple)) and len(info) >= 3 and info[2]:
        return f"{info[2]}, {info[1]}"
    return ""


def verdict(answers: dict, servers: dict, at: float) -> Outcome:
    """check-host.net's servers' answers for one port as one outcome: open when any connected (its answer
    [{"time", "address"}]), closed when none did and one was refused, blocked when none did and one got no answer (a
    timeout, no route), failed when none could tell (still checking when the wait ended, an error of their own)."""
    said, connected, refused, dropped = [], 0, 0, 0
    answers = answers if isinstance(answers, dict) else {}
    for node in sorted(set(servers) | set(answers)):
        where = place(servers.get(node)) or node.split(".")[0]
        answer = answers.get(node)
        item = answer[0] if isinstance(answer, list) and answer else None
        if answer is None:
            said.append(f"{where}: still checking when the wait ended")
        elif isinstance(item, dict) and item.get("error"):
            words = str(item["error"])
            low = words.lower()
            if any(w in low for w in REFUSED):
                refused += 1
            elif any(w in low for w in DROPPED):
                dropped += 1
            said.append(f"{where}: {words}")
        elif isinstance(item, dict) and isinstance(item.get("time"), (int, float)):
            connected += 1
            said.append(f"{where}: connected in {float(item['time']):.2f} s")
        else:
            said.append(f"{where}: an answer it could not read")
    n = len(said)
    if connected:
        return Outcome("open", f"open: {connected} of {n} servers connected", at, tuple(said))
    if refused:
        return Outcome("closed", f"closed: refused at {refused} of {n} servers (the address answers, nothing accepts this "
                                 "port: no forwarding to it, or nothing listening)", at, tuple(said))
    if dropped:
        return Outcome("blocked", f"blocked: no answer to {dropped} of {n} servers (dropped on the way: the router, the "
                                  "ISP or a firewall)", at, tuple(said))
    return Outcome("failed", f"failed: no server could tell ({n} asked)" if n else "failed: no server answered", at, tuple(said))


class CheckHost:
    """check-host.net's TCP check: an address's ports asked of `nodes` of its servers each, their answers waited for
    at most `wait` seconds. A public address only (the internet reaches no other); the plugin asks of this network's
    own alone, and only when the user asks for a check from the internet."""

    def __init__(self, get=get_json, sleep=time.sleep, clock=time.monotonic, wall=time.time, nodes: int = NODES,
                 wait: float = WAIT_S, first: float = FIRST_S, poll: float = POLL_S, gap: float = GAP_S):
        self.get, self.sleep, self.clock, self.wall = get, sleep, clock, wall
        self.nodes, self.wait, self.first, self.poll, self.gap = nodes, wait, first, poll, gap

    def check(self, address: str, ports) -> dict[int, Outcome]:
        """Each of `ports` (at most twelve) at `address` as check-host.net's servers found it."""
        try:
            ip = ipaddress.ip_address(str(address).strip())
        except ValueError:
            raise ValueError(f"not an address: {address!r}") from None
        if not ip.is_global:
            raise ValueError(f"{ip} is not a public address: the internet cannot reach it")
        ports = parse_ports(ports)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
        out: dict[int, Outcome] = {}
        asked: dict[int, tuple[str, dict]] = {}
        limited = ""  # check-host.net's limit reached: nothing more is asked of it in this check
        for i, p in enumerate(ports):
            if limited:
                out[p] = Outcome("failed", f"failed: not asked, check-host.net's limit was reached ({limited}): try again later", self.wall())
                continue
            if i:
                self.sleep(self.gap)
            try:
                a = self.get(f"{CHECK_HOST}/check-tcp?" + urllib.parse.urlencode({"host": f"{host}:{p}", "max_nodes": self.nodes}))
            except CheckError as e:
                if "429" in str(e):
                    limited = str(e)
                    out[p] = Outcome("failed", f"failed: check-host.net's limit was reached ({e}): try again later", self.wall())
                else:
                    out[p] = Outcome("failed", f"failed: check-host.net could not be asked ({e})", self.wall())
                continue
            if isinstance(a, dict) and a.get("ok") == 1 and a.get("request_id"):
                asked[p] = (str(a["request_id"]), a["nodes"] if isinstance(a.get("nodes"), dict) else {})
                continue
            error = str(a.get("error") or "") if isinstance(a, dict) else ""
            if "limit" in error.lower():
                limited = error
                out[p] = Outcome("failed", f"failed: check-host.net's limit was reached ({error}): try again later", self.wall())
            else:
                out[p] = Outcome("failed", f"failed: check-host.net did not take it ({error or 'an answer it could not read'})", self.wall())
        answers: dict[int, dict] = {}
        waiting = set(asked)
        deadline = self.clock() + self.wait
        if waiting:
            self.sleep(min(self.first, self.wait))
        while waiting:
            for p in sorted(waiting):
                rid, servers = asked[p]
                try:
                    r = self.get(f"{CHECK_HOST}/check-result/{urllib.parse.quote(rid, safe='')}")
                except CheckError:
                    continue
                if not isinstance(r, dict):
                    continue
                answers[p] = r
                names = servers or r
                if names and all(r.get(n) is not None for n in names):  # every server has answered
                    waiting.discard(p)
            if not waiting or self.clock() >= deadline:
                break
            self.sleep(self.poll)
        for p, (_, servers) in asked.items():
            out[p] = verdict(answers.get(p) or {}, servers, self.wall())
        return dict(sorted(out.items()))
