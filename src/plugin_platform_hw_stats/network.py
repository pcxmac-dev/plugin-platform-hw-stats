"""The services the hw-stats plugin asks about this network (every outside host is its plugin's to name, never the
library's): the name servers answering with the asker's own address (this network's public address: the user,
2026-11-08, "make sure platform hw stats is able to get the current public IP"), the port tester answering on every
TCP port (a port checked out from this machine), portchecker.io (first: it checks the asker's own address, not
logged) and check-host.net (when portchecker.io cannot), whose servers connect to this network's public address on
the ports asked (a port checked from the internet: "verify that 'selected' ports are available or blocked"), only when
the user asks; the router's own WAN address over UPnP (on this network only); and `Net`, what the path check asks of
this machine and its network (the library's route, ping, hops, capture and listener, these services)."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from liminal_libs import capture, netpath
from liminal_libs.ports import Listener, Outcome, parse_ports

# asked directly (no resolver between) for the asker's own address: (the name, its type, the server, whose); an IPv6
# address is asked of a server's IPv6 address, so it comes over IPv6 or not at all
PUBLIC_SERVERS = {
    4: (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),  # resolver1.opendns.com
        ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google")),  # ns1.google.com: its text record holds it
    6: (("myip.opendns.com", "aaaa", "2620:119:35::35", "OpenDNS"),
        ("o-o.myaddr.l.google.com", "txt", "2001:4860:4802:32::a", "Google")),
}
OUT_HOST = "portquiz.net"  # an outgoing port tester: it answers on every TCP port
TRACE_TO = "1.1.1.1"  # Cloudflare's resolver: the first routers on the way to it are this network's way out
PORTCHECKER = "https://portchecker.io"  # its API: /api/me/PORT checks the asker's own address ("True"/"False"), not logged
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


def get_text(url: str, timeout: float = 15.0, accept: str = "text/plain") -> str:
    """A GET's answer as text (the services' https addresses only)."""
    request = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as r:  # noqa: S310 - PORTCHECKER's and CHECK_HOST's https addresses only
            return r.read(1 << 20).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise CheckError(f"HTTP {e.code} {e.reason}") from None
    except (urllib.error.URLError, OSError) as e:
        raise CheckError(str(getattr(e, "reason", e))) from None


def get_json(url: str, timeout: float = 15.0):
    """A GET answered in JSON (check-host.net answers so when asked with Accept: application/json)."""
    body = get_text(url, timeout, accept="application/json")
    try:
        return json.loads(body)
    except ValueError:
        raise CheckError("an answer that is not JSON") from None


class PortChecker:
    """portchecker.io: whether this network's public address answers on a port, asked as "me" (it checks the asker's
    own address, and its code says those checks are not logged); one connection of a second from its server. It
    cannot say a refusal from no answer: a port not open reads "blocked" until the capture says more."""

    name = "portchecker.io"

    def __init__(self, get=get_text, wall=time.time):
        self.get, self.wall = get, wall

    def seen_as(self) -> str:
        """The address portchecker.io sees this network as (the one its checks connect to)."""
        return self.get(f"{PORTCHECKER}/api/me").strip().strip('"')

    def check(self, address: str, ports) -> dict[int, Outcome]:
        out: dict[int, Outcome] = {}
        try:
            seen = self.seen_as()
        except CheckError as e:
            return {int(p): Outcome("failed", f"failed: portchecker.io could not be asked ({e})", self.wall()) for p in ports}
        if seen != str(address):
            return {int(p): Outcome("failed", f"failed: portchecker.io sees this network as {seen}, not {address}", self.wall()) for p in ports}
        for p in parse_ports(ports):
            try:
                said = self.get(f"{PORTCHECKER}/api/me/{p}").strip().strip('"').lower()
            except CheckError as e:
                out[p] = Outcome("failed", f"failed: portchecker.io could not be asked ({e})", self.wall())
                continue
            if said == "true":
                out[p] = Outcome("open", "open: portchecker.io connected", self.wall())
            elif said == "false":
                out[p] = Outcome("blocked", "blocked: portchecker.io could not connect within a second (refused, or no answer)", self.wall())
            else:
                out[p] = Outcome("failed", f"failed: portchecker.io answered {said[:60]!r}", self.wall())
        return out


def probe(address: str, port: int, probers) -> tuple[Outcome, str]:
    """A port at this network's public address checked from the internet: by the first service able to tell (open
    or not), the next asked when one fails (its limit reached, unreachable). (the outcome, the service's name)."""
    tried = []
    for prober in probers:
        name = getattr(prober, "name", type(prober).__name__)
        try:
            o = prober.check(address, [port])[int(port)]
        except (CheckError, ValueError, KeyError) as e:
            o = Outcome("failed", f"failed: {name}: {e}", time.time())
        if o.state != "failed":
            return o, name
        tried.append(o.why or name)
    return Outcome("failed", "failed: no service could check it from the internet: " + "; ".join(tried), time.time()), ""


# -- the router's own answer (UPnP) ----------------------------------------------------------------------------

SSDP = ("239.255.255.250", 1900)
IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"  # the envelope's namespace (a name, never fetched)
SOAP_ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"


def router_wan(local: str | None, wait: float = 2.5, timeout: float = 4.0) -> str | None:
    """The router's own WAN address, when it answers UPnP (an Internet Gateway Device's GetExternalIPAddress): asked on
    this machine's network only; None when UPnP is off or nothing answered."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return None
    locations: set[str] = set()
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if local:
            s.bind((local, 0))
        s.settimeout(0.3)
        s.sendto(f"M-SEARCH * HTTP/1.1\r\nHOST: {SSDP[0]}:{SSDP[1]}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {IGD}\r\n\r\n".encode(), SSDP)
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                data, _ = s.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                continue
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                locations.add(m.group(1).decode(errors="replace"))
    except OSError:
        return None
    finally:
        s.close()
    for location in sorted(locations):
        parts = urllib.parse.urlparse(location)
        if parts.scheme != "http" or netpath.kind(parts.hostname) not in ("private", "shared", "link-local"):
            continue  # the router on this network, nothing else
        try:
            with urllib.request.urlopen(location, timeout=timeout) as r:  # noqa: S310 - the router's own description
                xml = r.read(1 << 20).decode("utf-8", "replace")
        except (OSError, ValueError):
            continue
        for service in re.findall(r"<service>(.*?)</service>", xml, flags=re.S):
            st, cu = re.search(r"<serviceType>([^<]*)<", service), re.search(r"<controlURL>([^<]*)<", service)
            if not st or not cu or not re.search(r"WAN(IP|PPP)Connection", st.group(1)):
                continue
            body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="{SOAP}" s:encodingStyle="{SOAP_ENCODING}"><s:Body>'
                    f'<u:GetExternalIPAddress xmlns:u="{st.group(1)}"/></s:Body></s:Envelope>').encode()
            request = urllib.request.Request(urllib.parse.urljoin(location, cu.group(1)), data=body, headers={
                "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{st.group(1)}#GetExternalIPAddress"'})
            try:
                with urllib.request.urlopen(request, timeout=timeout) as r:  # noqa: S310
                    answer = r.read(1 << 16).decode("utf-8", "replace")
            except (OSError, ValueError):
                continue
            m = re.search(r"<NewExternalIPAddress>\s*([^<\s]+)\s*<", answer)
            if m and netpath.kind(m.group(1)) != "unknown":
                return m.group(1)
    return None


class Net:
    """What the path check asks of this machine and its network (a test hands the plugin a stand-in): its route, a
    ping, the first hops, the router's WAN address, a capture of a port's packets, a listener on a port, the check
    from the internet."""

    def route(self) -> netpath.Route:
        return netpath.local_route()

    def ping(self, host: str) -> float | None:
        return netpath.ping(host)

    def hops(self) -> list[str | None] | None:
        return netpath.hops(TRACE_TO, 3)

    def wan(self, local: str | None) -> str | None:
        return router_wan(local)

    def capture(self, address: str, ports):
        """A started capture (capture.CaptureError when packets cannot be watched here)."""
        ok, why = capture.available()
        if not ok:
            raise capture.CaptureError(why)
        c = capture.Capture(address, ports)
        c.start()
        return c

    def listener(self, port: int) -> Listener:
        """A started listener on every address (OSError when the port is taken)."""
        lis = Listener(port)
        lis.start()
        return lis

    def probe(self, address: str, port: int) -> tuple[Outcome, str]:
        return probe(address, port, (PortChecker(), CheckHost()))


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
