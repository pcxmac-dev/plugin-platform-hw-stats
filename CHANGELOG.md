# Changelog

## 0.5.2 (2026-11-25)

What reaches beyond this machine is asked only from the page (the sweep after the independent review's finding PLT-H1;
the user's choice, 2026-11-25: plugin releases, each plugin declaring its change actions page-only). The platform hands
an ask over HTTP (`POST /api/machines/hw-stats/ask`, two headers and no sign-in) straight to a hook, so any program on
this machine asked every hook this plugin has, with none of the page's confirmations.

- **`PAGE_ONLY_HOOKS`** (liminal-libs 1.66.0's word): `public_address`, `check_ports`, `check_path` and
  `choose_ports`. Another plugin's ask of one is refused (403), and liminal-platform 0.34.0 refuses one over HTTP (401)
  unless its login shows that you are at the page. Before, a program of any account on this machine had:
  - `check_ports` send this network's public address and any twelve ports to check-host.net, whose servers then
    connect to them, and this machine connect to portquiz.net on each;
  - `check_path` listen on a port at every address while its way in is checked (on a DMZ host, open to the internet
    meanwhile), watch that port's packets at the network adapter, and ask the router over UPnP and portchecker.io;
  - `public_address` ask OpenDNS's and Google's name servers again, as often as it liked;
  - `choose_ports` change the ports the page lists and fills into Check ports.
  A platform that holds no login asks them as before. The 401 rests on the login's word that your browser is signed
  in, and a local login signs `secret` and `default` in with no password, so a program on this machine can sign itself
  in and ask them still: a proof that a program cannot make is the login's and the platform's to give.
- Asked by anyone, as before: `present`, `status`, `view`, `charts` and `refresh_ports` (reads of this machine, which
  send nothing anywhere). No plugin's code asks any hook of this one (2026-11-25). The plugin's own reading of the
  public address (at its attach and every 15 minutes) and the command line call the code in their own process, not
  through an ask, so they work as before.
- No new floor: a liminal-libs before 1.66.0 holds no hook to who asks it, and liminal-platform 0.34.0 then reads the
  word from the plugin itself.
- Tests: `tests/test_who_asks.py`, through the library's own App over stand-ins for the probe, the name servers,
  check-host.net, a connection out and the path check's network (skipped on a liminal-libs before 1.66.0): each of the
  four refused to another plugin and to an ask that names no one, no name server asked again, nothing sent, no port
  listened on, the ports listed unchanged; each done when the page asks it; the reads answered to a plugin. Taking a
  hook out of the word fails them.

Needs liminal-libs>=1.52.0.

## 0.5.1 (2026-11-15)

The capture card names two more pcap calls: pcap_setnonblock and pcap_get_selectable_fd. liminal-libs 1.54.0's capture
makes them on Linux, so a read waits on the capture's socket no more than its timeout, and a watch stops when it is told
to even when no packet comes. Nothing else changes.

## 0.5.0 (2026-11-15)

Liminal's own ports are named by the OS their app runs on (the user: "linux::liminal-login would be the prefix for WSL
instance and windows:: would be the prefix for the liminal on the ports page"). The Ports table, the summary line and
a check's answer say `windows::liminal-charts`, `windows::liminal-login` on Windows and `linux::liminal-charts`,
`linux::liminal-login` in a suite running on Linux, where they said "Liminal's charts", "Liminal's login". New
`os_prefix()`; `whose(app, system)` takes another OS's prefix for a suite elsewhere on the same PC.

## 0.4.1 (2026-11-14)

Liminal's own ports are the four apps' alone (liminal-libs 1.52.0; the user, 2026-11-14: "i only want ports for liminal-login ; liminal-platform ; liminal-charts ; liminal-integrator"; "never provide ports for anything else"): the integrator's login at 8796 is gone, a login an app inherits being an object in that app, at its port. The Ports table lists those four when HW_STATS_PORTS is not set.

## 0.4.0 (2026-11-11)

Its API on its page, plugin API 2.2 (the user: "each plugin should reflect the the API its attached to, and present
links that provide documentation, the plugin interface should more or less contain what it already has, BUT, it should
also expose more of what the API is about"). Ten cards (`apis.py`), each with the makers' pages, every part of the API
said covered or not, and every call the plugin makes beside the API's other notable ones: Windows' kernel32, ntdll and
iphlpapi (every Win32 function the library's sampler calls), Linux's /proc and /sys, the system's ping, tracert or
traceroute and nslookup, OpenDNS's and Google's name servers, portchecker.io (its OpenAPI), check-host.net,
portquiz.net (no HTTPS page of its own: the plugin's pages are linked), the router's UPnP Internet Gateway Device, and
Npcap with libpcap (Npcap's free license allows five installs; its OEM license, paid, more).

`api_facts()` says what the plugin kept while it ran, asking nothing: the sampler's state, the public address and
whose answer it was, the last checks from the internet and out, the last path check's findings. Tests: the cards name
every Win32 function, /proc and /sys file and pcap function the library calls for the plugin, the commands it runs, the
name servers' questions, the services' endpoints and portquiz.net's ports; a link check runs with
LIMINAL_VENDOR_PAGES=1. Needs liminal-libs>=1.49.0.

## 0.3.1 (2026-11-08)

A time near 1970 is said in UTC where Windows cannot take it to local time (Python before 3.13: CI's
windows-latest 3.12 failed on the path test's start time); the path test starts at a real time.

## 0.3.0 (2026-11-08)

A port's way in, hop by hop, drawn as it goes (the user: "the port checker doesn't seem to work, i have this computer as
DMZ host so, basically the check needs to validate the computer, the router/gateway to the computer, then the internet
to the computer, and graphically show traffic moving between the three different checks"; "i don't think the plugin is
able to check if there is a listener or to listen on the port in order to validate the traffic"; "if there is a
python-tcpdump that would be good ... as a listener"):

- `check_path(port, listen)` (Check the way in, a Way in button on each Ports row; `path PORT [--no-listen]` on the
  command line), on a thread of its own: this computer (what listens; the check's own listener on every address when
  nothing does; a connection to its address on the network), the router (a ping, the first hops toward 1.1.1.1, its
  WAN address over UPnP, a connection to the public address turned back to this computer), the internet
  (portchecker.io, else check-host.net). The port's packets are watched at the network adapter meanwhile (liminal-libs
  1.30.0's capture: Npcap, no administrator needed), so the check says where the traffic stops: never arriving
  (behind the ISP's NAT, or not forwarded), arriving and dropped by this computer's firewall, refused, or accepted.
- The platform's page draws it (liminal-platform 0.8.0, status.paths): the internet, the router and this computer,
  traffic moving along the link being checked, each hop in its state; what each hop showed beneath; the packets in a
  Traffic table (when, from, to, flags, what each was).
- portchecker.io first for a check from the internet (asked as "me": its checks of the asker's own address are not
  logged; check-host.net limited this machine at once); check-host.net when it cannot.
- On this PC (2026-11-08): the DMZ works (portchecker.io's SYNs seen arriving from 68.183.43.132, the router looping
  a connection to the public address back), and the traffic stops at this computer, which answers nothing on a port
  nothing listens on.

## 0.2.1 (2026-11-08)

The user, on the platform's page: "disk io is redundant as 'DISKS' below Ports, also there needs to be a refresh button
and port selector for PORTS".

- One Disks table: each disk's space and its reads and writes a second (the bytes since start beneath), in one row when
  they are the same disk (a drive's letter on Windows; the device holding the mount on Linux, from /sys/dev/block); the
  Disk I/O table is gone (the chart and the fact stay).
- The Ports table chooses what it lists (liminal-platform 0.7.0: a table's own choices and buttons): Liminal's own,
  Web (80, 443), Mail (25, 465, 587, 993), Remote access (22, 3389), HW_STATS_PORTS when set, or ports typed under Other
  ports (`choose_ports`); kept until the platform restarts, since the login keeps no setting yet. Refresh
  (`refresh_ports`) reads what listens on each port now; nothing is sent anywhere.

## 0.2.0 (2026-11-08)

This network's public address and its ports (the user: "lets make sure platform hw stats is able to get the current
public IP, and verify that 'selected' ports are available or blocked"; "there should be a way to check ports"; the
settings through the login, "but we will add login later"):

- The public address, IPv4 and IPv6, asked of OpenDNS (else Google's name server) when the plugin is attached and every
  15 minutes while it is, among the facts (`public_address`, the page's Read the public address again, `ip`).
- The ports chosen (`HW_STATS_PORTS`, read through the platform's login, the user's own setting once the login app holds
  it; Liminal's own pages' ports unless set) in a Ports table: what listens on each here (each program, on every
  address or this machine only), and each one's last check.
- Check ports (a form on the platform's page, liminal-platform 0.6.0; `check_ports`; `ports --where` on the command
  line): from the internet (check-host.net's servers try to connect to this network's public address: the address and
  the ports go to check-host.net, only then), out from this machine (connections to portquiz.net, which answers on
  every port) or both: open, closed (refused), blocked (no answer) or failed. One of Liminal's own pages answering from
  the internet is a problem said on the page. check-host.net's limit reached, nothing more is asked of it.
- On liminal-libs 1.29.0 (`dns.public_address`, `ports`, the probes' `program_names`); the services' hosts are named
  here (`network`), never in the library.

## 0.1.1 (2026-11-07)

The disks' I/O, hardware only (the user: "lets get disk io ... in hwstats"; "the platform only cares about hardware";
the databases' own figures are the integrator's): the bytes read and written a second over every disk, charted with
the network, and each disk's rates and totals since start in a table (liminal-libs 1.26.0: `disk` in the monitor's view).

## 0.1.0 (2026-11-07)

The first release: the charts app's Resources monitoring as a platform plugin (the library's
`resources.Monitor`, liminal-libs 1.22.0, which reads Linux as it reads Windows): the machine, every Liminal
app's processes, the disks and the data files; its status as facts, tables and charts for the platform's
page; sampling only while attached to the platform app.
