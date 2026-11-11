# plugin-platform-hw-stats

Hardware stats for Liminal: this machine's processor, memory, network, disks and data files, and every Liminal
app's processes, on Windows and Linux alike.

The user's words (2026-11-07): "i need the hardware monitoring that was in charts, it needs to be windows and
linux agnostic, ie it runs on both, the stats were on the charts app but they need a plugin too, hw-stats
platform plugin".

## What it does

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.2, its icon the gauge)
over the library's `resources.Monitor`, the sampler the charts app's Resources view uses:

- The machine: the processor's load over all its cores, the memory in use and committed, the network's bytes
  in and out a second, the adapters and the link speed, the TCP connections.
- Every Liminal app's processes (the charts app, the integrator, the login, the platform, each with its port
  or `(daemon)`): CPU as a share of one core, memory and private bytes, reads and writes a second, threads,
  handles, connections, when it started.
- The disks holding the data, the app and the system; each disk's reads and writes a second and since start (hardware
  only: the databases' own figures are the integrator's); the data folder's size, files and growth by folder.
- Read on Windows through kernel32, ntdll and iphlpapi, on Linux through `/proc` and `/sys`: the same figures
  either way. Elsewhere only this process, the disks and the files.

It samples only while attached to the platform app: every 30 s in the background, every 2 s while the
platform's page shows it, at most 5% of one core, with at most 16 MB of samples (ten minutes at full rate and
a day at one every 30 s). Detached, the sampling ends and the samples go.

The platform's page draws its status: the facts on the right, and in the middle the charts (the processor,
the memory, the network and each program's processor over the last ten minutes or the last day) and the
tables (the programs, the ports, the disks with their space and their reads and writes, the data folders).

## This network: its public address and its ports

The user (2026-11-08): "lets make sure platform hw stats is able to get the current public IP, and verify that
'selected' ports are available or blocked"; "there should be a way to check ports".

- **The public address**, IPv4 and IPv6: asked of OpenDNS's resolver (`myip.opendns.com` answers with the asker's
  address), else of Google's name server (`o-o.myaddr.l.google.com`), each asked directly; a public address only, so a
  machine without an IPv6 route says it has none. Read when the plugin is attached to the platform and every 15
  minutes while it is, and when asked (Read the public address again). Shown among the facts with whose answer it was.
- **The ports**: chosen above the Ports table: Liminal's own pages' ports (8765, 8775, 8785, 8795, 8796), Web (80,
  443), Mail (25, 465, 587, 993), Remote access (22, 3389), `HW_STATS_PORTS` when it is set, or ports typed under
  **Other ports** (at most 12). A choice on the page is kept until the platform restarts (the login keeps no setting
  yet); otherwise `HW_STATS_PORTS` (`25, 80, 443, 8765-8768`), read through the platform's login (today the platform's
  EnvironmentLogin, so the variable; the user's own setting once the login app holds the plugins' settings), else
  Liminal's own. The table says what listens on each here (the program, on every address or this machine only) and
  each one's last check; **Refresh** reads what listens again now (nothing is sent anywhere).
- **Check ports** (a button under the table, a form on the platform's page): the ports to check and where from:
  - *From the internet*: check-host.net's servers (three, in different countries) try to connect to this network's
    public address on each port. That address and the ports go to check-host.net, only when you press Check. The
    router's port forwarding, the ISP and this machine's firewall decide it together: **open** (a connection was made),
    **closed** (refused: the address answers, nothing accepts that port), **blocked** (no answer: dropped on the way).
    One of Liminal's own pages answering from the internet is shown as a problem: they are for this machine only.
    check-host.net limits its free checks; when it says its limit is reached, nothing more is asked of it and the
    check says to try again later.
  - *Out from this machine*: a connection to portquiz.net (it answers on every TCP port) on each port, its port 80
    first: an ISP blocking port 25, say, shows as blocked.

- **Check the way in** (a Way in button on each Ports row, or under the table): one port, hop by hop, drawn on the page
  as it goes (liminal-platform 0.8.0): **this computer** (what listens on the port; when nothing does, the check
  listens on it itself, on every address, until it ends; a connection to the computer's own address on the network),
  **the router** (a ping; the first routers toward 1.1.1.1, each said public or private; its WAN address when it
  answers UPnP; a connection to this network's public address, seen coming back to this computer when the router loops
  back to its DMZ host), then **the internet** (portchecker.io, else check-host.net, connecting to the public address).
  Throughout, the port's TCP packets are watched at the network adapter: a tcpdump in Python (liminal-libs' capture
  over Npcap's wpcap.dll, installed with Wireshark or on its own; no administrator needed unless Npcap was installed for
  administrators only; libpcap as root on Linux). The packets show where the traffic stops: nothing arriving (the
  ISP's NAT, or the router not forwarding it), arriving but unanswered (this computer's firewall, or nothing
  listening), refused, or accepted; the Traffic table lists them.
  Listening: Windows may ask once whether Python may accept connections. This computer may be the DMZ host: allowing
  Python on public networks lets the internet reach Python programs here while they listen.

Nothing on this machine is changed by a check. The services' hosts are this plugin's (`network.py`): the library
names none.

## Its API

The user's words (2026-11-11): "each plugin should reflect the the API its attached to, and present links that provide
documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more of
what the API is about". Since 0.4.0 (plugin API 2.2) the plugin declares what it attaches to (`apis.py`), and the
platform's page draws each card: what the API is, its links, every part of it (those the plugin uses first, the rest
under "more of the API") and every call it makes, with the API's other notable calls beside them.

- **Windows**: the Win32 functions the library's sampler calls ([GetSystemTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes),
  [GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex),
  [IOCTL_DISK_PERFORMANCE](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_performance),
  [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess),
  [GetIfTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2),
  [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) and the rest).
- **Linux**: [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), [sysfs](https://docs.kernel.org/filesystems/sysfs.html),
  [/proc/diskstats](https://docs.kernel.org/admin-guide/iostats.html), [/proc/net/tcp](https://docs.kernel.org/networking/proc_net_tcp.html).
- **ping, tracert or traceroute, and nslookup**, the system's own commands: the path check and the public address.
- **OpenDNS** ([its resolvers](https://www.opendns.com/setupguide/)) and **Google's name servers**
  ([Google Public DNS](https://developers.google.com/speed/public-dns)): this network's public address, asked of them
  directly; neither documents the name it answers so (myip.opendns.com, o-o.myaddr.l.google.com).
- **portchecker.io** ([its API](https://portchecker.io/docs), [its OpenAPI](https://portchecker.io/docs/openapi.json))
  and **check-host.net** ([its API](https://check-host.net/about/api)): a port checked from the internet.
- **portquiz.net**: a port checked out from this machine; its page (http://portquiz.net) has no HTTPS address, so its
  card links this plugin's own pages instead.
- **UPnP Internet Gateway Device** ([the specifications](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/)):
  the router's WAN address, on this network only.
- **Npcap and libpcap** ([Npcap](https://npcap.com/), [pcap(3PCAP)](https://www.tcpdump.org/manpages/pcap.3pcap.html)):
  the packets of the port checked. Npcap's free license allows five installs; more, or redistributing it, needs a paid
  [OEM license](https://npcap.com/oem/).

`api_facts()` says what the plugin kept of them while it ran, asking nothing: the sampler's state, this network's
public address and whose answer it was, the last checks from the internet and out, and the last path check's findings
(the prober's answer, the router's WAN address, the packets, the gateway and the first hops). Every address on the
cards was read on 2026-11-11; the test `test_the_cards_pages_answer` asks each of them again when
`LIMINAL_VENDOR_PAGES=1` is set (it is skipped otherwise).

## Its hooks

`present` (always), `status` (the summary, the facts, `tables`, `charts`, `forms`, `actions`), `view(span)` (the
monitor's answer, the shape the charts app's `/api/resources` gives), `charts(span)` (the charts alone; `span`:
`recent` or `day`), `public_address()` (read now), `check_ports(ports, where, address)` (`where`: `internet`, `out`
or `both`; `address`, when given, must still be this network's), `choose_ports(ports)` (`liminal`, `web`, `mail`,
`remote`, `setting`, `chosen` or ports as typed), `refresh_ports()` (what listens, read now), `check_path(port, listen)`
(the way in, hop by hop, on a thread: the status's `paths` and the Traffic table follow it).

## Its setting

| Variable | Pair | What |
|---|---|---|
| `HW_STATS_PORTS` | `hw-stats-ports` | the ports listed and filled into Check ports; unset: Liminal's own |

## From the command line

```
python -m plugin_platform_hw_stats status
python -m plugin_platform_hw_stats charts day
python -m plugin_platform_hw_stats view
python -m plugin_platform_hw_stats ip
python -m plugin_platform_hw_stats ports
python -m plugin_platform_hw_stats ports 25 80 443 --where out
python -m plugin_platform_hw_stats path 8795 --no-listen
```

`status`, `view` and `charts` take two samples a second apart, so the rates are there. `ip` reads the public address
now. `ports` says what listens on each port here (the ports chosen unless given) and sends nothing; with `--where
internet`, `out` or `both` it checks them as the page does.
