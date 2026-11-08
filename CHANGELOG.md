# Changelog

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
