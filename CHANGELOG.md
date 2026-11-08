# Changelog

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
