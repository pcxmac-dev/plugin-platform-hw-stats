# plugin-platform-hw-stats

Hardware stats for Liminal: this machine's processor, memory, network, disks and data files, and every Liminal
app's processes, on Windows and Linux alike.

The user's words (2026-11-07): "i need the hardware monitoring that was in charts, it needs to be windows and
linux agnostic, ie it runs on both, the stats were on the charts app but they need a plugin too, hw-stats
platform plugin".

## What it does

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.1, its icon the gauge)
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
tables (the programs, the disks, the data folders).

## This network: its public address and its ports

The user (2026-11-08): "lets make sure platform hw stats is able to get the current public IP, and verify that
'selected' ports are available or blocked"; "there should be a way to check ports".

- **The public address**, IPv4 and IPv6: asked of OpenDNS's resolver (`myip.opendns.com` answers with the asker's
  address), else of Google's name server (`o-o.myaddr.l.google.com`), each asked directly; a public address only, so a
  machine without an IPv6 route says it has none. Read when the plugin is attached to the platform and every 15
  minutes while it is, and when asked (Read the public address again). Shown among the facts with whose answer it was.
- **The ports**: `HW_STATS_PORTS` (`25, 80, 443, 8765-8768`, at most 12), read through the platform's login (today
  the platform's EnvironmentLogin, so the variable; the user's own setting once the login app holds the plugins'
  settings); unset, Liminal's own pages' ports (8765, 8775, 8785, 8795, 8796). The Ports table says what listens on each
  here (the program, on every address or this machine only) and each one's last check.
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

Nothing on this machine is changed by a check. The services' hosts are this plugin's (`network.py`): the library
names none.

## Its hooks

`present` (always), `status` (the summary, the facts, `tables`, `charts`, `forms`, `actions`), `view(span)` (the
monitor's answer, the shape the charts app's `/api/resources` gives), `charts(span)` (the charts alone; `span`:
`recent` or `day`), `public_address()` (read now), `check_ports(ports, where, address)` (`where`: `internet`, `out`
or `both`; `address`, when given, must still be this network's).

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
```

`status`, `view` and `charts` take two samples a second apart, so the rates are there. `ip` reads the public address
now. `ports` says what listens on each port here (the ports chosen unless given) and sends nothing; with `--where
internet`, `out` or `both` it checks them as the page does.
