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

## Its hooks

`present` (always), `status` (the summary, the facts, `tables`, `charts`), `view(span)` (the monitor's answer,
the shape the charts app's `/api/resources` gives), `charts(span)` (the charts alone; `span`: `recent` or
`day`).

## From the command line

```
python -m plugin_platform_hw_stats status
python -m plugin_platform_hw_stats charts day
python -m plugin_platform_hw_stats view
```

Each takes two samples a second apart, so the rates are there.
