"""What the hardware stats attach to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): this machine's own interfaces (Windows' kernel32, ntdll and iphlpapi; Linux's /proc and
/sys), the system's ping, tracert or traceroute and nslookup, and the outside services this network is checked with
(OpenDNS's and Google's name servers for the public address, portchecker.io and check-host.net from the internet,
portquiz.net out, the router over UPnP, Npcap or libpcap for the packets), each as its makers' pages describe it. Every
address was read on 2026-11-11 (`VERIFIED`). The facts (the last address read, the last checks) are said by the
plugin's api_facts."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
WIN32 = "https://learn.microsoft.com/en-us/windows/win32/"
API = WIN32 + "api/"
MAN7 = "https://man7.org/linux/man-pages/"
KERNEL = "https://docs.kernel.org/"
COMMANDS = "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/"
UPNP = "https://upnp.org/specs/gw/"
PCAP = "https://www.tcpdump.org/manpages/"
PROJECT = "https://github.com/pcxmac-dev/plugin-platform-hw-stats/blob/main/"

WINDOWS = Api(
    name="Windows (kernel32, ntdll, iphlpapi)",
    maker="Microsoft",
    about=("The Win32 functions the library's sampler calls by ctypes on Windows: the processor's and memory's figures, "
           "every process with its times, memory, reads and writes and command line, each fixed drive's reads and "
           "writes, the network adapters' bytes, the TCP connections and their processes, the route out. It samples "
           "every 30 s, every 2 s while the page shows it, within 5% of one core, and only while the plugin is attached."),
    kind="system",
    base="kernel32.dll, ntdll.dll and iphlpapi.dll, through ctypes (the library's resources.WindowsProbe)",
    version="Windows 10 and 11",
    auth="the platform's Windows user: another user's process shows no command line where Windows refuses it",
    limits="",
    costs="",
    links=(
        Link("Programming reference for the Win32 API", API, "docs"),
        Link("Processes and threads", WIN32 + "procthread/processes-and-threads", "guide"),
        Link("IP Helper", WIN32 + "iphlp/ip-helper-start-page", "guide"),
        Link("GetSystemTimes", API + "processthreadsapi/nf-processthreadsapi-getsystemtimes", "reference"),
        Link("IOCTL_DISK_PERFORMANCE", API + "winioctl/ni-winioctl-ioctl_disk_performance", "reference"),
        Link("Performance counters", WIN32 + "perfctrs/performance-counters-portal", "guide"),
    ),
    areas=(
        Area("The processor and memory", "busy and idle time since boot; physical memory and the commit limit",
             API + "sysinfoapi/nf-sysinfoapi-globalmemorystatusex", covered="the CPU's share, memory used and committed"),
        Area("Processes", "each process: its name, times, memory, reads and writes, handles, command line",
             WIN32 + "procthread/processes-and-threads",
             covered="every Liminal app's processes: CPU, memory, reads and writes, threads and handles, by command line"),
        Area("Disks", "each fixed drive: its space, its reads and writes", API + "winioctl/ni-winioctl-ioctl_disk_performance",
             covered="space free, bytes read and written per second"),
        Area("Network adapters", "each adapter's state, speed and bytes in and out", API + "netioapi/nf-netioapi-getiftable2",
             covered="the hardware adapters that are up: bytes in and out, link speed"),
        Area("TCP connections", "each connection and listener with its process", API + "iphlpapi/nf-iphlpapi-getextendedtcptable",
             covered="Liminal's connections, the machine's established and listening, who listens on each port"),
        Area("Routes", "the route a packet to an address takes", API + "iphlpapi/nf-iphlpapi-getbestroute",
             covered="this computer's address on its network and its gateway (the path check)"),
        Area("UDP endpoints", "each UDP endpoint with its process", API + "iphlpapi/nf-iphlpapi-getextendedudptable"),
        Area("Performance counters", "Windows' named counters (PDH)", WIN32 + "perfctrs/performance-counters-portal"),
    ),
    calls=(
        Call("GetSystemTimes", "idle, kernel and user time since boot", "The processor and memory", used="the CPU's share",
             docs=API + "processthreadsapi/nf-processthreadsapi-getsystemtimes"),
        Call("GlobalMemoryStatusEx", "physical memory and the commit limit", "The processor and memory",
             used="memory used and committed", docs=API + "sysinfoapi/nf-sysinfoapi-globalmemorystatusex"),
        Call("CreateToolhelp32Snapshot", "a snapshot of every process", "Processes", used="each sample's processes",
             docs=API + "tlhelp32/nf-tlhelp32-createtoolhelp32snapshot"),
        Call("Process32FirstW", "the snapshot's first process", "Processes", used="each sample's processes",
             docs=API + "tlhelp32/nf-tlhelp32-process32firstw"),
        Call("Process32NextW", "the snapshot's next process", "Processes", used="each sample's processes",
             docs=API + "tlhelp32/nf-tlhelp32-process32nextw"),
        Call("OpenProcess", "a process opened to query it (limited information, memory read)", "Processes",
             used="each Liminal process", docs=API + "processthreadsapi/nf-processthreadsapi-openprocess"),
        Call("GetProcessTimes", "a process's start, kernel and user times", "Processes", used="its CPU",
             docs=API + "processthreadsapi/nf-processthreadsapi-getprocesstimes"),
        Call("K32GetProcessMemoryInfo", "a process's working set and private bytes", "Processes", used="its memory",
             docs=API + "psapi/nf-psapi-getprocessmemoryinfo"),
        Call("GetProcessIoCounters", "a process's bytes read and written", "Processes", used="its reads and writes",
             docs=API + "winbase/nf-winbase-getprocessiocounters"),
        Call("GetProcessHandleCount", "a process's open handles", "Processes", used="its handles",
             docs=API + "processthreadsapi/nf-processthreadsapi-getprocesshandlecount"),
        Call("NtQueryInformationProcess", "a process's command line (ProcessCommandLineInformation)", "Processes",
             used="which Liminal app a process is", docs=API + "winternl/nf-winternl-ntqueryinformationprocess"),
        Call("CloseHandle", "a handle closed", "Processes", used="after each query", docs=API + "handleapi/nf-handleapi-closehandle"),
        Call("GetLogicalDrives", "the drive letters there are", "Disks", used="each sample's drives",
             docs=API + "fileapi/nf-fileapi-getlogicaldrives"),
        Call("GetDriveTypeW", "a drive's type (fixed, removable, network)", "Disks", used="fixed drives only",
             docs=API + "fileapi/nf-fileapi-getdrivetypew"),
        Call("CreateFileW", "a volume opened, asking no access", "Disks", used="each fixed drive's reads and writes",
             docs=API + "fileapi/nf-fileapi-createfilew"),
        Call("DeviceIoControl IOCTL_DISK_PERFORMANCE", "a volume's bytes read and written so far", "Disks",
             used="each fixed drive's reads and writes", docs=API + "winioctl/ni-winioctl-ioctl_disk_performance"),
        Call("GetDiskFreeSpaceExW", "a drive's space and free space", "Disks", used="the Disks table (through Python's disk_usage)",
             docs=API + "fileapi/nf-fileapi-getdiskfreespaceexw"),
        Call("GetIfTable2", "every network interface's row (MIB_IF_ROW2)", "Network adapters", used="bytes in and out",
             docs=API + "netioapi/nf-netioapi-getiftable2"),
        Call("FreeMibTable", "the table freed", "Network adapters", used="after each read",
             docs=API + "netioapi/nf-netioapi-freemibtable"),
        Call("GetExtendedTcpTable", "the TCP table with each owner's process id (IPv4 and IPv6)", "TCP connections",
             used="the connections, and who listens on a port", docs=API + "iphlpapi/nf-iphlpapi-getextendedtcptable"),
        Call("GetBestRoute", "the route to an address", "Routes", used="this computer's address and gateway (the path check)",
             docs=API + "iphlpapi/nf-iphlpapi-getbestroute"),
        Call("GetExtendedUdpTable", "the UDP table with each owner's process id", "UDP endpoints",
             docs=API + "iphlpapi/nf-iphlpapi-getextendedudptable"),
        Call("PdhOpenQueryW", "a performance counter query", "Performance counters", docs=API + "pdh/nf-pdh-pdhopenqueryw"),
        Call("GetPerformanceInfo", "the system's memory and handle totals", "The processor and memory",
             docs=API + "psapi/nf-psapi-getperformanceinfo"),
    ),
    verified=VERIFIED,
)

LINUX = Api(
    name="Linux (/proc and /sys)",
    maker="the Linux kernel",
    about=("The files the kernel keeps of itself, which the library's sampler reads on Linux: the processor's times and "
           "memory, every process's times, memory, reads and writes, command line and open files, each disk's reads and "
           "writes, each network interface's bytes and speed, the TCP sockets, the routing table. The same cadence as on "
           "Windows: every 30 s, every 2 s while shown, only while the plugin is attached."),
    kind="kernel",
    base="/proc and /sys, read as files (the library's resources.LinuxProbe)",
    version="the proc(5) and sysfs files of current kernels",
    auth="the platform's user: another user's process shows no reads and writes or open files",
    limits="",
    costs="",
    links=(
        Link("proc(5)", MAN7 + "man5/proc.5.html", "reference"),
        Link("The /proc filesystem", KERNEL + "filesystems/proc.html", "docs"),
        Link("sysfs", KERNEL + "filesystems/sysfs.html", "docs"),
        Link("I/O statistics fields (/proc/diskstats)", KERNEL + "admin-guide/iostats.html", "reference"),
        Link("/proc/net/tcp", KERNEL + "networking/proc_net_tcp.html", "reference"),
        Link("/sys/class/net", "https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net", "spec"),
    ),
    areas=(
        Area("The processor and memory", "CPU times since boot, memory and swap", MAN7 + "man5/proc_stat.5.html",
             covered="the CPU's share, memory used and committed"),
        Area("Processes", "each process's times, status, reads and writes, command line, open files",
             MAN7 + "man5/proc_pid_stat.5.html",
             covered="every Liminal app's processes: CPU, memory, reads and writes, threads and files"),
        Area("Disks", "each block device's reads and writes", KERNEL + "admin-guide/iostats.html",
             covered="whole disks' bytes read and written per second"),
        Area("Network interfaces", "each interface's bytes, state, device and speed", "https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net",
             covered="the hardware interfaces that are up: bytes in and out, link speed"),
        Area("TCP sockets", "each socket's addresses and state, and the inode its process holds", KERNEL + "networking/proc_net_tcp.html",
             covered="the connections, and who listens on a port (by the processes' open files)"),
        Area("Routes", "the IPv4 routing table", MAN7 + "man5/proc_pid_net.5.html", covered="the gateway (the path check)"),
        Area("Load", "the load averages", MAN7 + "man5/proc_loadavg.5.html"),
        Area("Pressure", "the time tasks wait for CPU, memory and I/O (PSI)", KERNEL + "accounting/psi.html"),
    ),
    calls=(
        Call("/proc/stat", "CPU times since boot", "The processor and memory", used="the CPU's share",
             docs=MAN7 + "man5/proc_stat.5.html"),
        Call("/proc/meminfo", "memory and swap", "The processor and memory", used="memory used and committed",
             docs=MAN7 + "man5/proc_meminfo.5.html"),
        Call("/proc/<pid>/stat", "a process's times and state", "Processes", used="its CPU", docs=MAN7 + "man5/proc_pid_stat.5.html"),
        Call("/proc/<pid>/status", "a process's memory and threads", "Processes", used="its memory and threads",
             docs=MAN7 + "man5/proc_pid_status.5.html"),
        Call("/proc/<pid>/io", "a process's bytes read and written", "Processes", used="its reads and writes",
             docs=MAN7 + "man5/proc_pid_io.5.html"),
        Call("/proc/<pid>/cmdline", "a process's command line", "Processes", used="which Liminal app it is",
             docs=MAN7 + "man5/proc_pid_cmdline.5.html"),
        Call("/proc/<pid>/fd", "a process's open files and sockets", "Processes", used="its files; whose a socket is",
             docs=MAN7 + "man5/proc_pid_fd.5.html"),
        Call("/proc/<pid>/comm", "a process's program name", "Processes", used="a port's listener named",
             docs=MAN7 + "man5/proc_pid_comm.5.html"),
        Call("/proc/diskstats", "each block device's reads and writes", "Disks", used="the disks' reads and writes",
             docs=KERNEL + "admin-guide/iostats.html"),
        Call("/sys/block", "the whole disks (not their partitions)", "Disks", used="the disks counted",
             docs=KERNEL + "filesystems/sysfs.html"),
        Call("statvfs", "a file system's space and free space", "Disks", used="the Disks table (through Python's disk_usage)",
             docs=MAN7 + "man3/statvfs.3.html"),
        Call("/proc/net/dev", "each interface's bytes", "Network interfaces", used="bytes in and out",
             docs=MAN7 + "man5/proc_pid_net.5.html"),
        Call("/sys/class/net/<interface>/operstate, device, speed", "an interface's state, its hardware, its speed",
             "Network interfaces", used="the hardware interfaces that are up, the link speed",
             docs="https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net"),
        Call("/proc/net/tcp and /proc/net/tcp6", "the TCP sockets", "TCP sockets", used="the connections and the listeners",
             docs=KERNEL + "networking/proc_net_tcp.html"),
        Call("/proc/net/route", "the IPv4 routing table", "Routes", used="the gateway", docs=MAN7 + "man5/proc_pid_net.5.html"),
        Call("/proc/loadavg", "the load averages", "Load", docs=MAN7 + "man5/proc_loadavg.5.html"),
        Call("/proc/pressure/cpu, memory, io", "pressure stall information", "Pressure", docs=KERNEL + "accounting/psi.html"),
    ),
    verified=VERIFIED,
)

TOOLS = Api(
    name="ping, tracert or traceroute, and nslookup",
    maker="Microsoft (Windows' commands); iputils, traceroute and BIND on Linux",
    about=("The system's own network commands, run windowless: ping for one echo to the gateway, tracert (traceroute, "
           "else tracepath, on Linux) for the first three routers on the way to Cloudflare's 1.1.1.1 (this network's way "
           "out; only those three are asked), and nslookup to ask a name server directly for this network's public "
           "address. The path check and the public address use them."),
    kind="command",
    base="ping, tracert (traceroute, tracepath) and nslookup, windowless",
    version="Windows' own commands; on Linux iputils' ping and tracepath, traceroute, BIND's nslookup",
    auth="none: ordinary commands, no rights needed",
    limits="",
    costs="",
    links=(
        Link("ping (Windows)", COMMANDS + "ping", "reference"),
        Link("tracert (Windows)", COMMANDS + "tracert", "reference"),
        Link("nslookup (Windows)", COMMANDS + "nslookup", "reference"),
        Link("ping(8)", MAN7 + "man8/ping.8.html", "reference"),
        Link("traceroute(8)", MAN7 + "man8/traceroute.8.html", "reference"),
        Link("tracepath(8)", MAN7 + "man8/tracepath.8.html", "reference"),
        Link("BIND's manual pages (nslookup)", "https://bind9.readthedocs.io/en/latest/manpages.html", "docs"),
        Link("1.1.1.1 (Cloudflare)", "https://developers.cloudflare.com/1.1.1.1/", "guide"),
    ),
    areas=(
        Area("Echoes", "an ICMP echo and its round trip", COMMANDS + "ping", covered="the gateway's round trip (the path check)"),
        Area("The way out", "the routers on the way to an address, hop by hop", COMMANDS + "tracert",
             covered="the first three hops toward 1.1.1.1: a private address after the router means the ISP's NAT"),
        Area("Asking a name server", "a record asked of a server named, not the machine's resolver", COMMANDS + "nslookup",
             covered="this network's public address, asked of OpenDNS's and Google's servers (their cards)"),
        Area("Paths and their MTU", "the path's MTU found as it is traced", MAN7 + "man8/tracepath.8.html"),
    ),
    calls=(
        Call("ping -n 1 -w <ms> <host>", "one echo (Windows)", "Echoes", used="the gateway's round trip", docs=COMMANDS + "ping"),
        Call("ping -c 1 -W <s> <host>", "one echo (Linux)", "Echoes", used="the gateway's round trip", docs=MAN7 + "man8/ping.8.html"),
        Call("tracert -d -h 3 -w 700 1.1.1.1", "the first three hops (Windows)", "The way out", used="the router's way out",
             docs=COMMANDS + "tracert"),
        Call("traceroute -n -m 3 -q 1 -w 1 1.1.1.1", "the first three hops (Linux)", "The way out", used="the router's way out",
             docs=MAN7 + "man8/traceroute.8.html"),
        Call("tracepath -n -m 3 1.1.1.1", "the same, where traceroute is not there", "The way out", used="the router's way out",
             docs=MAN7 + "man8/tracepath.8.html"),
        Call("nslookup -type=<type> -timeout=3 -retry=1 <name> <server>", "a record asked of a server, directly",
             "Asking a name server", used="this network's public address", docs=COMMANDS + "nslookup"),
        Call("pathping <host>", "the hops with each one's loss (Windows)", "The way out", docs=COMMANDS + "pathping"),
    ),
    verified=VERIFIED,
)

OPENDNS = Api(
    name="OpenDNS (myip.opendns.com)",
    maker="Cisco (OpenDNS)",
    about=("OpenDNS's resolvers answer the name myip.opendns.com, asked of them directly, with the asker's own public "
           "address: an A record over IPv4, an AAAA record over IPv6. The plugin asks resolver1 (208.67.222.222, and "
           "2620:119:35::35 over IPv6) for this network's public address when it is attached, every 15 minutes while it "
           "is, and when you ask. OpenDNS documents the resolvers, not this name."),
    kind="dns",
    base="nslookup -type=a myip.opendns.com 208.67.222.222; -type=aaaa at 2620:119:35::35",
    version="OpenDNS's public resolvers (208.67.222.222, 208.67.220.220)",
    auth="none: a public DNS question",
    limits="none published; the plugin asks once an IP version every 15 minutes while it is attached, and when you ask",
    costs="",
    links=(
        Link("OpenDNS's setup guide (its resolvers' addresses)", "https://www.opendns.com/setupguide/", "guide"),
        Link("OpenDNS", "https://www.opendns.com/", "docs"),
        Link("OpenDNS's support", "https://www.opendns.com/support/", "guide"),
        Link("Cisco Umbrella's status", "https://status.umbrella.cisco.com/", "status"),
        Link("OpenDNS's terms", "https://www.opendns.com/consumer-terms/", "terms"),
        Link("OpenDNS's privacy policy", "https://www.opendns.com/privacy-policy/", "terms"),
    ),
    areas=(
        Area("The asker's own address", "myip.opendns.com, answered with the address the question came from",
             "https://www.opendns.com/setupguide/", covered="this network's public IPv4 and IPv6 address"),
        Area("Its resolvers", "public resolvers anyone may use, with filtering for accounts", "https://www.opendns.com/setupguide/"),
        Area("FamilyShield", "resolvers that block adult content (208.67.222.123, 208.67.220.123)", "https://www.opendns.com/setupguide/"),
        Area("Accounts and filtering", "a network's own filtering, set up on its dashboard", "https://www.opendns.com/support/"),
    ),
    calls=(
        Call("nslookup -type=a myip.opendns.com 208.67.222.222", "the asker's IPv4 address", "The asker's own address",
             used="this network's public IPv4 address (asked first)", docs="https://www.opendns.com/setupguide/"),
        Call("nslookup -type=aaaa myip.opendns.com 2620:119:35::35", "the asker's IPv6 address, asked over IPv6",
             "The asker's own address", used="this network's public IPv6 address (asked first)"),
        Call("nslookup <name> 208.67.222.222", "any name resolved by OpenDNS", "Its resolvers",
             docs="https://www.opendns.com/setupguide/"),
    ),
    verified=VERIFIED,
)

GOOGLE = Api(
    name="Google's name servers (o-o.myaddr.l.google.com)",
    maker="Google",
    about=("Google's own name servers (ns1.google.com) answer the text record of o-o.myaddr.l.google.com with the "
           "address the question came from. The plugin asks them when OpenDNS gives no public address. Google documents "
           "no page for this name; its Public DNS pages, linked here, cover its DNS service and its terms."),
    kind="dns",
    base="nslookup -type=txt o-o.myaddr.l.google.com 216.239.32.10 (ns1.google.com; 2001:4860:4802:32::a over IPv6)",
    version="Google's authoritative servers for google.com",
    auth="none: a public DNS question",
    limits="none published; asked only when OpenDNS gives no public address",
    costs="",
    links=(
        Link("Google Public DNS", "https://developers.google.com/speed/public-dns", "docs"),
        Link("Google Public DNS: frequently asked questions", "https://developers.google.com/speed/public-dns/faq", "guide"),
        Link("Google Public DNS: DNS over HTTPS (JSON)", "https://developers.google.com/speed/public-dns/docs/doh/json", "reference"),
        Link("Google Public DNS's terms", "https://developers.google.com/speed/public-dns/terms", "terms"),
        Link("Google Public DNS's privacy", "https://developers.google.com/speed/public-dns/privacy", "terms"),
    ),
    areas=(
        Area("The asker's own address", "o-o.myaddr.l.google.com's text record, asked of ns1.google.com directly",
             covered="this network's public IPv4 and IPv6 address, when OpenDNS gives none"),
        Area("Google Public DNS", "the public resolvers (8.8.8.8, 8.8.4.4)", "https://developers.google.com/speed/public-dns/docs/using"),
        Area("DNS over HTTPS", "names resolved over HTTPS, as JSON too", "https://developers.google.com/speed/public-dns/docs/doh"),
    ),
    calls=(
        Call("nslookup -type=txt o-o.myaddr.l.google.com 216.239.32.10", "the asker's address, in a text record",
             "The asker's own address", used="this network's public IPv4 address, when OpenDNS gives none"),
        Call("nslookup -type=txt o-o.myaddr.l.google.com 2001:4860:4802:32::a", "the same, asked over IPv6",
             "The asker's own address", used="this network's public IPv6 address, when OpenDNS gives none"),
        Call("GET https://dns.google/resolve?name=<name>&type=<type>", "a name resolved over HTTPS, as JSON",
             "DNS over HTTPS", docs="https://developers.google.com/speed/public-dns/docs/doh/json"),
    ),
    verified=VERIFIED,
)

PORTCHECKER = Api(
    name="portchecker.io",
    maker="portchecker.io (open source, by dsgnr)",
    about=("portchecker.io checks from its own server whether a port answers at an address; asked for \"me\", it checks "
           "the asker's own address, the one it sees the question come from. The path check asks it first for the port "
           "being checked, after making sure it sees this network as its public address. It cannot tell a refusal from no "
           "answer: a port not open reads blocked until the packets say more."),
    kind="rest",
    base="https://portchecker.io/api",
    version="its API 4.1.0 (docs/openapi.json)",
    auth="none",
    limits="none published; the plugin asks it one port at a time, only when you check a port's way in",
    costs="",
    links=(
        Link("portchecker.io's API", "https://portchecker.io/docs", "reference"),
        Link("Its OpenAPI specification", "https://portchecker.io/docs/openapi.json", "spec"),
        Link("portchecker.io", "https://portchecker.io", "docs"),
        Link("Its source", "https://github.com/dsgnr/portchecker.io", "source"),
    ),
    areas=(
        Area("The asker's address", "the address it sees a question come from", "https://portchecker.io/docs",
             covered="checked to be this network's public address before a port is asked"),
        Area("One port", "one port at an address (me: the asker's)", "https://portchecker.io/docs",
             covered="the port being checked, from the internet (the path check)"),
        Area("Several ports", "many ports of an address in one question", "https://portchecker.io/docs"),
        Area("Its health and metrics", "whether it answers; its own figures", "https://portchecker.io/docs"),
    ),
    calls=(
        Call("GET /api/me", "the address it sees the question come from", "The asker's address",
             used="this network's public address, as it sees it", docs="https://portchecker.io/docs"),
        Call("GET /api/me/<port>", "whether a port answers at the asker's address (True or False)", "One port",
             used="the path check, first", docs="https://portchecker.io/docs"),
        Call("GET /api/<host>/<port>", "whether a port answers at an address", "One port", docs="https://portchecker.io/docs"),
        Call("POST /api/query", "several ports of an address at once", "Several ports", docs="https://portchecker.io/docs"),
        Call("GET /healthz", "whether it answers", "Its health and metrics", docs="https://portchecker.io/docs"),
    ),
    verified=VERIFIED,
)

CHECK_HOST = Api(
    name="check-host.net",
    maker="check-host.net",
    about=("check-host.net checks a host from its servers in many countries: TCP, ping, HTTP, DNS and UDP, a check started "
           "and its answers asked for after. The plugin asks three of its servers to connect to this network's public "
           "address on each port you check from the internet (and the path check asks it when portchecker.io cannot "
           "tell); only this network's own address is ever sent."),
    kind="rest",
    base="https://check-host.net (Accept: application/json)",
    version="its API page as it reads now",
    auth="none",
    limits=("not published: it answers limit_exceeded (or HTTP 429) when asked too often, as it answered this PC on "
            "2026-11-08; the plugin then asks it nothing more in that check"),
    costs="",
    links=(
        Link("check-host.net's API", "https://check-host.net/about/api", "reference"),
        Link("check-host.net", "https://check-host.net/", "docs"),
        Link("Its FAQ", "https://check-host.net/about/faq", "guide"),
        Link("Its servers", "https://check-host.net/nodes/hosts", "tool"),
    ),
    areas=(
        Area("TCP checks", "a connection to host:port from its servers", "https://check-host.net/about/api",
             covered="each port checked from the internet, from three servers"),
        Area("Results", "each server's answer, asked for until each has one", "https://check-host.net/about/api",
             covered="open, closed, blocked or failed, from the servers' answers"),
        Area("Ping, HTTP, DNS and UDP checks", "the other kinds of check", "https://check-host.net/about/api"),
        Area("Its servers", "the servers it checks from, and where they are", "https://check-host.net/nodes/hosts",
             covered="each answer said with its server's place"),
    ),
    calls=(
        Call("GET /check-tcp?host=<address>:<port>&max_nodes=3", "a TCP check started from three servers", "TCP checks",
             used="Check ports, from the internet; the path check when portchecker.io cannot tell",
             docs="https://check-host.net/about/api"),
        Call("GET /check-result/<request id>", "the servers' answers so far", "Results", used="asked until each server answers",
             docs="https://check-host.net/about/api"),
        Call("GET /check-ping?host=<host>", "a ping check", "Ping, HTTP, DNS and UDP checks", docs="https://check-host.net/about/api"),
        Call("GET /check-http?host=<url>", "an HTTP check", "Ping, HTTP, DNS and UDP checks", docs="https://check-host.net/about/api"),
        Call("GET /check-result-extended/<request id>", "the answers with the check's command and host", "Results",
             docs="https://check-host.net/about/api"),
        Call("GET /nodes/hosts", "its servers", "Its servers", docs="https://check-host.net/nodes/hosts"),
    ),
    verified=VERIFIED,
)

PORTQUIZ = Api(
    name="portquiz.net",
    maker="portquiz.net",
    about=("portquiz.net is a server that listens on every TCP port, so a connection to it on a port shows whether that "
           "port gets out of this network. The plugin connects to it on each port you check out from this machine, its "
           "port 80 first (when even that fails, nothing is said of the others). Its own page, http://portquiz.net, has no "
           "HTTPS address, so it is named here, not linked; the plugin's own pages say how it is used."),
    kind="socket",
    base="TCP connections to portquiz.net:<port> from this machine (no request inside them)",
    version="its server as it answers now",
    auth="none",
    limits="none published; the plugin connects eight ports at a time at most, only when you check",
    costs="",
    links=(
        Link("How the plugin checks a port out (its README)", PROJECT + "README.md", "guide"),
        Link("The plugin's network services (network.py)", PROJECT + "src/plugin_platform_hw_stats/network.py", "source"),
    ),
    areas=(
        Area("A port out", "a TCP connection on any port: it answers on all of them", PROJECT + "README.md",
             covered="each port checked out from this machine: open, closed (refused) or blocked (no answer)"),
        Area("A web page on any port", "its page answered over HTTP on whatever port is asked"),
    ),
    calls=(
        Call("TCP connect portquiz.net:80", "the control: whether it can be reached at all", "A port out",
             used="first, before the ports asked"),
        Call("TCP connect portquiz.net:<port>", "one port out", "A port out", used="Check ports, out from this machine"),
        Call("GET http://portquiz.net:<port>/", "its page on a port", "A web page on any port"),
    ),
    verified=VERIFIED,
)

UPNP_IGD = Api(
    name="UPnP Internet Gateway Device",
    maker="the Open Connectivity Foundation (UPnP)",
    about=("A home router that speaks UPnP answers a search on its network (SSDP), describes itself, and tells its WAN "
           "address over a SOAP action; IGD also lets programs open ports on it. The path check asks the router on this "
           "network only, and only its WAN address: a private one means the ISP's NAT (CGNAT) stands in front of it."),
    kind="xml",
    base="SSDP to 239.255.255.250:1900 (UDP), then SOAP over plain HTTP to the router's own address on this network",
    version="InternetGatewayDevice:1 (WANIPConnection and WANPPPConnection)",
    auth="none: whatever on this network asks, the router answers",
    limits="",
    costs="",
    links=(
        Link("UPnP standards and architecture", "https://openconnectivity.org/developer/specifications/upnp-resources/upnp/", "docs"),
        Link("Internet Gateway Device v2", "https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/",
             "reference"),
        Link("UPnP Device Architecture 2.0", "https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf", "spec"),
        Link("InternetGatewayDevice:1", UPNP + "UPnP-gw-InternetGatewayDevice-v1-Device.pdf", "spec"),
        Link("WANIPConnection:1", UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf", "spec"),
        Link("WANPPPConnection:1", UPNP + "UPnP-gw-WANPPPConnection-v1-Service.pdf", "spec"),
        Link("WANIPConnection:2", UPNP + "UPnP-gw-WANIPConnection-v2-Service.pdf", "spec"),
    ),
    areas=(
        Area("Discovery (SSDP)", "a search sent to the network's multicast address, answered with each device's description",
             "https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf",
             covered="the router found on this network (its description only from a private address)"),
        Area("Description", "the device's XML: its services and their control addresses",
             "https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf",
             covered="its WANIPConnection or WANPPPConnection service found"),
        Area("The WAN connection", "the connection's state and its external address", UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf",
             covered="its external (WAN) address"),
        Area("Port mappings", "ports opened on the router for a computer, and closed", UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf"),
        Area("IPv6 pinholes", "IPv6 firewall openings (WANIPv6FirewallControl)", UPNP + "UPnP-gw-WANIPv6FirewallControl-v1-Service.pdf"),
    ),
    calls=(
        Call("M-SEARCH * (ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1)", "a search for gateways", "Discovery (SSDP)",
             used="the path check: the router's location",
             docs="https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf"),
        Call("GET <location>", "the router's description", "Description", used="its WAN connection service and control address",
             docs="https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf"),
        Call("POST <controlURL> GetExternalIPAddress", "the WAN's external address", "The WAN connection",
             used="the router's WAN address (the path check)", docs=UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf"),
        Call("POST <controlURL> GetStatusInfo", "the connection's state and uptime", "The WAN connection",
             docs=UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf"),
        Call("POST <controlURL> AddPortMapping", "a port opened on the router", "Port mappings",
             docs=UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf", writes=True),
        Call("POST <controlURL> DeletePortMapping", "a port mapping removed", "Port mappings",
             docs=UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf", writes=True),
        Call("POST <controlURL> GetGenericPortMappingEntry", "the router's port mappings, one by one", "Port mappings",
             docs=UPNP + "UPnP-gw-WANIPConnection-v1-Service.pdf"),
    ),
    verified=VERIFIED,
)

CAPTURE = Api(
    name="Npcap and libpcap",
    maker="Nmap Software (Npcap) and the Tcpdump Group (libpcap)",
    about=("The packet capture library: an adapter opened, a filter compiled and set, each packet read as it arrives, "
           "before the machine's firewall decides. The library calls it by ctypes, no package between: Npcap's wpcap.dll "
           "on Windows (installed with Wireshark or on its own), the system's libpcap on Linux. The path check watches "
           "the checked port's TCP packets with it (their addresses, ports and flags; never their payload)."),
    kind="sdk",
    base=r"wpcap.dll from %SystemRoot%\System32\Npcap (Windows), libpcap (Linux), through ctypes (the library's capture.py)",
    version="Npcap 1.90 (2026-10-21) and libpcap's pcap API",
    auth="Npcap: any user unless it was installed for administrators only; libpcap: root or CAP_NET_RAW",
    limits="",
    costs=("Npcap's free license allows five installs (with a few exceptions, such as with Nmap or Wireshark); more, or "
           "redistributing it, needs a paid Npcap OEM license; libpcap costs nothing"),
    links=(
        Link("Npcap", "https://npcap.com/", "docs"),
        Link("The Npcap guide", "https://npcap.com/guide/", "guide"),
        Link("Npcap's API (pcap)", "https://npcap.com/guide/wpcap/pcap.html", "reference"),
        Link("pcap(3PCAP)", PCAP + "pcap.3pcap.html", "reference"),
        Link("pcap-filter(7)", PCAP + "pcap-filter.7.html", "reference"),
        Link("Npcap's changes", "https://npcap.com/changelog", "changelog"),
        Link("Npcap OEM", "https://npcap.com/oem/", "pricing"),
        Link("Npcap's license", "https://github.com/nmap/npcap/blob/master/LICENSE", "terms"),
        Link("libpcap's source", "https://github.com/the-tcpdump-group/libpcap", "source"),
    ),
    areas=(
        Area("Adapters", "the devices packets can be read from, and their addresses", PCAP + "pcap_findalldevs.3pcap.html",
             covered="the adapter holding this computer's address on its network"),
        Area("Opening a capture", "an adapter opened, how much of each packet kept", PCAP + "pcap_open_live.3pcap.html",
             covered="the headers alone (128 bytes), not in promiscuous mode"),
        Area("Filters", "BPF filters compiled from words and set", PCAP + "pcap-filter.7.html",
             covered="TCP on the port checked, to or from this computer"),
        Area("Reading packets", "each packet as it arrives, with its time", PCAP + "pcap_next_ex.3pcap.html",
             covered="addresses, ports and flags of each, while the check runs"),
        Area("Writing a capture", "packets saved to a file Wireshark reads", PCAP + "pcap_dump_open.3pcap.html"),
        Area("The newer way to open", "pcap_create, then options, then pcap_activate", PCAP + "pcap_create.3pcap.html"),
    ),
    calls=(
        Call("pcap_findalldevs", "every capture device", "Adapters", used="the adapter holding the address",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_freealldevs", "the device list freed", "Adapters", used="after the adapter is found",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_open_live", "a device opened for capture", "Opening a capture", used="the path check's capture",
             docs=PCAP + "pcap_open_live.3pcap.html"),
        Call("pcap_compile", "a filter compiled", "Filters", used="TCP on the port checked", docs=PCAP + "pcap_compile.3pcap.html"),
        Call("pcap_setfilter", "the filter set", "Filters", used="the same", docs=PCAP + "pcap_setfilter.3pcap.html"),
        Call("pcap_freecode", "the compiled filter freed", "Filters", used="once it is set", docs=PCAP + "pcap_freecode.3pcap.html"),
        Call("pcap_datalink", "the link layer's type", "Reading packets", used="where each packet's IP header starts",
             docs=PCAP + "pcap_datalink.3pcap.html"),
        Call("pcap_next_ex", "the next packet", "Reading packets", used="each packet while the check runs",
             docs=PCAP + "pcap_next_ex.3pcap.html"),
        Call("pcap_geterr", "the last error in words", "Reading packets", used="why packets could not be watched",
             docs=PCAP + "pcap_geterr.3pcap.html"),
        Call("pcap_close", "the capture closed", "Opening a capture", used="when the check ends", docs=PCAP + "pcap_close.3pcap.html"),
        Call("pcap_loop", "packets handed to a callback", "Reading packets", docs=PCAP + "pcap_loop.3pcap.html"),
        Call("pcap_dump_open", "a capture file opened for writing", "Writing a capture", docs=PCAP + "pcap_dump_open.3pcap.html"),
        Call("pcap_create", "a capture handle made, not yet active", "The newer way to open", docs=PCAP + "pcap_create.3pcap.html"),
    ),
    verified=VERIFIED,
)

APIS = (WINDOWS, LINUX, TOOLS, OPENDNS, GOOGLE, PORTCHECKER, CHECK_HOST, PORTQUIZ, UPNP_IGD, CAPTURE)
