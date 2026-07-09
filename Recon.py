#!/usr/bin/env python3
"""
Recon.py v2.1 — Automated Nmap Recon Pipeline
──────────────────────────────────────────────
Modes:
  1. Single Target           — standard scan against one host
  2. Single Target (Pivot)   — scan through Ligolo-ng tunnel
  3. Network Range           — discover + scan a network range
  4. Network Range (Pivot)   — discover + scan through Ligolo-ng tunnel

Workflow:  UDP (background) → deep top-1000 → full sweep → new-port deep scan
           (Network mode: fping+nmap discovery → sweep → interactive host
            selection → per-host AUTHORITATIVE deep scan)

Reliability model (v2.1):
  * Discovery unions a fast fping (ICMP) pass with nmap's thorough pass, so a
    host that only answers one of them is never silently dropped.
  * Every discovered host is selectable — even ones the fast sweep reported
    zero ports on.
  * Each host you pick is re-scanned INDEPENDENTLY (careful top-1000 + a full
    -p- re-sweep with no --min-rate), so a port the fast aggregate sweep drops
    (the classic "3306 vanished" bug) is caught per host.

Usage:  sudo python3 Recon.py
"""

import subprocess, sys, os, re, signal, time, shutil, ipaddress, curses
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich import box
except ImportError:
    print("\n[!] Missing 'rich' library.")
    print("    Install with:  pip install rich --break-system-packages\n")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════
console = Console()

UDP_PORTS = "53,69,111,123,137,161,500,623,1434"

UDP_HINTS = {
    53: ("DNS", "dig axfr, dnsenum, dnsrecon, fierce",
         "attempt zone transfers and brute-force subdomains — leaked records can reveal internal hosts"),
    69: ("TFTP", "tftp, atftp, nmap tftp-enum",
         "grab files blindly (no auth!) — look for config files, boot images, anything juicy"),
    111: ("RPCbind", "rpcinfo -p, showmount -e, nmap nfs-ls/nfs-showmount",
          "list RPC services and check for NFS shares you can mount — easy wins if exports are open"),
    123: ("NTP", "ntpq -c readlist, ntpdc -c monlist, nmap ntp-monlist",
          "check for monlist amplification and peer info — can leak internal IPs and hostnames"),
    137: ("NetBIOS-NS", "nbtscan, nmblookup, nmap nbstat",
          "enumerate NetBIOS names, domain info, and logged-in users — quick wins for domain context"),
    161: ("SNMP", "snmpwalk -v2c -c public, onesixtyone, snmp-check, snmpbulkwalk",
          "enumerate users, processes, installed software, network interfaces — look for creds and cleartext strings"),
    500: ("IKE/IPsec", "ike-scan -M, strongswan, ikeforce",
          "fingerprint the VPN and test aggressive mode — you might capture a pre-shared key to crack"),
    623: ("IPMI/BMC", "ipmitool, metasploit ipmi_dumphashes, nmap ipmi-version",
          "dump RAKP hashes (crackable offline), try default creds (ADMIN/ADMIN) — can lead to remote KVM"),
    1434: ("MS-SQL Browser", "nmap ms-sql-info, msfconsole mssql_ping, sqsh",
           "discover hidden SQL Server instances and their TCP ports — then pivot to TCP for the real attack"),
}

# ─── Reliability toggle ──────────────────────────────────────────────────────
# When True, each host you pick for a deep scan gets its OWN full -p- re-sweep
# (default adaptive timing, NO --min-rate) before the script/version scan, making
# per-host results authoritative and independent of the fast aggregate sweep.
# Costs one extra single-host full scan per SELECTED host (you only pay it for
# hosts you care about). Set False to trust the aggregate sweep for ports beyond
# the top-1000. Either way, the top-1000 is always deep-scanned independently, so
# common ports (SSH/HTTP/MySQL-3306/RDP/...) can never be missed.
VERIFY_HOSTS_WITH_FULL_SWEEP = True

# Nmap default top-1000 TCP ports (for diff against full sweep)
TOP_1000 = {
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,
    79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,
    146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,
    406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,
    541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,
    683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,
    880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,
    1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,
    1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,
    1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,
    1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,
    1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,
    1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,
    1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,
    1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,
    1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,
    1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,
    1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,
    1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,
    1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,
    2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,
    2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,
    2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,
    2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,
    2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,
    2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,
    3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,
    3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,
    3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,
    3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,
    3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,
    4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,
    4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,
    5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,
    5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,
    5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,
    5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,
    5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,
    6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,
    6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,
    6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,
    7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,
    7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,
    8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,
    8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,
    8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,
    9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,
    9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,
    9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,
    9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,
    10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,
    12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,
    15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,
    18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,
    20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,
    27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,
    32775,32776,32777,32778,32779,32780,32787,32801,32826,32976,33354,33899,34571,34572,
    34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,
    49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,
    49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,
    52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,
    58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389,
}

# TCP ports used for host discovery in pivot mode (no ICMP available)
# Covers: Linux (21,22,80,443,8080,8443), Windows (135,139,445,3389,5985),
#         Active Directory DCs (53,88,389), databases (1433)
PIVOT_DISCOVERY_PORTS = "21,22,53,80,88,135,139,389,443,445,1433,3389,5985,8080,8443"

# ─── Colors / Theming ───────────────────────────────────────────────────────
C_PHASE = "bold cyan"
C_OK    = "bold green"
C_WARN  = "bold yellow"
C_ERR   = "bold red"
C_DIM   = "dim white"
C_PORT  = "bold magenta"
C_INFO  = "bold blue"
C_HINT  = "bold yellow"
C_SVC   = "bold white"
C_PIVOT = "bold red"

# ═══════════════════════════════════════════════════════════════════════════
#  CURSES MENUS — arrow-key interactive selection
# ═══════════════════════════════════════════════════════════════════════════

def _init_colors():
    """Initialize curses color pairs."""
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)     # selected / accent
    curses.init_pair(2, curses.COLOR_WHITE, -1)     # normal text
    curses.init_pair(3, curses.COLOR_GREEN, -1)     # completed / success
    curses.init_pair(4, curses.COLOR_YELLOW, -1)    # warning
    curses.init_pair(5, curses.COLOR_RED, -1)       # pivot accent
    try:
        curses.init_pair(6, 8, -1)                  # dim gray (if supported)
    except curses.error:
        curses.init_pair(6, curses.COLOR_WHITE, -1)


BANNER_LINES = [
    r"  ╦═╗╔═╗╔═╗╔═╗╔╗╔",
    r"  ╠╦╝║╣ ║  ║ ║║║║",
    r"  ╩╚═╚═╝╚═╝╚═╝╝╚╝  v2.1",
    "",
    "  Automated Nmap Recon Pipeline",
    "  By Soel Kwun",
]


def curses_select_mode():
    """Mode selection screen with banner. Returns mode index (0-3) or -1 for exit."""
    modes = [
        ("Single Target",            "Standard scan against one host"),
        ("Single Target  [PIVOT]",   "Scan through active Ligolo-ng tunnel (--unprivileged, no min-rate)"),
        ("Network Range",            "fping+nmap discovery, then scan a network range"),
        ("Network Range  [PIVOT]",   "Discover and scan through active Ligolo-ng tunnel"),
    ]

    def _run(stdscr):
        curses.curs_set(0)
        _init_colors()
        selected = 0

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            y = 1

            # Banner
            for line in BANNER_LINES:
                try:
                    stdscr.addnstr(y, 0, line, w - 1, curses.color_pair(1) | curses.A_BOLD)
                except curses.error:
                    pass
                y += 1

            y += 1
            try:
                stdscr.addnstr(y, 2, "Select Scan Mode", w - 3, curses.color_pair(1) | curses.A_BOLD)
                y += 1
                stdscr.addnstr(y, 2, "-" * 20, w - 3, curses.color_pair(6))
            except curses.error:
                pass
            y += 1

            for i, (label, desc) in enumerate(modes):
                y += 1
                if y >= h - 3:
                    break
                is_pivot = "[PIVOT]" in label
                try:
                    if i == selected:
                        attr = curses.color_pair(5 if is_pivot else 1) | curses.A_BOLD
                        stdscr.addnstr(y, 2, "> ", w - 3, attr)
                        stdscr.addnstr(y, 4, label, w - 5, attr)
                        if y + 1 < h - 2:
                            stdscr.addnstr(y + 1, 6, desc, w - 7, curses.color_pair(6))
                    else:
                        attr = curses.color_pair(5 if is_pivot else 2)
                        stdscr.addnstr(y, 2, "  ", w - 3, attr)
                        stdscr.addnstr(y, 4, label, w - 5, attr)
                        if y + 1 < h - 2:
                            stdscr.addnstr(y + 1, 6, desc, w - 7, curses.color_pair(6))
                except curses.error:
                    pass
                y += 1

            y += 2
            try:
                stdscr.addnstr(min(y, h - 1), 2, "[Up/Down] Navigate   [Enter] Select   [q] Quit",
                               w - 3, curses.color_pair(6))
            except curses.error:
                pass

            stdscr.refresh()
            key = stdscr.getch()

            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(modes) - 1, selected + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return selected
            elif key in (ord('q'), ord('Q'), 27):
                return -1

    try:
        return curses.wrapper(_run)
    except KeyboardInterrupt:
        return -1


def curses_select_minrate():
    """Min-rate selection. Returns int (0 = disabled)."""
    options = [
        ("None  (disabled — most reliable, matches nmap defaults)", 0),
        ("500   (careful — production / client networks)", 500),
        ("2000  (standard — CTF exams: OSCP, CPTS)",      2000),
        ("4000  (aggressive — HTB / fast labs ONLY; can drop ports)", 4000),
    ]

    def _run(stdscr):
        curses.curs_set(0)
        _init_colors()
        selected = 2  # default to 2000

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            y = 1

            try:
                stdscr.addnstr(y, 2, "Select --min-rate for full port sweep (P2)",
                               w - 3, curses.color_pair(1) | curses.A_BOLD)
                y += 1
                stdscr.addnstr(y, 2, "-" * 44, w - 3, curses.color_pair(6))
            except curses.error:
                pass
            y += 2

            for i, (label, _) in enumerate(options):
                if y >= h - 4:
                    break
                try:
                    if i == selected:
                        stdscr.addnstr(y, 2, "> " + label, w - 3,
                                       curses.color_pair(1) | curses.A_BOLD)
                    else:
                        stdscr.addnstr(y, 2, "  " + label, w - 3, curses.color_pair(2))
                except curses.error:
                    pass
                y += 1

            y += 1
            try:
                stdscr.addnstr(y, 2, "Higher = faster but likelier to drop a SYN/ACK and miss a port.",
                               w - 3, curses.color_pair(6))
                y += 1
                stdscr.addnstr(y, 2, "In network mode, each host you pick is re-swept with no rate limit.",
                               w - 3, curses.color_pair(6))
            except curses.error:
                pass

            y += 2
            try:
                stdscr.addnstr(min(y, h - 1), 2, "[Up/Down] Navigate   [Enter] Select",
                               w - 3, curses.color_pair(6))
            except curses.error:
                pass

            stdscr.refresh()
            key = stdscr.getch()

            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(options) - 1, selected + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return options[selected][1]

    try:
        return curses.wrapper(_run)
    except KeyboardInterrupt:
        sys.exit(130)


def curses_select_host(hosts_ports: dict, completed: set):
    """
    Interactive host selector for network mode.
    hosts_ports: {ip: set_of_open_ports}
    completed:   set of IPs already scanned
    Returns: selected IP string, or None to quit.
    """
    sorted_hosts = sorted(hosts_ports.keys(), key=lambda x: ipaddress.IPv4Address(x))
    if not sorted_hosts:
        return None

    def _format_ports_lines(ports, avail_width):
        """Format port list into up to 2 lines that fit within avail_width each.
        Returns (line1, line2) where line2 may be empty."""
        s = sorted(ports)
        if not s:
            return "(none in sweep — will re-verify)", ""
        line1 = ""
        cutoff = None
        for i, p in enumerate(s):
            addition = str(p) if i == 0 else f", {p}"
            remaining = len(s) - (i + 1)
            reserve = 5 if remaining > 0 else 0
            if len(line1) + len(addition) + reserve > avail_width and i > 0:
                cutoff = i
                break
            line1 += addition
        if cutoff is None:
            return line1, ""
        # Build line2 from remaining ports
        leftover = s[cutoff:]
        line2 = ""
        for i, p in enumerate(leftover):
            addition = str(p) if i == 0 else f", {p}"
            remaining = len(leftover) - (i + 1)
            reserve = 5 if remaining > 0 else 0
            if len(line2) + len(addition) + reserve > avail_width and i > 0:
                line2 += ", ..."
                return line1, line2
            line2 += addition
        return line1, line2

    def _run(stdscr):
        curses.curs_set(0)
        _init_colors()
        selected = 0
        scroll = 0

        # Skip to first non-completed host by default
        for i, ip in enumerate(sorted_hosts):
            if ip not in completed:
                selected = i
                break

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()

            # Header
            total = len(sorted_hosts)
            done  = len(completed & set(sorted_hosts))
            try:
                stdscr.addnstr(1, 2, f"Select Target for Deep Scan  ({done}/{total} completed)",
                               w - 3, curses.color_pair(1) | curses.A_BOLD)
                stdscr.addnstr(2, 2, "-" * 50, w - 3, curses.color_pair(6))
            except curses.error:
                pass

            # Scrollable list — 2 rows per host (line1: IP + ports, line2: overflow ports)
            ROWS_PER_HOST = 2
            list_start_y = 4
            visible_rows = h - list_start_y - 3  # leave room for footer
            visible = max(1, visible_rows // ROWS_PER_HOST)

            # Adjust scroll
            if selected < scroll:
                scroll = selected
            if selected >= scroll + visible:
                scroll = selected - visible + 1

            # Column where "ports: " value starts (for line2 alignment)
            # "> " (2) + IP (16) + " -- " (4) + "NNN ports: " (11) = 33 from col 4
            indent2 = 4 + 16 + 4 + 11  # = 35

            for idx in range(scroll, min(scroll + visible, total)):
                y = list_start_y + (idx - scroll) * ROWS_PER_HOST
                ip = sorted_hosts[idx]
                ports = hosts_ports[ip]
                is_done = ip in completed
                count = len(ports)

                # Available width for port list on each line
                prefix_len = 35
                done_suffix_len = 9 if is_done else 0
                port_avail = max(10, w - 4 - prefix_len - done_suffix_len - 1)
                port_avail2 = max(10, w - indent2 - 1)
                port_line1, port_line2 = _format_ports_lines(ports, port_avail)

                # If line2 overflows its own width, re-truncate
                if port_line2 and len(port_line2) > port_avail2:
                    port_line2 = port_line2[:port_avail2 - 4] + " ..."

                try:
                    if is_done:
                        marker = "[DONE] "
                        if idx == selected:
                            stdscr.addnstr(y, 2, "> ", w - 3, curses.color_pair(3) | curses.A_BOLD)
                            line = f"{ip:<16} -- {count:>3} ports: {port_line1}  {marker}"
                            stdscr.addnstr(y, 4, line, w - 5, curses.color_pair(3))
                        else:
                            line = f"  {ip:<16} -- {count:>3} ports: {port_line1}  {marker}"
                            stdscr.addnstr(y, 2, line, w - 3, curses.color_pair(6))
                        if port_line2 and y + 1 < h - 2:
                            stdscr.addnstr(y + 1, indent2, port_line2, w - indent2 - 1,
                                           curses.color_pair(3) if idx == selected else curses.color_pair(6))
                    else:
                        if idx == selected:
                            stdscr.addnstr(y, 2, "> ", w - 3, curses.color_pair(1) | curses.A_BOLD)
                            line = f"{ip:<16} -- {count:>3} ports: {port_line1}"
                            stdscr.addnstr(y, 4, line, w - 5, curses.color_pair(1) | curses.A_BOLD)
                        else:
                            line = f"  {ip:<16} -- {count:>3} ports: {port_line1}"
                            stdscr.addnstr(y, 2, line, w - 3, curses.color_pair(2))
                        if port_line2 and y + 1 < h - 2:
                            stdscr.addnstr(y + 1, indent2, port_line2, w - indent2 - 1,
                                           curses.color_pair(1) if idx == selected else curses.color_pair(6))
                except curses.error:
                    pass

            # Footer
            footer_y = min(list_start_y + visible * ROWS_PER_HOST + 1, h - 1)
            try:
                stdscr.addnstr(footer_y, 2,
                               "[Up/Down] Navigate   [Enter] Scan selected   [q] Done / Exit",
                               w - 3, curses.color_pair(6))
            except curses.error:
                pass

            stdscr.refresh()
            key = stdscr.getch()

            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(total - 1, selected + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return sorted_hosts[selected]
            elif key in (ord('q'), ord('Q'), 27):
                return None

    try:
        return curses.wrapper(_run)
    except KeyboardInterrupt:
        return None


def curses_select_resume(phase_name: str):
    """Ask user whether to resume or restart a phase. Returns 'resume' or 'restart'."""
    options = [
        ("Resume  (skip completed phases, continue where left off)", "resume"),
        ("Restart (overwrite previous results)",                     "restart"),
    ]

    def _run(stdscr):
        curses.curs_set(0)
        _init_colors()
        selected = 0

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()

            try:
                stdscr.addnstr(1, 2, f"Previous results detected for: {phase_name}",
                               w - 3, curses.color_pair(4) | curses.A_BOLD)
                stdscr.addnstr(2, 2, "-" * 50, w - 3, curses.color_pair(6))
            except curses.error:
                pass

            for i, (label, _) in enumerate(options):
                y = 4 + i
                try:
                    if i == selected:
                        stdscr.addnstr(y, 2, "> " + label, w - 3,
                                       curses.color_pair(1) | curses.A_BOLD)
                    else:
                        stdscr.addnstr(y, 2, "  " + label, w - 3, curses.color_pair(2))
                except curses.error:
                    pass

            try:
                stdscr.addnstr(8, 2, "[Up/Down] Navigate   [Enter] Select",
                               w - 3, curses.color_pair(6))
            except curses.error:
                pass

            stdscr.refresh()
            key = stdscr.getch()

            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(options) - 1, selected + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return options[selected][1]

    try:
        return curses.wrapper(_run)
    except KeyboardInterrupt:
        sys.exit(130)


def curses_few_hosts_prompt(hosts: list, pivot: bool):
    """When <3 hosts found, recommend Single Target mode. Returns 'single' or 'continue'."""
    mode_label = "Single Target (Pivot)" if pivot else "Single Target"

    def _run(stdscr):
        curses.curs_set(0)
        _init_colors()
        selected = 0  # default to recommended option

        options = [
            (f"Switch to {mode_label} mode  (recommended)", "single"),
            ("Continue with Network Range scan",            "continue"),
        ]

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            y = 1

            try:
                stdscr.addnstr(y, 2, f"Only {len(hosts)} host(s) discovered",
                               w - 3, curses.color_pair(4) | curses.A_BOLD)
                y += 1
                stdscr.addnstr(y, 2, "-" * 50, w - 3, curses.color_pair(6))
                y += 2

                for ip in hosts:
                    stdscr.addnstr(y, 4, ip, w - 5, curses.color_pair(1) | curses.A_BOLD)
                    y += 1

                y += 1
                stdscr.addnstr(y, 2, f"{mode_label} mode gets you attacking faster —",
                               w - 3, curses.color_pair(2))
                y += 1
                stdscr.addnstr(y, 2, "P1 deep scan runs immediately instead of waiting",
                               w - 3, curses.color_pair(6))
                y += 1
                stdscr.addnstr(y, 2, "for a full port sweep across all hosts first.",
                               w - 3, curses.color_pair(6))
                y += 2
            except curses.error:
                pass

            for i, (label, _) in enumerate(options):
                try:
                    if i == selected:
                        stdscr.addnstr(y, 2, "> " + label, w - 3,
                                       curses.color_pair(1) | curses.A_BOLD)
                    else:
                        stdscr.addnstr(y, 2, "  " + label, w - 3, curses.color_pair(2))
                except curses.error:
                    pass
                y += 1

            y += 2
            try:
                stdscr.addnstr(min(y, h - 1), 2, "[Up/Down] Navigate   [Enter] Select",
                               w - 3, curses.color_pair(6))
            except curses.error:
                pass

            stdscr.refresh()
            key = stdscr.getch()

            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(options) - 1, selected + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                return options[selected][1]

    try:
        return curses.wrapper(_run)
    except KeyboardInterrupt:
        sys.exit(130)


udp_proc = None
disc_proc = None


def banner(pivot=False):
    art = Text()
    art.append(r"""
    ╦═╗╔═╗╔═╗╔═╗╔╗╔
    ╠╦╝║╣ ║  ║ ║║║║
    ╩╚═╚═╝╚═╝╚═╝╝╚╝""", style="bold cyan")
    art.append("  v2.1\n", style="dim cyan")
    art.append("\n  Automated Nmap Recon Pipeline", style="bold white")
    if pivot:
        art.append("\n  MODE: ", style="dim white")
        art.append("PIVOT (Ligolo-ng)", style="bold red")
        art.append("  --unprivileged  |  no min-rate  |  -n", style="dim red")
    art.append("\n\n  By ", style="dim white")
    art.append("Soel Kwun", style="bold cyan")
    art.append("  (Developed for Personal Use)", style="dim cyan")
    console.print(Panel(art, border_style="red" if pivot else "cyan", box=box.DOUBLE, padding=(0, 2)))


def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_cidr(cidr_str: str) -> bool:
    try:
        ipaddress.IPv4Network(cidr_str.strip(), strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def get_target_ip() -> str:
    console.print()
    while True:
        ip = console.input("[bold cyan]  Target IP > [/] ").strip()
        if validate_ip(ip):
            return ip
        console.print(f"  [bold red]x[/]  '{ip}' is not a valid IPv4 address. Try again.")


def get_cidr() -> str:
    console.print()
    console.print(f"  [{C_DIM}]Example: 172.16.5.0/24, 10.129.202.0/23[/]")
    while True:
        cidr = console.input("[bold cyan]  Network Range (CIDR) > [/] ").strip()
        if validate_cidr(cidr):
            return str(ipaddress.IPv4Network(cidr, strict=False))
        console.print(f"  [bold red]x[/]  '{cidr}' is not a valid CIDR range. Try again. (e.g. 172.16.5.0/24)")


def phase_header(label: str, desc: str, style: str = C_PHASE, pivot_note: str = ""):
    console.print()
    console.rule(style=style)
    line = f"  [{style}]> {label}[/]  —  {desc}"
    if pivot_note:
        line += f"  [{C_PIVOT}]({pivot_note})[/]"
    console.print(line)
    console.rule(style=style)
    console.print()


def sanitize_dirname(name: str) -> str:
    """Sanitize a CIDR or IP for use as a directory name."""
    return name.replace("/", "_")


# ═══════════════════════════════════════════════════════════════════════════
#  NMAP EXECUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def extract_open_ports_from_verbose(line: str):
    m = re.search(r"Discovered open port (\d+)/(tcp|udp)", line)
    if m:
        return int(m.group(1)), m.group(2)
    return None


def extract_ports_from_gnmap(gnmap_path: str) -> set:
    """Extract all open port numbers from a .gnmap file (TCP or UDP).
    Also counts 'open|filtered' — for UDP that state is the norm and ignoring
    it silently drops maybe-open services."""
    ports = set()
    try:
        with open(gnmap_path) as f:
            for line in f:
                # Trailing '/' anchors to the STATE/PROTO field so we don't match
                # a stray 'N/open' substring elsewhere.
                for m in re.finditer(r"(\d+)/open(?:\|filtered)?/", line):
                    ports.add(int(m.group(1)))
    except FileNotFoundError:
        pass
    return ports


def extract_hosts_ports_from_gnmap(gnmap_path: str) -> dict:
    """Parse gnmap to get {ip: set_of_open_tcp_ports} per host.
    Includes 'open|filtered' TCP so a firewalled-but-live port isn't dropped."""
    hosts = {}
    try:
        with open(gnmap_path) as f:
            for line in f:
                if "/open" not in line:
                    continue
                m = re.match(r"^Host:\s+(\S+)", line)
                if not m:
                    continue
                ip = m.group(1)
                ports = set()
                for pm in re.finditer(r"(\d+)/open(?:\|filtered)?/tcp", line):
                    ports.add(int(pm.group(1)))
                if ports:
                    hosts[ip] = ports
    except FileNotFoundError:
        pass
    return hosts


def extract_live_hosts_from_gnmap(gnmap_path: str) -> list:
    """Parse gnmap from -sn discovery scan to get list of live IPs."""
    hosts = []
    try:
        with open(gnmap_path) as f:
            for line in f:
                if "Status: Up" in line:
                    m = re.match(r"^Host:\s+(\S+)", line)
                    if m:
                        hosts.append(m.group(1))
    except FileNotFoundError:
        pass
    return sorted(set(hosts), key=lambda x: ipaddress.IPv4Address(x))


def is_scan_complete(filepath: str) -> bool:
    """Check if a .gnmap or .nmap file represents a completed scan.
    Nmap writes '# Nmap done' as the final line on successful completion.
    A file that exists but lacks this marker was interrupted mid-scan."""
    if not os.path.exists(filepath):
        return False
    try:
        with open(filepath, "rb") as f:
            # Seek to the last 512 bytes to find the marker efficiently
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 512))
            tail = f.read().decode("utf-8", errors="replace")
            return "# Nmap done" in tail
    except (OSError, IOError):
        return False


def print_port_discovery(port: int, proto: str, phase: str):
    console.print(f"    [{C_PORT}]* OPEN {proto.upper()}/{port}[/]  [{C_DIM}]({phase})[/]")


def run_nmap_live(cmd: list, phase_name: str, oA_base: str, raw_dir: str,
                  logfile=None, show_ports=True) -> int:
    """Run nmap with live output. Returns exit code."""
    full_cmd = (["sudo"] + cmd) if os.geteuid() != 0 else cmd
    proc = subprocess.Popen(
        full_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    port_count = 0
    start = time.time()

    for line in proc.stdout:
        stripped = line.rstrip()

        if logfile:
            logfile.write(line)
            logfile.flush()

        if show_ports:
            found = extract_open_ports_from_verbose(stripped)
            if found:
                port_count += 1
                print_port_discovery(found[0], found[1], phase_name)
                continue

        if "About " in stripped and "done" in stripped:
            console.print(f"    [{C_DIM}]{stripped.strip()}[/]")
            continue

        if any(k in stripped for k in ["Service Info:", "SF:", "|_", "|  "]):
            console.print(f"    [{C_DIM}]{stripped.strip()}[/]")

    proc.wait()
    elapsed = time.time() - start

    # Move .gnmap and .xml into raw/
    for ext in [".gnmap", ".xml"]:
        src = f"{oA_base}{ext}"
        if os.path.exists(src):
            shutil.move(src, os.path.join(raw_dir, os.path.basename(src)))

    mins, secs = divmod(int(elapsed), 60)
    if proc.returncode == 0:
        console.print(f"\n    [{C_OK}]+ {phase_name} complete[/]  "
                       f"[{C_DIM}]({mins}m {secs}s, {port_count} port(s) discovered)[/]")
    else:
        console.print(f"\n    [{C_ERR}]x {phase_name} FAILED (exit code {proc.returncode})[/]")
        console.print(f"    [{C_ERR}]  Warning: Results may be incomplete — check the .nmap file and consider re-running.[/]")

    return proc.returncode


def start_udp_background(target: str, raw_dir: str, pivot: bool = False) -> subprocess.Popen:
    """Launch UDP scan in background. Returns the Popen object."""
    global udp_proc
    live_path = os.path.join(raw_dir, "03.deep_udp_targeted.live")
    oA_base = "03.deep_udp_targeted"

    cmd = ["nmap", "-Pn", "-sU", "-sV", "-n", "-v",
           "-p", UDP_PORTS,
           "-oA", oA_base, target]
    # Note: --unprivileged is NOT added for UDP because -sU requires raw sockets.
    # Through Ligolo-ng, raw UDP goes through the TUN interface and the agent handles forwarding.
    # Results may be less reliable through tunnels — this is expected.

    full_cmd = (["sudo"] + cmd) if os.geteuid() != 0 else cmd

    live_fh = open(live_path, "w")
    udp_proc = subprocess.Popen(full_cmd, stdout=live_fh, stderr=subprocess.STDOUT)
    return udp_proc


def move_udp_outputs(raw_dir: str):
    for ext in [".gnmap", ".xml"]:
        src = f"03.deep_udp_targeted{ext}"
        if os.path.exists(src):
            shutil.move(src, os.path.join(raw_dir, os.path.basename(src)))


def print_udp_hints(gnmap_path: str):
    open_ports = extract_ports_from_gnmap(gnmap_path)
    if not open_ports:
        return

    sorted_ports = sorted(open_ports)
    port_labels = []
    for p in sorted_ports:
        svc = UDP_HINTS[p][0] if p in UDP_HINTS else "?"
        port_labels.append(f"{p}/{svc}")
    port_summary = ", ".join(port_labels)

    console.print()
    console.rule(style=C_HINT)
    console.print(f"  [{C_HINT}]UDP RESULTS[/]  —  {len(open_ports)} open port(s) found: [{C_PORT}]{port_summary}[/]")
    console.rule(style=C_HINT)

    for port in sorted_ports:
        if port in UDP_HINTS:
            svc, tools, purpose = UDP_HINTS[port]
            console.print(f"\n    [{C_PORT}]UDP/{port}[/] — [{C_SVC}]{svc}[/]")
            console.print(f"      [{C_HINT}]TIPS:[/]  Try {tools}")
            console.print(f"            to {purpose}")
        else:
            console.print(f"\n    [{C_PORT}]UDP/{port}[/] — [{C_DIM}]no predefined tips (check nmap output)[/]")
    console.print()


def wait_for_udp(udp: subprocess.Popen, raw_dir: str) -> bool:
    """Wait for background UDP scan. Returns True if completed."""
    udp_done = udp.poll() is not None
    if not udp_done:
        console.print(f"\n  [{C_INFO}]Waiting for UDP scan to finish...[/]  [{C_DIM}](Ctrl+C to skip)[/]")
        try:
            udp.wait(timeout=300)
            udp_done = True
        except subprocess.TimeoutExpired:
            console.print(f"    [{C_WARN}]UDP scan still running after 5 min. Moving on.[/]")
        except KeyboardInterrupt:
            console.print(f"    [{C_WARN}]Skipping UDP wait.[/]")
    move_udp_outputs(raw_dir)
    return udp_done


# ═══════════════════════════════════════════════════════════════════════════
#  HOST DISCOVERY  (fping fast pass  +  nmap thorough pass, unioned)
# ═══════════════════════════════════════════════════════════════════════════

def run_fping_discovery(cidr: str, pivot: bool = False):
    """
    Fast ICMP host discovery with fping (parallel — a whole /24 in ~seconds).

    Returns (alive_ips: list, status: str)
      status == "ok"     -> fping ran, alive_ips is the result (possibly empty)
      status == "absent" -> fping not installed
      status == "error"  -> fping failed to run

    In pivot mode ICMP is sent through the Ligolo-ng TUN. This often works even
    though the tool historically assumed ICMP was blocked — so fping is tried
    first and UNIONED with the TCP-SYN discovery, meaning nothing is silently
    missed either way.
    """
    if not shutil.which("fping"):
        return [], "absent"

    # fping pings all targets in parallel, so total time ≈ timeout × (retries+1),
    # roughly independent of how many hosts are down.
    #   -a alive only   -q quiet (suppress per-target stats/errors)
    #   -g generate from CIDR   -r retries   -t per-probe timeout (ms)
    if pivot:
        cmd = ["fping", "-a", "-q", "-r", "2", "-t", "1200", "-g", cidr]  # tolerate tunnel latency
    else:
        cmd = ["fping", "-a", "-q", "-r", "2", "-t", "500", "-g", cidr]

    full = (["sudo"] + cmd) if os.geteuid() != 0 else cmd
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, Exception):
        return [], "error"

    alive = []
    for ln in result.stdout.splitlines():
        ip = ln.strip()
        if ip and validate_ip(ip):
            alive.append(ip)
    return sorted(set(alive), key=lambda x: ipaddress.IPv4Address(x)), "ok"


def _launch_nmap_discovery_bg(cidr: str, raw_dir_rel: str, pivot: bool):
    """
    Launch nmap host discovery in the BACKGROUND so the fast fping pass can run
    (and display) in the foreground first. Returns the Popen (or None on failure).

    Normal: -sn  (ICMP echo + timestamp + TCP SYN/ACK — catches ICMP-filtered hosts)
    Pivot : --unprivileged -sn -PS<ports>  (TCP-SYN discovery — no ICMP assumed)
    """
    global disc_proc
    live_path = os.path.join(raw_dir_rel, "01.discovery.live")
    if pivot:
        cmd = ["nmap", "--unprivileged", "-sn", "-n", "-v",
               f"-PS{PIVOT_DISCOVERY_PORTS}", "-oA", "01.discovery", cidr]
    else:
        cmd = ["nmap", "-sn", "-v", "-oA", "01.discovery", cidr]

    full = (["sudo"] + cmd) if os.geteuid() != 0 else cmd
    try:
        fh = open(live_path, "w")
        disc_proc = subprocess.Popen(full, stdout=fh, stderr=subprocess.STDOUT)
        return disc_proc
    except Exception:
        return None


def _discover_hosts(cidr: str, raw_dir_rel: str, pivot: bool) -> list:
    """
    Layered host discovery:
      * fast fping ICMP preview (foreground)  — you see live hosts in seconds
      * thorough nmap pass (background)       — catches hosts fping can't see
    then UNION so no live host is silently missed. Returns a sorted list of IPs,
    writes 02.live_hosts.txt, and moves nmap outputs into raw/.
    """
    global disc_proc
    live_hosts_file = "02.live_hosts.txt"

    if pivot:
        phase_header("PHASE 1 — HOST DISCOVERY",
                     f"fping ICMP (fast)  +  nmap -PS{PIVOT_DISCOVERY_PORTS} (thorough)",
                     C_PIVOT, pivot_note="ICMP tried through tunnel + TCP-SYN, results unioned")
    else:
        phase_header("PHASE 1 — HOST DISCOVERY",
                     "fping ICMP (fast preview)  +  nmap -sn (thorough, catches filtered hosts)")

    # Kick off the thorough nmap pass in the background right away.
    nmap_bg = _launch_nmap_discovery_bg(cidr, raw_dir_rel, pivot)
    if nmap_bg:
        console.print(f"    [{C_DIM}]nmap thorough discovery running in background (PID {nmap_bg.pid})...[/]")

    # Fast fping preview in the foreground.
    fping_hosts, fp_status = run_fping_discovery(cidr, pivot)
    if fp_status == "absent":
        console.print(f"    [{C_WARN}]fping not installed — using nmap discovery only.[/]")
        console.print(f"    [{C_DIM}]  Install for ~3-second sweeps:  sudo apt install fping[/]")
    elif fp_status == "error":
        console.print(f"    [{C_WARN}]fping ran into an error — relying on nmap discovery.[/]")
    else:
        if fping_hosts:
            console.print(f"\n    [{C_OK}]+ fping found {len(fping_hosts)} host(s) instantly:[/]")
            for ip in fping_hosts:
                console.print(f"      [{C_PORT}]{ip}[/]  [{C_DIM}](ICMP)[/]")
        else:
            why = "ICMP may be filtered through the tunnel" if pivot else "hosts may be blocking ping"
            console.print(f"    [{C_DIM}]fping saw no ICMP-responsive hosts ({why}).[/]")

    # Wait for the thorough nmap pass to finish (it's the reliability backstop).
    nmap_hosts = []
    if nmap_bg:
        if nmap_bg.poll() is None:
            console.print(f"\n    [{C_INFO}]Waiting for nmap thorough pass "
                          f"(catches hosts fping can't see)...[/]  [{C_DIM}](Ctrl+C to skip)[/]")
        try:
            nmap_bg.wait(timeout=600)
        except subprocess.TimeoutExpired:
            console.print(f"    [{C_WARN}]nmap discovery slow (>10 min) — proceeding with what we have.[/]")
            try:
                nmap_bg.terminate()
            except Exception:
                pass
        except KeyboardInterrupt:
            console.print(f"    [{C_WARN}]Skipping nmap discovery wait — using fping results only.[/]")
            try:
                nmap_bg.terminate()
            except Exception:
                pass
        disc_proc = None
        # Move nmap outputs into raw/ (its .nmap stays at top level, like the sweeps).
        for ext in [".gnmap", ".xml"]:
            src = f"01.discovery{ext}"
            if os.path.exists(src):
                shutil.move(src, os.path.join(raw_dir_rel, os.path.basename(src)))
        nmap_hosts = extract_live_hosts_from_gnmap(os.path.join(raw_dir_rel, "01.discovery.gnmap"))

    # UNION — reliability: never drop a host that either method found.
    all_set = set(fping_hosts) | set(nmap_hosts)
    all_hosts = sorted(all_set, key=lambda x: ipaddress.IPv4Address(x))

    # Report the delta so coverage is trustworthy and visible.
    only_nmap = sorted(set(nmap_hosts) - set(fping_hosts), key=lambda x: ipaddress.IPv4Address(x))
    only_fping = sorted(set(fping_hosts) - set(nmap_hosts), key=lambda x: ipaddress.IPv4Address(x))
    if only_nmap:
        tag = "TCP-SYN caught, ICMP missed" if pivot else "likely ICMP-filtered"
        console.print(f"\n    [{C_WARN}]! nmap caught {len(only_nmap)} host(s) fping missed "
                      f"({tag}):[/]  [{C_PORT}]{', '.join(only_nmap)}[/]")
    if only_fping and nmap_bg:
        tag = "ICMP answered, probe ports closed"
        console.print(f"    [{C_DIM}]  fping-only host(s) ({tag}): {', '.join(only_fping)}[/]")

    if all_hosts:
        with open(live_hosts_file, "w") as f:
            f.write("\n".join(all_hosts) + "\n")

    return all_hosts


# ═══════════════════════════════════════════════════════════════════════════
#  SINGLE TARGET PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def print_single_summary(target, scan_dir, raw_dir, p1_ports, p2_new, p3_ran, udp_done, p1_rc, p2_rc, pivot):
    console.print()
    console.rule(style=C_OK)

    table = Table(
        title=f"  Recon Complete — {target}" + ("  [PIVOT]" if pivot else ""),
        box=box.ROUNDED,
        border_style="green",
        title_style="bold green",
        padding=(0, 2),
    )
    table.add_column("Phase", style="bold cyan", min_width=14)
    table.add_column("Status", style="white", min_width=12)
    table.add_column("Quick View", style="dim white", min_width=40)

    p1_status = f"[green]+[/]  {len(p1_ports)} port(s)" if p1_rc == 0 else "[red]x FAILED[/] — check output"
    table.add_row("P1  top-1000", p1_status, "cat 01.deep_tcp_top1000.nmap")

    p2_status = "[green]+[/]" if p2_rc == 0 else "[red]x FAILED[/] — re-run sweep"
    table.add_row("P2  full sweep", p2_status, "cat 02.sweep_all_tcp_ports.nmap")

    if p2_rc != 0:
        table.add_row("P3  new ports", "[red]SKIPPED[/]", "P2 failed — cannot diff ports")
    elif p3_ran:
        table.add_row("P3  new ports", f"[green]+[/]  {len(p2_new)} new port(s)", "cat 04.deep_tcp_targeted.nmap")
    else:
        table.add_row("P3  new ports", "[yellow]SKIPPED[/]", "no new ports beyond top-1000")

    if udp_done:
        udp_open = extract_ports_from_gnmap(os.path.join(raw_dir, "03.deep_udp_targeted.gnmap"))
        udp_status = f"[green]+[/]  {len(udp_open)} port(s)"
    else:
        udp_status = "[yellow]still running[/]"
    table.add_row("UDP targeted", udp_status, "cat 03.deep_udp_targeted.nmap")

    console.print(table)
    console.print(f"\n  [{C_INFO}]Files:[/]")
    console.print(f"    [{C_DIM}]Scan results (.nmap)   -> [/]  {scan_dir}/")
    console.print(f"    [{C_DIM}]Raw data (.gnmap/.xml) -> [/]  {scan_dir}/raw/")
    console.print(f"\n  [{C_WARN}]Tip:[/] Open another terminal and run:")
    console.print(f"    [bold white]cd {scan_dir} && cat 01.deep_tcp_top1000.nmap[/]")
    console.rule(style=C_OK)
    console.print()


def pipeline_single(target: str, minrate: int, pivot: bool):
    """Full single-target scan pipeline."""
    scan_dir = target
    raw_dir = os.path.join(scan_dir, "raw")

    # ── Resume detection ──
    if os.path.isdir(scan_dir):
        choice = curses_select_resume(target)
        if choice == "restart":
            shutil.rmtree(scan_dir)

    os.makedirs(raw_dir, exist_ok=True)
    start_cwd = os.getcwd()
    os.chdir(scan_dir)
    raw_dir_rel = "raw"

    console.print(f"  [{C_INFO}]Output directory:[/]  {os.path.abspath('.')}")
    console.print(f"  [{C_DIM}]   raw/  (gnmap, xml, logs)[/]")
    if pivot:
        console.print(f"  [{C_PIVOT}]   PIVOT MODE: --unprivileged on TCP | -n on all | no min-rate[/]")

    logfile = open("00.tcp_chain.log", "a")

    # ── Pivot-aware nmap flag builders ──
    def tcp_base(extra_flags: list) -> list:
        """Build base nmap TCP command flags."""
        cmd = ["nmap"]
        if pivot:
            cmd.append("--unprivileged")
        cmd.extend(["-Pn", "-n"] if pivot else ["-Pn"])
        cmd.extend(extra_flags)
        return cmd

    # ═══ UDP — Background ═══
    udp = None
    udp_nmap = "03.deep_udp_targeted.nmap"
    if not is_scan_complete(udp_nmap):
        phase_header("UDP SCAN", f"Background — ports {UDP_PORTS}", C_INFO,
                     pivot_note="through Ligolo-ng tunnel" if pivot else "")
        udp = start_udp_background(target, raw_dir_rel, pivot)
        console.print(f"    [{C_OK}]+ UDP scan launched[/]  [{C_DIM}](PID {udp.pid})[/]")
        console.print(f"    [{C_DIM}]  Watch live:  tail -f {os.path.abspath(raw_dir_rel)}/03.deep_udp_targeted.live[/]")
        if pivot:
            console.print(f"    [{C_WARN}]  Note: UDP through Ligolo-ng tunnel may have limited reliability.[/]")
    else:
        console.print(f"\n  [{C_OK}]+ UDP scan already exists — skipping.[/]")

    # ═══ P1 — Deep top-1000 ═══
    p1_gnmap = os.path.join(raw_dir_rel, "01.deep_tcp_top1000.gnmap")
    p1_rc = 0
    if not is_scan_complete(p1_gnmap):
        phase_header("P1 — DEEP TOP-1000",
                     "nmap -Pn -sC -sV -v --open  (scripts + version detection)",
                     pivot_note="+ --unprivileged -n" if pivot else "")
        p1_cmd = tcp_base(["-sC", "-sV", "-v", "--open", "-oA", "01.deep_tcp_top1000", target])
        p1_rc = run_nmap_live(p1_cmd, "P1", "01.deep_tcp_top1000", raw_dir_rel, logfile)
    else:
        console.print(f"\n  [{C_OK}]+ P1 results exist — skipping.[/]")

    p1_ports = extract_ports_from_gnmap(p1_gnmap)
    if p1_ports:
        console.print(f"\n    [{C_PORT}]P1 open ports:[/]  {', '.join(str(p) for p in sorted(p1_ports))}")
    console.print(f"\n    [{C_WARN}]->  You can start attacking now from another terminal![/]")
    console.print(f"      [bold white]cat {os.path.abspath('01.deep_tcp_top1000.nmap')}[/]")

    # ═══ P2 — Full port sweep ═══
    time.sleep(2)
    p2_gnmap = os.path.join(raw_dir_rel, "02.sweep_all_tcp_ports.gnmap")
    p2_rc = 0
    if not is_scan_complete(p2_gnmap):
        rate_desc = f"--min-rate {minrate}" if minrate > 0 else "no rate limit"
        phase_header("P2 — FULL PORT SWEEP",
                     f"nmap -Pn -n -p- -v --open  ({rate_desc}, all 65535 ports)",
                     pivot_note="+ --unprivileged" if pivot else "")
        p2_flags = ["-n", "-p-", "-v", "--open"]
        if minrate > 0:
            p2_flags.extend(["--min-rate", str(minrate)])
        p2_cmd = tcp_base(p2_flags + ["-oA", "02.sweep_all_tcp_ports", target])
        # De-duplicate -n if pivot mode already added it
        p2_cmd = _dedup_flags(p2_cmd)
        p2_rc = run_nmap_live(p2_cmd, "P2", "02.sweep_all_tcp_ports", raw_dir_rel, logfile)
    else:
        console.print(f"\n  [{C_OK}]+ P2 results exist — skipping.[/]")

    # ═══ P3 — Deep scan on NEW ports only ═══
    time.sleep(2)
    p2_ports = extract_ports_from_gnmap(p2_gnmap)
    new_ports = sorted(p2_ports - TOP_1000)
    p3_ran = False

    p4_gnmap = os.path.join(raw_dir_rel, "04.deep_tcp_targeted.gnmap")
    if is_scan_complete(p4_gnmap):
        console.print(f"\n  [{C_OK}]+ P3 results exist — skipping.[/]")
        p3_ran = True
    elif p2_rc != 0:
        phase_header("P3 — SKIPPED", "P2 sweep failed — cannot reliably diff ports.", C_ERR)
    elif new_ports:
        port_str = ",".join(str(p) for p in new_ports)
        phase_header("P3 — NEW-PORT DEEP SCAN",
                     f"Deep scan on {len(new_ports)} port(s) not in top-1000: {port_str}",
                     pivot_note="+ --unprivileged -n" if pivot else "")
        p3_cmd = tcp_base(["-sC", "-sV", "-v", "--open",
                           "-p", port_str,
                           "-oA", "04.deep_tcp_targeted", target])
        p3_cmd = _dedup_flags(p3_cmd)
        run_nmap_live(p3_cmd, "P3", "04.deep_tcp_targeted", raw_dir_rel, logfile)
        p3_ran = True
    else:
        phase_header("P3 — SKIPPED", "No new ports found beyond top-1000", C_WARN)

    logfile.close()

    # ── Wait for UDP ──
    udp_done = True
    if udp:
        udp_done = wait_for_udp(udp, raw_dir_rel)

    # ── UDP hints ──
    udp_gnmap = os.path.join(raw_dir_rel, "03.deep_udp_targeted.gnmap")
    if udp_done and os.path.exists(udp_gnmap):
        print_udp_hints(udp_gnmap)

    # ── Summary ──
    print_single_summary(target, os.path.abspath("."), os.path.abspath(raw_dir_rel),
                         p1_ports, new_ports, p3_ran, udp_done, p1_rc, p2_rc, pivot)
    os.chdir(start_cwd)


# ═══════════════════════════════════════════════════════════════════════════
#  NETWORK RANGE PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def pipeline_network(cidr: str, minrate: int, pivot: bool):
    """Full network range scan pipeline."""
    range_dir = sanitize_dirname(cidr)
    raw_dir = os.path.join(range_dir, "raw")

    # ── Resume detection ──
    if os.path.isdir(range_dir):
        choice = curses_select_resume(cidr)
        if choice == "restart":
            shutil.rmtree(range_dir)

    os.makedirs(raw_dir, exist_ok=True)
    start_cwd = os.getcwd()
    os.chdir(range_dir)
    raw_dir_rel = "raw"

    console.print(f"  [{C_INFO}]Output directory:[/]  {os.path.abspath('.')}")
    if pivot:
        console.print(f"  [{C_PIVOT}]   PIVOT MODE: fping ICMP + TCP-SYN discovery | --unprivileged | no min-rate[/]")

    # ── Pivot-aware nmap flag builder (for the sweep) ──
    def tcp_base(extra_flags: list) -> list:
        cmd = ["nmap"]
        if pivot:
            cmd.append("--unprivileged")
        cmd.extend(["-Pn", "-n"] if pivot else ["-Pn"])
        cmd.extend(extra_flags)
        return cmd

    # ═══ PHASE 1 — Host Discovery (fping fast + nmap thorough, unioned) ═══
    discovery_gnmap = os.path.join(raw_dir_rel, "01.discovery.gnmap")
    live_hosts_file = "02.live_hosts.txt"

    if (os.path.exists(live_hosts_file) and os.path.getsize(live_hosts_file) > 0
            and is_scan_complete(discovery_gnmap)):
        console.print(f"\n  [{C_OK}]+ Discovery results exist — skipping.[/]")
        with open(live_hosts_file) as f:
            live_hosts = [line.strip() for line in f if line.strip()]
    else:
        live_hosts = _discover_hosts(cidr, raw_dir_rel, pivot)

    if not live_hosts:
        console.print(f"\n  [{C_ERR}]x No live hosts found in {cidr}.[/]")
        if pivot:
            console.print(f"    [{C_WARN}]Tip: Verify Ligolo-ng tunnel is active and routes are set.[/]")
        console.print(f"    [{C_DIM}]If you know a host is up, try Single Target mode (it uses -Pn).[/]")
        os.chdir(start_cwd)
        return

    console.print(f"\n    [{C_OK}]+ {len(live_hosts)} live host(s) total:[/]")
    for ip in live_hosts:
        console.print(f"      [{C_PORT}]{ip}[/]")

    # ── Few hosts? Recommend Single Target mode ──
    sweep_gnmap = os.path.join(raw_dir_rel, "03.sweep_allhosts_all_tcp_ports.gnmap")
    if len(live_hosts) < 3 and not is_scan_complete(sweep_gnmap):
        choice = curses_few_hosts_prompt(live_hosts, pivot)
        if choice == "single":
            mode_label = "Single Target (Pivot)" if pivot else "Single Target"
            console.print()
            console.rule(style=C_INFO)
            console.print(f"  [{C_INFO}]Switching to {mode_label} mode[/]")
            console.print(f"  [{C_DIM}]Run Recon.py once per host:[/]")
            console.print()
            for ip in live_hosts:
                console.print(f"    [bold white]sudo python3 Recon.py[/]  [{C_DIM}]→ {mode_label} → {ip}[/]")
            console.print()
            console.rule(style=C_INFO)
            console.print()
            os.chdir(start_cwd)
            return

    # ═══ PHASE 2 — Full Port Sweep (all hosts) ═══
    if is_scan_complete(sweep_gnmap):
        console.print(f"\n  [{C_OK}]+ Sweep results exist — skipping.[/]")
    else:
        rate_desc = f"--min-rate {minrate}" if minrate > 0 else "no rate limit"
        phase_header("PHASE 2 — FULL PORT SWEEP (ALL HOSTS)",
                     f"nmap -Pn -n -p- -v --open -iL live_hosts  ({rate_desc})",
                     pivot_note="+ --unprivileged" if pivot else "")
        console.print(f"  [{C_DIM}]  This is a fast PREVIEW to prioritize hosts; each host you pick is "
                      f"re-verified independently.[/]\n")

        sweep_flags = ["-n", "-p-", "-v", "--open"]
        if minrate > 0:
            sweep_flags.extend(["--min-rate", str(minrate)])
        sweep_cmd = tcp_base(sweep_flags + [
            "-iL", live_hosts_file,
            "-oA", "03.sweep_allhosts_all_tcp_ports",
        ])
        sweep_cmd = _dedup_flags(sweep_cmd)
        sweep_rc = run_nmap_live(sweep_cmd, "Sweep", "03.sweep_allhosts_all_tcp_ports", raw_dir_rel)

        if sweep_rc != 0:
            console.print(f"\n  [{C_ERR}]x Sweep failed. Fix the issue and re-run.[/]")
            os.chdir(start_cwd)
            return

    # ── Parse sweep results (fast PREVIEW only — used to prioritize hosts) ──
    sweep_hosts_ports = extract_hosts_ports_from_gnmap(sweep_gnmap)

    # Make EVERY discovered host selectable, even ones the fast aggregate sweep
    # reported no open ports on. Each host you pick is re-verified independently
    # in the deep-scan phase, so a host the sweep under-reported (or a port it
    # dropped) can still be caught.
    hosts_ports = {ip: sweep_hosts_ports.get(ip, set()) for ip in live_hosts}

    total_ports = sum(len(p) for p in hosts_ports.values())
    hosts_with_ports = sum(1 for p in hosts_ports.values() if p)
    console.print(f"\n    [{C_OK}]+ Sweep complete:[/]  {hosts_with_ports} host(s) reported open ports "
                  f"({total_ports} total); all {len(hosts_ports)} live host(s) selectable")
    console.print(f"    [{C_DIM}]  Each deep scan re-verifies its host, so sweep misses don't propagate.[/]")

    # ═══ PHASE 3 — Interactive Per-Host Deep Scan Loop ═══
    completed_hosts = _detect_completed_hosts(hosts_ports)

    while True:
        target_ip = curses_select_host(hosts_ports, completed_hosts)
        if target_ip is None:
            break

        if target_ip in completed_hosts:
            console.print(f"\n  [{C_WARN}]{target_ip} was already scanned. Re-scanning will overwrite results.[/]")

        _scan_single_host_from_sweep(target_ip, hosts_ports[target_ip], pivot)
        completed_hosts.add(target_ip)

        remaining = len(hosts_ports) - len(completed_hosts & set(hosts_ports.keys()))
        if remaining > 0:
            console.print(f"\n  [{C_INFO}]{remaining} host(s) remaining. Returning to host selection...[/]")
            time.sleep(2)
        else:
            console.print(f"\n  [{C_OK}]+ All hosts scanned![/]")
            break

    # ── Network summary ──
    _print_network_summary(cidr, os.path.abspath("."), hosts_ports, completed_hosts, pivot)
    os.chdir(start_cwd)


def _detect_completed_hosts(hosts_ports: dict) -> set:
    """Check which hosts already have scan directories with results."""
    completed = set()
    for ip in hosts_ports:
        host_dir = ip
        p1_gnmap = os.path.join(host_dir, "raw", "01.deep_tcp_top1000.gnmap")
        p4_gnmap = os.path.join(host_dir, "raw", "04.deep_tcp_targeted.gnmap")
        # Consider complete if at least the top-1000 scan completed successfully
        if is_scan_complete(p1_gnmap) or is_scan_complete(p4_gnmap):
            completed.add(ip)
    return completed


def _scan_single_host_from_sweep(target: str, known_ports: set, pivot: bool):
    """
    Deep scan a single host — AUTHORITATIVE and independent of the aggregate
    network sweep, so a miss in the fast all-hosts sweep can't reach the result.

      P1: careful -sC -sV on nmap's DEFAULT top-1000  (guarantees common ports)
      P2: full -p- re-sweep of THIS host, default adaptive timing, NO --min-rate
          (aggressive rates are what drop SYN/ACKs and cause missed ports)
      P3: careful -sC -sV on any ports beyond the top-1000
          (union of aggregate-sweep hits and this host's fresh -p- results)
    """
    host_dir = target
    raw_dir = os.path.join(host_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    saved_cwd = os.getcwd()
    os.chdir(host_dir)
    raw_dir_rel = "raw"

    console.print()
    console.rule(style=C_PHASE)
    console.print(f"  [{C_PHASE}]> DEEP SCAN — {target}[/]  "
                  f"({len(known_ports)} port(s) from sweep — will re-verify)")
    console.rule(style=C_PHASE)
    console.print(f"  [{C_INFO}]Output:[/]  {os.path.abspath('.')}")

    logfile = open("00.tcp_chain.log", "a")

    def tcp_base(extra_flags: list) -> list:
        cmd = ["nmap"]
        if pivot:
            cmd.append("--unprivileged")
        cmd.extend(["-Pn", "-n"] if pivot else ["-Pn"])
        cmd.extend(extra_flags)
        return cmd

    # ═══ UDP — Background ═══
    udp = None
    if not is_scan_complete("03.deep_udp_targeted.nmap"):
        phase_header("UDP SCAN", f"Background — ports {UDP_PORTS}", C_INFO,
                     pivot_note="through Ligolo-ng tunnel" if pivot else "")
        udp = start_udp_background(target, raw_dir_rel, pivot)
        console.print(f"    [{C_OK}]+ UDP scan launched[/]  [{C_DIM}](PID {udp.pid})[/]")
        if pivot:
            console.print(f"    [{C_WARN}]  Note: UDP through Ligolo-ng tunnel may have limited reliability.[/]")
    else:
        console.print(f"\n  [{C_OK}]+ UDP scan already exists — skipping.[/]")

    # ═══ P1 — Careful deep scan of the DEFAULT top-1000 (independent of sweep) ═══
    p1_gnmap = os.path.join(raw_dir_rel, "01.deep_tcp_top1000.gnmap")
    if not is_scan_complete(p1_gnmap):
        phase_header("P1 — DEEP TOP-1000 (independent)",
                     "nmap -sC -sV -v --open  (nmap's own top-1000, not the sweep's)",
                     pivot_note="+ --unprivileged -n" if pivot else "")
        p1_cmd = _dedup_flags(tcp_base(["-sC", "-sV", "-v", "--open",
                                        "-oA", "01.deep_tcp_top1000", target]))
        run_nmap_live(p1_cmd, "P1 top-1000", "01.deep_tcp_top1000", raw_dir_rel, logfile)
    else:
        console.print(f"\n  [{C_OK}]+ Top-1000 deep scan exists — skipping.[/]")

    p1_ports = extract_ports_from_gnmap(p1_gnmap)
    if p1_ports:
        console.print(f"\n    [{C_PORT}]Top-1000 open ports:[/]  "
                      f"{', '.join(str(p) for p in sorted(p1_ports))}")
        console.print(f"\n    [{C_WARN}]->  You can start attacking now from another terminal![/]")
        console.print(f"      [bold white]cat {os.path.abspath('01.deep_tcp_top1000.nmap')}[/]")

    # ═══ P2 — Authoritative full -p- re-sweep of THIS host ═══
    # Default adaptive timing, no forced --min-rate: single-host full sweeps are
    # fast, and dropping the aggressive rate is exactly what prevents missed ports.
    fresh_ports = set()
    if VERIFY_HOSTS_WITH_FULL_SWEEP:
        time.sleep(2)
        host_sweep_gnmap = os.path.join(raw_dir_rel, "05.host_full_tcp_sweep.gnmap")
        if not is_scan_complete(host_sweep_gnmap):
            phase_header("P2 — FULL PORT RE-SWEEP (this host)",
                         "nmap -Pn -n -p- -v --open  (default timing, no min-rate → reliable)",
                         pivot_note="+ --unprivileged" if pivot else "")
            b_cmd = _dedup_flags(tcp_base(["-n", "-p-", "-v", "--open",
                                           "-oA", "05.host_full_tcp_sweep", target]))
            run_nmap_live(b_cmd, "Full re-sweep", "05.host_full_tcp_sweep", raw_dir_rel, logfile)
        else:
            console.print(f"\n  [{C_OK}]+ Full port re-sweep exists — skipping.[/]")
        fresh_ports = extract_ports_from_gnmap(host_sweep_gnmap)

    # Union of what the aggregate sweep saw and what this host's own sweep saw —
    # nothing found by either pass is ever dropped.
    all_open = set(known_ports) | fresh_ports
    beyond_top1000 = sorted(all_open - TOP_1000)

    missed_by_aggregate = sorted(fresh_ports - set(known_ports))
    if missed_by_aggregate:
        console.print(f"\n    [{C_WARN}]! Re-sweep found {len(missed_by_aggregate)} port(s) "
                      f"the network sweep missed:[/]  "
                      f"[{C_PORT}]{', '.join(str(p) for p in missed_by_aggregate)}[/]")

    # ═══ P3 — Careful scan of ports beyond the top-1000 ═══
    time.sleep(2)
    p4_gnmap = os.path.join(raw_dir_rel, "04.deep_tcp_targeted.gnmap")
    if not is_scan_complete(p4_gnmap):
        if beyond_top1000:
            port_str = ",".join(str(p) for p in beyond_top1000)
            phase_header("P3 — DEEP SCAN (ports beyond top-1000)",
                         f"{len(beyond_top1000)} port(s) outside top-1000: {port_str}",
                         pivot_note="+ --unprivileged -n" if pivot else "")
            p3_cmd = _dedup_flags(tcp_base(["-sC", "-sV", "-v", "--open",
                                            "-p", port_str,
                                            "-oA", "04.deep_tcp_targeted", target]))
            run_nmap_live(p3_cmd, "Deep beyond-top-1000", "04.deep_tcp_targeted", raw_dir_rel, logfile)
        else:
            console.print(f"\n  [{C_DIM}]No open ports beyond the top-1000 — skipping P3.[/]")
    else:
        console.print(f"\n  [{C_OK}]+ Beyond-top-1000 deep scan exists — skipping.[/]")

    logfile.close()

    # ── Wait for UDP ──
    udp_done = True
    if udp:
        udp_done = wait_for_udp(udp, raw_dir_rel)

    udp_gnmap = os.path.join(raw_dir_rel, "03.deep_udp_targeted.gnmap")
    if udp_done and os.path.exists(udp_gnmap):
        print_udp_hints(udp_gnmap)

    # ── Per-host summary ──
    console.print()
    console.rule(style=C_OK)
    console.print(f"  [{C_OK}]+ Deep scan complete for {target}[/]")
    console.print(f"    [{C_DIM}]Confirmed open TCP ports:[/]  {len(p1_ports | all_open)}")
    console.print(f"    [{C_DIM}]Results in:[/]  {os.path.abspath('.')}")
    console.rule(style=C_OK)

    os.chdir(saved_cwd)


def _print_network_summary(cidr, base_dir, hosts_ports, completed, pivot):
    console.print()
    console.rule(style=C_OK)

    table = Table(
        title=f"  Network Recon Summary — {cidr}" + ("  [PIVOT]" if pivot else ""),
        box=box.ROUNDED,
        border_style="green",
        title_style="bold green",
        padding=(0, 2),
    )
    table.add_column("Host", style="bold cyan", min_width=16)
    table.add_column("Open Ports", style="white", min_width=8)
    table.add_column("Status", style="white", min_width=12)
    table.add_column("Directory", style="dim white", min_width=20)

    for ip in sorted(hosts_ports.keys(), key=lambda x: ipaddress.IPv4Address(x)):
        port_count = len(hosts_ports[ip])
        if ip in completed:
            status = "[green]+ SCANNED[/]"
            directory = f"{base_dir}/{ip}/"
        else:
            status = "[yellow]- PENDING[/]"
            directory = "—"
        table.add_row(ip, str(port_count), status, directory)

    console.print(table)
    console.print(f"\n  [{C_INFO}]Base directory:[/]  {base_dir}/")
    console.print(f"    [{C_DIM}]Discovery / sweep results at top level.[/]")
    console.print(f"    [{C_DIM}]Per-host deep scan results in each host directory.[/]")
    console.print(f"    [{C_DIM}]Port counts above are from the fast sweep; scanned hosts were re-verified.[/]")
    console.rule(style=C_OK)
    console.print()


# ═══════════════════════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════════════════════

def _dedup_flags(cmd: list) -> list:
    """Remove duplicate flags like -n appearing twice."""
    seen = set()
    result = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            skip_next = False
            result.append(arg)
            continue
        if arg.startswith("-") and not arg.startswith("--"):
            # Short flag: -n, -v, -p, etc.
            if arg in seen and arg in ("-n", "-v", "-Pn"):
                continue
            seen.add(arg)
        elif arg.startswith("--"):
            if arg in seen and arg in ("--unprivileged", "--open"):
                continue
            seen.add(arg)
            # Flags that take a value
            if arg in ("--min-rate",):
                skip_next = True
        result.append(arg)
    return result


def cleanup(signum=None, frame=None):
    global udp_proc, disc_proc
    console.print(f"\n\n  [{C_WARN}]Interrupted — cleaning up...[/]")
    for proc, label in ((udp_proc, "UDP scan"), (disc_proc, "discovery scan")):
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                console.print(f"    [{C_DIM}]{label} terminated.[/]")
            except Exception:
                pass
    console.print(f"    [{C_DIM}]Partial results saved in the target directory.[/]\n")
    sys.exit(130)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    signal.signal(signal.SIGINT, cleanup)

    # ── Mode selection (curses) ──
    mode = curses_select_mode()
    if mode < 0:
        console.print("\n  Exited.\n")
        sys.exit(0)

    pivot   = mode in (1, 3)
    network = mode in (2, 3)

    # ── Banner (rich) ──
    banner(pivot=pivot)

    # ── Root check ──
    if os.geteuid() != 0:
        console.print(f"  [{C_WARN}]Not running as root. UDP, SYN, and fping ICMP scans require sudo.[/]")
        console.print(f"    [{C_DIM}]Re-run with:  sudo python3 Recon.py[/]\n")
        sys.exit(1)

    # ── Target input ──
    if network:
        cidr = get_cidr()
        console.print(f"\n  [{C_OK}]+ Range set:[/]  [bold white]{cidr}[/]")
        minrate = 0 if pivot else curses_select_minrate()
        if not pivot and minrate > 0:
            console.print(f"  [{C_INFO}]  --min-rate:[/]  {minrate}")
        _minrate_caution(minrate, network=True)
        console.print()
        pipeline_network(cidr, minrate, pivot)
    else:
        target = get_target_ip()
        console.print(f"\n  [{C_OK}]+ Target set:[/]  [bold white]{target}[/]")
        minrate = 0 if pivot else curses_select_minrate()
        if not pivot and minrate > 0:
            console.print(f"  [{C_INFO}]  --min-rate:[/]  {minrate}")
        _minrate_caution(minrate, network=False)
        console.print()
        pipeline_single(target, minrate, pivot)


def _minrate_caution(minrate: int, network: bool):
    """Warn when an aggressive min-rate is chosen; note the reliability backstop."""
    if minrate >= 4000:
        console.print(f"  [{C_WARN}]  Caution:[/] --min-rate {minrate} is aggressive; on congested or "
                      f"filtered networks it can silently drop ports.")
        if network:
            console.print(f"  [{C_DIM}]           Each host you deep-scan is re-swept with no rate limit, "
                          f"so misses are caught there.[/]")
        else:
            console.print(f"  [{C_DIM}]           If results look thin, re-run — the careful top-1000 scan "
                          f"still covers common ports.[/]")


if __name__ == "__main__":
    main()
