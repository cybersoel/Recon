#!/usr/bin/env python3
"""
recon.py — Automated Nmap Recon Pipeline
─────────────────────────────────────────
Workflow:  UDP (background) → P1 deep top-1000 → P2 full sweep → P3 new-port deep scan

Usage:  sudo python3 recon.py
"""

import subprocess, sys, os, re, signal, time, shutil, ipaddress
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich import box
except ImportError:
    print("\n[!] Missing 'rich' library.")
    print("    See README.txt for install options (venv, pipx, apt, etc.)\n")
    sys.exit(1)

# ─── Constants ──────────────────────────────────────────────────────────────
console = Console()

UDP_PORTS = "53,69,111,123,137,161,500,623,1434"

# Short attack-path hints per UDP port
# Format: { port: (service, tools, purpose) }
UDP_HINTS = {
    53: (
        "DNS",
        "dig axfr, dnsenum, dnsrecon, fierce",
        "attempt zone transfers and brute-force subdomains — leaked records can reveal internal hosts",
    ),
    69: (
        "TFTP",
        "tftp, atftp, nmap tftp-enum",
        "grab files blindly (no auth!) — look for config files, boot images, anything juicy",
    ),
    111: (
        "RPCbind",
        "rpcinfo -p, showmount -e, nmap nfs-ls/nfs-showmount",
        "list RPC services and check for NFS shares you can mount — easy wins if exports are open",
    ),
    123: (
        "NTP",
        "ntpq -c readlist, ntpdc -c monlist, nmap ntp-monlist",
        "check for monlist amplification and peer info — can leak internal IPs and hostnames",
    ),
    137: (
        "NetBIOS-NS",
        "nbtscan, nmblookup, nmap nbstat",
        "enumerate NetBIOS names, domain info, and logged-in users — quick wins for domain context",
    ),
    161: (
        "SNMP",
        "snmpwalk -v2c -c public, onesixtyone, snmp-check, snmpbulkwalk",
        "enumerate users, processes, installed software, network interfaces — look for creds and cleartext strings",
    ),
    500: (
        "IKE/IPsec",
        "ike-scan -M, strongswan, ikeforce",
        "fingerprint the VPN and test aggressive mode — you might capture a pre-shared key to crack",
    ),
    623: (
        "IPMI/BMC",
        "ipmitool, metasploit ipmi_dumphashes, nmap ipmi-version",
        "dump RAKP hashes (crackable offline), try default creds (ADMIN/ADMIN) — can lead to remote KVM",
    ),
    1434: (
        "MS-SQL Browser",
        "nmap ms-sql-info, msfconsole mssql_ping, sqsh",
        "discover hidden SQL Server instances and their TCP ports — then pivot to TCP for the real attack",
    ),
}

# Nmap's actual default top-1000 TCP ports (used to diff against P2 results)
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

# ─── Colors / Theming ───────────────────────────────────────────────────────
C_PHASE  = "bold cyan"
C_OK     = "bold green"
C_WARN   = "bold yellow"
C_ERR    = "bold red"
C_DIM    = "dim white"
C_PORT   = "bold magenta"
C_INFO   = "bold blue"
C_HINT   = "bold yellow"
C_SVC    = "bold white"

# ─── Helpers ─────────────────────────────────────────────────────────────────
udp_proc = None


def banner():
    art = Text()
    art.append(r"""
    ╦═╗╔═╗╔═╗╔═╗╔╗╔
    ╠╦╝║╣ ║  ║ ║║║║
    ╩╚═╚═╝╚═╝╚═╝╝╚╝""", style="bold cyan")
    art.append("  v1.0\n", style="dim cyan")
    art.append("\n  Automated Nmap Recon Pipeline", style="bold white")
    art.append("\n  UDP ║ P1 deep-1000 → P2 full sweep → P3 new-port deep", style="dim white")
    art.append("\n\n  By ", style="dim white")
    art.append("Soel Kwun", style="bold cyan")
    art.append("  (Developed for Personal Use)", style="dim cyan")

    console.print(Panel(art, border_style="cyan", box=box.DOUBLE, padding=(0, 2)))


def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ipaddress.AddressValueError:
        return False


def get_target_ip() -> str:
    console.print()
    while True:
        ip = console.input("[bold cyan]  Target IP ➜ [/] ").strip()
        if validate_ip(ip):
            return ip
        console.print(f"  [bold red]✗[/]  '{ip}' is not a valid IPv4 address. Try again.")


def phase_header(label: str, desc: str, style: str = C_PHASE):
    console.print()
    console.rule(style=style)
    console.print(f"  [{style}]▶ {label}[/]  —  {desc}")
    console.rule(style=style)
    console.print()


def extract_open_ports_from_verbose(line: str):
    m = re.search(r"Discovered open port (\d+)/(tcp|udp)", line)
    if m:
        return int(m.group(1)), m.group(2)
    return None


def extract_ports_from_gnmap(gnmap_path: str) -> set:
    ports = set()
    try:
        with open(gnmap_path) as f:
            for line in f:
                for m in re.finditer(r"(\d+)/open", line):
                    ports.add(int(m.group(1)))
    except FileNotFoundError:
        pass
    return ports


def print_port_discovery(port: int, proto: str, phase: str):
    console.print(f"    [{C_PORT}]★ OPEN {proto.upper()}/{port}[/]  [{C_DIM}]({phase})[/]")


def run_nmap_live(cmd: list, phase_name: str, oA_base: str, raw_dir: str,
                  logfile=None, show_ports=True) -> int:
    """Run nmap with live output. Returns the exit code."""
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
        console.print(f"\n    [{C_OK}]✓ {phase_name} complete[/]  "
                       f"[{C_DIM}]({mins}m {secs}s, {port_count} port(s) discovered)[/]")
    else:
        console.print(f"\n    [{C_ERR}]✗ {phase_name} FAILED (exit code {proc.returncode})[/]")
        console.print(f"    [{C_ERR}]  ⚠  Results may be incomplete — check the .nmap file and consider re-running.[/]")

    return proc.returncode


def start_udp_background(target: str, raw_dir: str) -> subprocess.Popen:
    global udp_proc
    live_path = os.path.join(raw_dir, "03.deep_udp_targeted.live")
    oA_base   = "03.deep_udp_targeted"

    cmd = [
        "nmap", "-Pn", "-sU", "-sV", "-n", "-v",
        "-p", UDP_PORTS,
        "-oA", oA_base,
        target,
    ]
    full_cmd = (["sudo"] + cmd) if os.geteuid() != 0 else cmd

    live_fh = open(live_path, "w")
    udp_proc = subprocess.Popen(
        full_cmd,
        stdout=live_fh,
        stderr=subprocess.STDOUT,
    )
    return udp_proc


def move_udp_outputs(raw_dir: str):
    for ext in [".gnmap", ".xml"]:
        src = f"03.deep_udp_targeted{ext}"
        if os.path.exists(src):
            shutil.move(src, os.path.join(raw_dir, os.path.basename(src)))


def print_udp_hints(gnmap_path: str):
    """Parse UDP .gnmap for open ports, display them, and print attack tips."""
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
    console.print(f"  [{C_HINT}]⚡ UDP RESULTS[/]  —  {len(open_ports)} open port(s) found: [{C_PORT}]{port_summary}[/]")
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


def print_summary(target: str, scan_dir: str, raw_dir: str, p1_ports, p2_new, p3_ran, udp_done, p1_rc, p2_rc):
    console.print()
    console.rule(style=C_OK)

    table = Table(
        title=f"  Recon Complete — {target}",
        box=box.ROUNDED,
        border_style="green",
        title_style="bold green",
        padding=(0, 2),
    )
    table.add_column("Phase", style="bold cyan", min_width=14)
    table.add_column("Status", style="white", min_width=12)
    table.add_column("Quick View", style="dim white", min_width=40)

    p1_status = f"[green]✓[/]  {len(p1_ports)} port(s)" if p1_rc == 0 else "[red]✗ FAILED[/] — check output"
    table.add_row(
        "P1  top-1000",
        p1_status,
        "cat 01.deep_tcp_top1000.nmap",
    )
    p2_status = "[green]✓[/]" if p2_rc == 0 else "[red]✗ FAILED[/] — re-run sweep"
    table.add_row(
        "P2  full sweep",
        p2_status,
        "cat 02.sweep_all_tcp_ports.nmap",
    )
    if p2_rc != 0:
        table.add_row(
            "P3  new ports",
            "[red]SKIPPED[/]",
            "P2 failed — cannot diff ports",
        )
    elif p3_ran:
        table.add_row(
            "P3  new ports",
            f"[green]✓[/]  {len(p2_new)} new port(s)",
            "cat 04.deep_tcp_targeted.nmap",
        )
    else:
        table.add_row(
            "P3  new ports",
            "[yellow]SKIPPED[/]",
            "no new ports beyond top-1000",
        )
    if udp_done:
        udp_open = extract_ports_from_gnmap(os.path.join(raw_dir, "03.deep_udp_targeted.gnmap"))
        udp_status = f"[green]✓[/]  {len(udp_open)} port(s)" if udp_open else "[green]✓[/]  0 port(s)"
    else:
        udp_status = "[yellow]still running[/]"
    table.add_row(
        "UDP targeted",
        udp_status,
        "cat 03.deep_udp_targeted.nmap",
    )

    console.print(table)

    console.print(f"\n  [{C_INFO}]Files:[/]")
    console.print(f"    [{C_DIM}]Scan results (.nmap) →[/]  {scan_dir}/")
    console.print(f"    [{C_DIM}]Raw data (.gnmap/.xml) →[/]  {scan_dir}/raw/")
    console.print(f"\n  [{C_WARN}]Tip:[/] Open another terminal and run:")
    console.print(f"    [bold white]cd {scan_dir} && cat 01.deep_tcp_top1000.nmap[/]")
    console.rule(style=C_OK)
    console.print()


def cleanup(signum=None, frame=None):
    global udp_proc
    console.print(f"\n\n  [{C_WARN}]⚠  Interrupted — cleaning up...[/]")
    if udp_proc and udp_proc.poll() is None:
        udp_proc.terminate()
        console.print(f"    [{C_DIM}]UDP scan terminated.[/]")
    console.print(f"    [{C_DIM}]Partial results saved in the target directory.[/]\n")
    sys.exit(130)


# ─── Main Pipeline ───────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, cleanup)

    banner()

    if os.geteuid() != 0:
        console.print(f"  [{C_WARN}]⚠  Not running as root. UDP & SYN scans require sudo.[/]")
        console.print(f"    [{C_DIM}]Re-run with:  sudo python3 recon.py[/]\n")
        sys.exit(1)

    target = get_target_ip()
    console.print(f"\n  [{C_OK}]✓ Target set:[/]  [bold white]{target}[/]\n")

    # ── Directory structure ──
    scan_dir = target
    raw_dir  = os.path.join(scan_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    os.chdir(scan_dir)
    raw_dir_rel = "raw"
    console.print(f"  [{C_INFO}]📁 Output directory:[/]  {os.path.abspath('.')}")
    console.print(f"  [{C_DIM}]   └── raw/  (gnmap, xml, logs)[/]")

    logfile = open("00.tcp_chain.log", "w")

    # ═════════════════════════════════════════════════════════════════════
    #  UDP — Background
    # ═════════════════════════════════════════════════════════════════════
    phase_header("UDP SCAN", f"Background — ports {UDP_PORTS}", C_INFO)
    udp = start_udp_background(target, raw_dir_rel)
    console.print(f"    [{C_OK}]✓ UDP scan launched[/]  [{C_DIM}](PID {udp.pid})[/]")
    console.print(f"    [{C_DIM}]  Watch live:  tail -f {os.path.abspath(raw_dir_rel)}/03.deep_udp_targeted.live[/]")

    # ═════════════════════════════════════════════════════════════════════
    #  P1 — Deep top-1000
    # ═════════════════════════════════════════════════════════════════════
    phase_header("P1 — DEEP TOP-1000", "nmap -Pn -sC -sV -v --open  (scripts + version detection)")
    p1_cmd = [
        "nmap", "-Pn", "-sC", "-sV", "-v", "--open",
        "-oA", "01.deep_tcp_top1000",
        target,
    ]
    p1_rc = run_nmap_live(p1_cmd, "P1", "01.deep_tcp_top1000", raw_dir_rel, logfile)
    p1_ports = extract_ports_from_gnmap(os.path.join(raw_dir_rel, "01.deep_tcp_top1000.gnmap"))

    if p1_ports:
        console.print(f"\n    [{C_PORT}]P1 open ports:[/]  {', '.join(str(p) for p in sorted(p1_ports))}")
    console.print(f"\n    [{C_WARN}]➜  You can start attacking now from Terminal 2![/]")
    console.print(f"      [bold white]cat {os.path.abspath('01.deep_tcp_top1000.nmap')}[/]")

    # ═════════════════════════════════════════════════════════════════════
    #  P2 — Full port sweep
    # ═════════════════════════════════════════════════════════════════════
    time.sleep(3)
    phase_header("P2 — FULL PORT SWEEP", "nmap -Pn -n -p- -v --open --min-rate 2000  (all 65535 ports)")
    p2_cmd = [
        "nmap", "-Pn", "-n", "-p-", "-v", "--open", "--min-rate", "2000",
        "-oA", "02.sweep_all_tcp_ports",
        target,
    ]
    p2_rc = run_nmap_live(p2_cmd, "P2", "02.sweep_all_tcp_ports", raw_dir_rel, logfile)

    # ═════════════════════════════════════════════════════════════════════
    #  P3 — Deep scan on NEW ports only
    # ═════════════════════════════════════════════════════════════════════
    time.sleep(3)
    p2_ports = extract_ports_from_gnmap(os.path.join(raw_dir_rel, "02.sweep_all_tcp_ports.gnmap"))
    new_ports = sorted(p2_ports - TOP_1000)

    p3_ran = False
    if p2_rc != 0:
        phase_header("P3 — SKIPPED", "P2 sweep failed — cannot reliably diff ports. Re-run or sweep manually.", C_ERR)
    elif new_ports:
        port_str = ",".join(str(p) for p in new_ports)
        phase_header("P3 — NEW-PORT DEEP SCAN", f"Deep scan on {len(new_ports)} port(s) not in top-1000: {port_str}")
        p3_cmd = [
            "nmap", "-Pn", "-sC", "-sV", "-n", "-v", "--open",
            "-p", port_str,
            "-oA", "04.deep_tcp_targeted",
            target,
        ]
        run_nmap_live(p3_cmd, "P3", "04.deep_tcp_targeted", raw_dir_rel, logfile)
        p3_ran = True
    else:
        phase_header("P3 — SKIPPED", "No new ports found beyond top-1000", C_WARN)

    logfile.close()

    # ── Wait for UDP ──
    udp_done = udp.poll() is not None
    if not udp_done:
        console.print(f"\n  [{C_INFO}]⏳ Waiting for UDP scan to finish...[/]  [{C_DIM}](Ctrl+C to skip)[/]")
        try:
            udp.wait(timeout=300)
            udp_done = True
        except subprocess.TimeoutExpired:
            console.print(f"    [{C_WARN}]UDP scan still running after 5 min. Moving on.[/]")
        except KeyboardInterrupt:
            console.print(f"    [{C_WARN}]Skipping UDP wait.[/]")

    move_udp_outputs(raw_dir_rel)

    # ── UDP attack hints ──
    udp_gnmap = os.path.join(raw_dir_rel, "03.deep_udp_targeted.gnmap")
    if udp_done and os.path.exists(udp_gnmap):
        print_udp_hints(udp_gnmap)

    # ═════════════════════════════════════════════════════════════════════
    #  Summary
    # ═════════════════════════════════════════════════════════════════════
    print_summary(target, os.path.abspath("."), os.path.abspath(raw_dir_rel),
                  p1_ports, new_ports, p3_ran, udp_done, p1_rc, p2_rc)


if __name__ == "__main__":
    main()
