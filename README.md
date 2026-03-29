# RECON.PY

**Automated Nmap Recon Pipeline**
By **Soel Kwun** — Developed for Personal Use

---

## What It Does

Interactive nmap automation with **4 scan modes**, selected via arrow-key menu on launch:

| Mode | Description |
|------|-------------|
| **Single Target** | Standard scan against one host |
| **Single Target (Pivot)** | Scan through active Ligolo-ng tunnel (`--unprivileged`, no min-rate) |
| **Network Range** | Discover hosts across a CIDR range, then deep scan each |
| **Network Range (Pivot)** | Same as above, but through Ligolo-ng tunnel (TCP-based discovery, no ICMP) |

### Single Target Workflow
```
UDP (background) → P1 deep top-1000 → P2 full 65535 sweep → P3 new-port deep scan
```

### Network Range Workflow
```
Host Discovery → Full Port Sweep (all hosts) → Interactive Host Selection → Per-Host Deep Scan
```

You enter the target, pick your options with arrow keys, and it handles everything — clean colored output, live port discovery, organized files. Attack from Terminal 2 while it runs.

---

## Requirements

- Python 3.8+
- `nmap`
- `rich` (Python library — see install options below)

### Installing `rich`

The only external dependency. Pick whatever works for your setup:

**Option 1 — apt (Kali / Debian / Ubuntu)** ⭐ Easiest on Kali
```bash
sudo apt install python3-rich
```
No pip needed. Already in Kali repos.

**Option 2 — venv (works everywhere, zero system pollution)**
```bash
python3 -m venv ~/recon-venv
source ~/recon-venv/bin/activate
pip install rich
```
Then always run Recon.py from the activated venv:
```bash
source ~/recon-venv/bin/activate
sudo $(which python3) Recon.py
```
> **Note:** `sudo python3` won't see venv packages. You need `sudo $(which python3)` to use the venv's python as root. Alternatively: `sudo ~/recon-venv/bin/python3 Recon.py`

**Option 3 — pip with `--break-system-packages` (quick & dirty)**
```bash
pip install rich --break-system-packages
```
Works on modern Kali/Debian that block pip by default. Fine for a pentest VM you don't care about keeping clean.

**Option 4 — pip install --user**
```bash
pip install --user rich
```
Installs to `~/.local/lib/python3.x/`. May not be visible to sudo — same `sudo $(which python3)` trick from Option 2 applies.

> **Note:** `pipx` won't work here. It's designed for runnable CLI tools, not importable libraries.

---

## Usage

```bash
sudo python3 Recon.py
```

An arrow-key menu appears:

```
  ╦═╗╔═╗╔═╗╔═╗╔╗╔
  ╠╦╝║╣ ║  ║ ║║║║
  ╩╚═╚═╝╚═╝╚═╝╝╚╝  v2.0

  Select Scan Mode
  --------------------

> Single Target
    Standard scan against one host

  Single Target  [PIVOT]
    Scan through active Ligolo-ng tunnel (--unprivileged, no min-rate)

  Network Range
    Discover hosts and scan a network range

  Network Range  [PIVOT]
    Discover and scan through active Ligolo-ng tunnel

  [Up/Down] Navigate   [Enter] Select   [q] Quit
```

After selecting a mode, you'll be prompted for the target and options (min-rate, etc.) before scanning begins.

### Terminal Workflow

| Terminal | What to do |
|----------|------------|
| **Terminal 1** | `sudo python3 Recon.py` → select mode, enter target, let it run. Don't touch this terminal. |
| **Terminal 2** | Attack as soon as P1 starts showing open ports. `cd <target_ip> && cat 01.deep_tcp_top1000.nmap` |

---

## Scan Modes in Detail

### Single Target

After entering the IP, you select a `--min-rate` for the full port sweep (P2):

| Option | Use Case |
|--------|----------|
| **None (disabled)** | Maximum reliability — let nmap auto-adjust |
| **500** | Careful — production / client networks |
| **2000** | Standard — CTF exams (OSCP, CPTS) |
| **4000** | Aggressive — HTB / fast labs |

Then the pipeline runs:

| Phase | What it does |
|-------|-------------|
| **UDP** | Fires immediately in background. Scans 9 common UDP ports (DNS, SNMP, TFTP, NTP, NetBIOS, IKE, IPMI, MSSQL Browser, RPCbind). |
| **P1** | Deep scan on nmap's default top-1000 TCP ports with `-sC -sV`. Scripts + versions. Start attacking from Terminal 2 as soon as this finishes. |
| **P2** | Full port sweep across all 65535 TCP ports (`-p-`). Fast but shallow — catches ports P1 missed. |
| **P3** | Auto-extracts ports P2 found that were NOT in the top-1000, then runs deep `-sC -sV` on just those. Skips if P2 found nothing new. |

### Single Target (Pivot)

Same pipeline as Single Target, but designed for scanning through an active **Ligolo-ng** tunnel:

- `--unprivileged` added to all TCP nmap commands (agent can't forward raw packets)
- `-n` added to all commands (DNS resolution won't work through tunnel)
- **No `--min-rate`** — rate limiting through a tunnel causes instability and drops
- UDP scan still runs (flows through TUN interface natively — one of Ligolo-ng's advantages over SOCKS-based tools)
- Phase headers display added flags in **red** so you always know what pivot mode changed

### Network Range

1. **Host Discovery** — `nmap -sn` with ICMP + TCP probes to find live hosts
2. **Full Port Sweep** — all 65535 TCP ports scanned (without options like -sV -sC) across every live host (with your selected min-rate)
3. **Interactive Host Selection** — arrow-key menu shows every discovered host with their open ports. Pick one to deep scan. Already-scanned hosts appear as `[DONE]`.
4. **Per-Host Deep Scan** — targeted deep scan using only the known open ports (split into top-1000 vs non-top-1000) + background UDP
5. **Repeat** — returns to host selection after each scan. Press `q` when done.

### Network Range (Pivot)

Same as Network Range, but:

- Host discovery uses **TCP probes** (`-PS22,80,135,139,443,445,3389,5985,8080,8443`) instead of ICMP — ping/ICMP is typically disabled on internal networks
- All TCP scans include `--unprivileged` and `-n`
- No min-rate option

---

## Output Structure

### Single Target
```
10.10.10.100/
├── 01.deep_tcp_top1000.nmap         ← cat this  (P1: scripts + versions)
├── 02.sweep_all_tcp_ports.nmap      ← cat this  (P2: all 65535 ports)
├── 03.deep_udp_targeted.nmap        ← cat this  (UDP results)
├── 04.deep_tcp_targeted.nmap        ← cat this  (P3: new ports only, if any)
├── 00.tcp_chain.log                 ← full combined terminal log
└── raw/
    ├── *.gnmap                      ← machine-parseable (used internally)
    ├── *.xml                        ← XML output (for tools like searchsploit)
    └── 03.deep_udp_targeted.live    ← UDP live stream file
```

### Network Range
```
172.16.5.0_24/
├── 02.live_hosts.txt                ← discovered live hosts
├── 03.sweep_allhosts_all_tcp_ports.nmap
├── raw/
│   ├── 01.discovery.gnmap
│   └── 03.sweep_allhosts_all_tcp_ports.gnmap
├── 172.16.5.10/                     ← per-host deep scan results
│   ├── 01.deep_tcp_top1000.nmap
│   ├── 03.deep_udp_targeted.nmap
│   ├── 04.deep_tcp_targeted.nmap
│   └── raw/
├── 172.16.5.20/
│   └── ...
```

Only `.nmap` files (the ones you'd `cat` or `vi`) are at the top level. Everything else is tucked into `raw/` so it doesn't clutter your view.

---

## Resume & Reliability

- **Resume detection** — if you re-run against an existing target/range, the tool asks `Resume` or `Restart`
- **Completion validation** — resume checks verify nmap's `# Nmap done` marker in output files. Interrupted or partial scans are automatically re-run, never silently skipped
- **Ctrl+C** at any point cleanly terminates scans and saves partial results
- **UDP timeout** — if UDP is still running when TCP finishes, it waits up to 5 minutes then moves on. Ctrl+C to skip the wait

---

## UDP Attack Tips

When UDP ports are found open, the tool prints short attack-path tips:

```
UDP/161 — SNMP
  TIPS:  Try snmpwalk -v2c -c public, onesixtyone, snmp-check, snmpbulkwalk
         to enumerate users, processes, installed software — look for creds and cleartext strings
```

Covered UDP ports: DNS (53), TFTP (69), RPCbind (111), NTP (123), NetBIOS-NS (137), SNMP (161), IKE/IPsec (500), IPMI/BMC (623), MS-SQL Browser (1434).

These are quick reminders, not full guides. Check HackTricks or your notes for detailed methodology.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Missing `rich` library | See install options above. Easiest on Kali: `sudo apt install python3-rich` |
| `sudo python3` can't find `rich` | Your rich is in user-space but sudo uses system python. Fix: `sudo $(which python3) Recon.py` |
| Permission denied | Run with `sudo`. Nmap needs root for raw socket scans. |
| Scans seem slow | P2 uses your selected min-rate. Nmap auto-adjusts for bad networks. Don't crank higher on exams. |
| Pivot mode — no hosts found | Verify Ligolo-ng tunnel is active and routes are set (`ip route show`). |
| Pivot mode — scans hang or drop | Tunnel may have dropped (`yamux: keepalive failed`). Re-run agent on pivot host. Reduce scan intensity. |
| Resume skips a phase you want to re-run | Select `Restart` when prompted, or delete the specific `.gnmap` file from `raw/`. |

---

## Changelog

### v2.0
- **4 scan modes** with interactive arrow-key selection (curses-based menu)
- **Ligolo-ng pivot support** — `--unprivileged`, `-n`, no min-rate, TCP-based host discovery
- **Network range scanning** — host discovery, full sweep, interactive per-host deep scan
- **Min-rate selection** — choose scan speed per environment (disabled / 500 / 2000 / 4000)
- **Resume detection** — validates scan completion before skipping; partial scans are re-run
- **Pivot-aware phase headers** — added flags shown in red so you know exactly what's running

### v1.0
- Single target scanning with UDP + TCP pipeline
- Live port discovery output
- UDP attack tips
- Organized file output structure
