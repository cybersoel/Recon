# RECON.PY

**Automated Nmap Recon Pipeline**
*By Soel Kwun — Developed for Personal Use*

---

## What It Does

Runs a structured nmap scan pipeline against a single target IP:

```
UDP (background)  →  P1 deep top-1000  →  P2 full 65535 sweep  →  P3 new-port deep scan
```

You enter the IP, it handles everything — clean colored output, live port discovery, organized files. Attack from Terminal 2 while it runs.

---

## Requirements

- Python 3.8+
- nmap
- `rich` (Python library — see install options below)

---

## Installing `rich`

The only external dependency. Pick whatever works for your setup:

### Option 1 — apt (Kali / Debian / Ubuntu) ⭐ Easiest on Kali

```bash
sudo apt install python3-rich
```

No pip needed. Already in Kali repos. Check first with `apt search python3-rich`.

### Option 2 — pipx?

**Won't work here.** pipx is designed for runnable CLI tools (like sqlmap, autorecon, etc.), not importable libraries. Use one of the other options.

### Option 3 — venv (works everywhere, zero system pollution)

```bash
python3 -m venv ~/recon-venv
source ~/recon-venv/bin/activate
pip install rich
```

Then always run recon.py from the activated venv:

```bash
source ~/recon-venv/bin/activate
sudo $(which python3) recon.py
```

> **Note:** `sudo python3` won't see venv packages. You need `sudo $(which python3)` to use the venv's python as root.
> Alternatively: `sudo ~/recon-venv/bin/python3 recon.py`

### Option 4 — pip with `--break-system-packages` (quick & dirty)

```bash
pip install rich --break-system-packages
```

Works on modern Kali/Debian that block pip by default. Fine for a pentest VM you don't care about keeping clean.

### Option 5 — pip install `--user`

```bash
pip install --user rich
```

Installs to `~/.local/lib/python3.x/`. May not be visible to sudo — same `sudo $(which python3)` trick from Option 3 applies.

---

## Usage

```bash
sudo python3 recon.py
```

It will prompt:

```
Target IP ➜ 10.10.10.100
```

Then all phases run automatically.

---

## Terminal Workflow

| Terminal | What to do |
|----------|------------|
| **Terminal 1** | `sudo python3 recon.py` → enter IP, let it run. Don't touch this terminal again. |
| **Terminal 2** | Attack as soon as P1 starts showing open ports. `cd 10.10.10.100 && cat 01.deep_tcp_top1000.nmap` |

---

## Output Structure

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

Only `.nmap` files (the ones you'd `cat` or `vi`) are at the top level. Everything else is tucked into `raw/` so it doesn't clutter your view.

---

## Scan Phases

| Phase | What it does |
|-------|-------------|
| **UDP** | Fires immediately in background. Scans 9 common UDP ports (DNS, SNMP, TFTP, NTP, NetBIOS, IKE, IPMI, MSSQL Browser, RPCbind). Doesn't interfere with TCP — different protocol stack. |
| **P1** | Deep scan on nmap's default top-1000 TCP ports with `-sC -sV`. Your bread and butter — scripts + versions, fast. Start attacking from Terminal 2 as soon as this finishes. |
| **P2** | Full port sweep across all 65535 TCP ports (`-p-`) with `--min-rate 2000`. Fast but shallow — catches ports P1 missed. |
| **P3** | Auto-extracts any ports P2 found that were NOT in the top-1000, then runs a deep `-sC -sV` scan on just those. Skips entirely if P2 found nothing new. |

---

## UDP Attack Tips

When UDP ports are found open, the tool prints short attack-path tips with common tools and what to look for:

```
UDP/161 — SNMP
  TIPS:  Try snmpwalk -v2c -c public, onesixtyone, snmp-check, snmpbulkwalk
         to enumerate users, processes, installed software — look for creds and cleartext strings
```

These are quick reminders, not full guides. Check HackTricks or your notes for detailed methodology.

---

## Tips

- If P3 shows **SKIPPED**, that's normal — means no hidden high ports were found.
- **Ctrl+C** at any point cleanly terminates scans and saves partial results.
- Requires **root** (`sudo`) for SYN and UDP scans.
- If UDP is still running when TCP finishes, it waits up to 5 minutes then moves on. Ctrl+C to skip the wait.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Missing 'rich' library` | See install options above. Easiest on Kali: `sudo apt install python3-rich` |
| `sudo python3` can't find `rich` | Your rich is in user-space but sudo uses system python. Fix: `sudo $(which python3) recon.py` |
| `Permission denied` / `Operation not permitted` | Run with `sudo`. Nmap needs root for raw socket scans. |
| Scans seem slow | P2 uses `--min-rate 2000` already. Nmap auto-adjusts for bad networks. Don't crank higher on exams. |
