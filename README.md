# Recon
nmap Recon tool

Setup (one time):
bashpip install rich
chmod +x recon.py
Run it:
bashsudo python3 recon.py
```

It'll prompt you for the target IP, then automatically runs the full pipeline from your concept.

**What the terminal experience looks like:**

The output uses `rich` for colored, sectioned output — each phase (UDP, T1, T2, T4) gets a clearly separated header with ruled lines. Open ports are highlighted with a `★ OPEN TCP/80` style callout in magenta the moment nmap discovers them via `-v`. Nmap progress percentages are shown dimmed so they don't clutter the important stuff. At the end you get a summary table showing all phases, their status, and the exact `cat` command to review each result.

**File organization — the key thing you asked for:**
```
10.10.10.100/
├── 01.deep_tcp_top1000.nmap      ← cat this
├── 02.sweep_all_tcp_ports.nmap   ← cat this  
├── 03.deep_udp_targeted.nmap     ← cat this
├── 04.deep_tcp_targeted.nmap     ← cat this (if new ports found)
├── 00.tcp_chain.log              ← full combined log
└── raw/                          ← stuff you don't need day-to-day
    ├── *.gnmap
    ├── *.xml
    └── 03.deep_udp_targeted.live
Only .nmap files (the human-readable ones you'd cat or vi) live at the top level. The .gnmap and .xml files get auto-moved into raw/ so they don't clutter your view. The script still uses .gnmap internally to extract ports for the T4 diff logic.
Terminal 2 workflow stays exactly the same — once T1 starts printing ports, you jump to your attack terminal and start working. The script even prints a reminder with the exact cat command path after T1 finishes.
