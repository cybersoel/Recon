# Recon
nmap Recon tool

# Setup (one time):
```
# Install Dependency (font)
pip install rich
# OR
pipx install rich

# Change permission
chmod +x recon.py
# Run it:
sudo python3 recon.py
```



**File organization:**
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
```
