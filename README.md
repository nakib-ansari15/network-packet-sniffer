# Network Packet Sniffer (Python + Scapy)

A lightweight packet sniffer built with **Python** and **Scapy** for learning and SOC-style investigations.
It captures TCP/UDP/ICMP traffic, optionally filters with BPF (e.g., `tcp`, `udp port 53`), and extracts HTTP request details
(Host, path, user agent) when traffic is plain HTTP (port 80). Includes simple suspicious-activity heuristics (e.g., SYN scan hints).

## Features
- Interface selection (`-i`), BPF filter (`-f`), packet count (`-n`) or timeout (`-t`)
- CSV logging of packet metadata
- Optional PCAP capture file for later analysis (`--pcap`)
- HTTP request parsing (Host, path, User-Agent) for plaintext HTTP
- Basic detection hints (SYN without ACK → possible scan)
- Clean shutdown with Ctrl+C
- Easy to explain in interviews and extend

## Quickstart (Kali/Debian)
```bash
# 1) System prep (choose *one* approach)
# A. Use system Scapy (simple)
sudo apt update && sudo apt install -y python3-scapy

# B. Or use pip in a venv (more portable)
sudo apt update && sudo apt install -y python3-venv
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2) Root/capabilities
# Option 1 (simplest): run with sudo
sudo -E python3 sniffer.py -i wlan0 -f tcp --pcap capture.pcap -o out.csv

# Option 2 (no sudo): grant raw socket caps to python (advanced; redo after Python updates)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python3 sniffer.py -i wlan0 -f "tcp" -o out.csv

# 3) Examples
sudo -E python3 sniffer.py -i eth0 -f "icmp" -n 50
sudo -E python3 sniffer.py -i wlan0 -f "tcp port 80" --http-only -o http.csv
sudo -E python3 sniffer.py -i any -f "udp port 53" --pcap dns.pcap -t 60
```

> Tip: On many systems, HTTPS dominates web traffic. You will only see HTTP details (Host/Path/User-Agent) for **unencrypted** HTTP (port 80). That’s normal.

## CLI Usage
```text
usage: sniffer.py [-h] [-i IFACE] [-f FILTER] [-n COUNT] [-t TIMEOUT]
                  [-o CSV_OUT] [--pcap PCAP_OUT] [--http-only] [--summary]

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        interface to sniff on (default: Scapy’s default)
  -f FILTER, --filter FILTER
                        BPF filter, e.g., "tcp", "udp port 53", "icmp"
  -n COUNT, --count COUNT
                        stop after N packets (0 = unlimited)
  -t TIMEOUT, --timeout TIMEOUT
                        stop after T seconds (0 = unlimited)
  -o CSV_OUT, --out CSV_OUT
                        path to CSV log (optional)
  --pcap PCAP_OUT       path to write PCAP (optional)
  --http-only           log only HTTP requests (for plaintext HTTP)
  --summary             reduce console verbosity (still logs to CSV/PCAP)
```

## Project Structure
```
packet-sniffer/
├─ sniffer.py          # main script (entrypoint)
├─ requirements.txt    # Python dependencies (when using venv/pip)
└─ README.md
```

## How it Works (high level)
- Uses Scapy’s `sniff()` to capture packets at Layer 2/3 on a given interface.
- BPF filter is passed to the kernel (fast, efficient).
- For each packet: extract IP/ports/protocol, length, and helpful summary.
- If TCP with payload on port 80: parse HTTP request line, Host, and User-Agent.
- For heuristics: if `SYN` without `ACK` → prints a “possible scan” hint.
- Optionally writes **PCAP** for offline analysis (Wireshark), and **CSV** for quick triage.

## Interview Talking Points
- Differences between HTTP vs HTTPS visibility (metadata vs content).
- Why use **BPF filters** (kernel-level filtering = performance).
- Raw sockets & permissions, and safe alternatives (capabilities).
- How you’d extend it: TLS SNI parsing, DNS query extraction, GeoIP tagging, stateful scan detection.

## Legal & Ethical
Only capture traffic on networks you own or have explicit permission to monitor. Respect privacy and laws in your jurisdiction.
