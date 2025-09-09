#!/usr/bin/env python3
"""
Network Packet Sniffer using Python + Scapy
- Captures TCP/UDP/ICMP
- Optional BPF filter
- CSV logging + optional PCAP
- HTTP (plaintext) request parsing
- Basic scan hints (SYN without ACK)

Author: Mohammed Nakib Ansari
"""

import argparse
import csv
import signal
import sys
import time
from datetime import datetime
from typing import Optional, Dict, Any

from scapy.all import (
    sniff, AsyncSniffer, wrpcap, conf,
    IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSQR
)

class Main:
    def __init__(self):
        self.args = self._parse_args()
        self.csv_writer = None
        self.csv_file = None
        self.pcap_packets = []
        self.running = True
        self.counters = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "http": 0,
        }

    @staticmethod
    def _parse_args():
        p = argparse.ArgumentParser(description="Simple Python + Scapy packet sniffer")
        p.add_argument("-i", "--iface", help="Interface to sniff on (default: scapy's default)", default=None)
        p.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp", "udp port 53", "icmp"', default=None)
        p.add_argument("-n", "--count", type=int, default=0, help="Stop after N packets (0 = unlimited)")
        p.add_argument("-t", "--timeout", type=int, default=0, help="Stop after T seconds (0 = unlimited)")
        p.add_argument("-o", "--out", dest="csv_out", default=None, help="CSV output path (optional)")
        p.add_argument("--pcap", dest="pcap_out", default=None, help="PCAP output path (optional)")
        p.add_argument("--http-only", action="store_true", help="Log only HTTP requests (plaintext HTTP)")
        p.add_argument("--summary", action="store_true", help="Print compact console output")
        return p.parse_args()

    def _open_csv(self):
        if not self.args.csv_out:
            return
        self.csv_file = open(self.args.csv_out, "w", newline="", encoding="utf-8")
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow([
            "timestamp_iso", "src", "sport", "dst", "dport", "proto", "len",
            "info", "http_host", "http_path", "user_agent", "suspicion"
        ])
        self.csv_file.flush()

    def _close_csv(self):
        if self.csv_file:
            self.csv_file.close()
            self.csv_file = None
            self.csv_writer = None

    @staticmethod
    def _pkt_ip_fields(pkt) -> Dict[str, Any]:
        fields = {
            "src": None, "dst": None, "sport": None, "dport": None,
            "proto": None, "length": len(pkt)
        }
        if IP in pkt:
            fields["src"] = pkt[IP].src
            fields["dst"] = pkt[IP].dst
            proto = pkt[IP].proto
            if TCP in pkt:
                fields["proto"] = "TCP"
                fields["sport"] = pkt[TCP].sport
                fields["dport"] = pkt[TCP].dport
            elif UDP in pkt:
                fields["proto"] = "UDP"
                fields["sport"] = pkt[UDP].sport
                fields["dport"] = pkt[UDP].dport
            elif ICMP in pkt:
                fields["proto"] = "ICMP"
            else:
                fields["proto"] = str(proto)
        elif IPv6 in pkt:
            fields["src"] = pkt[IPv6].src
            fields["dst"] = pkt[IPv6].dst
            if TCP in pkt:
                fields["proto"] = "TCP"
                fields["sport"] = pkt[TCP].sport
                fields["dport"] = pkt[TCP].dport
            elif UDP in pkt:
                fields["proto"] = "UDP"
                fields["sport"] = pkt[UDP].sport
                fields["dport"] = pkt[UDP].dport
            else:
                fields["proto"] = "IPv6"
        return fields

    @staticmethod
    def _parse_http(pkt) -> Dict[str, Optional[str]]:
        http = {"host": None, "path": None, "ua": None}
        try:
            if TCP in pkt and Raw in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                if 80 in (sport, dport):
                    payload: bytes = bytes(pkt[Raw].load)
                    # Basic check for HTTP request methods
                    if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")):
                        lines = payload.split(b"\r\n")
                        if lines:
                            # Request line: e.g., "GET /path HTTP/1.1"
                            parts = lines[0].split()
                            if len(parts) >= 2:
                                http["path"] = parts[1].decode(errors="ignore")
                        for line in lines[1:]:
                            if line.lower().startswith(b"host:"):
                                http["host"] = line.split(b":", 1)[1].strip().decode(errors="ignore")
                            elif line.lower().startswith(b"user-agent:"):
                                http["ua"] = line.split(b":", 1)[1].strip().decode(errors="ignore")
                        return http
        except Exception:
            pass
        return http

    @staticmethod
    def _suspicion_hint(pkt) -> Optional[str]:
        # Very basic: SYN without ACK → possible (half-open) scan
        try:
            if TCP in pkt:
                flags = pkt[TCP].flags
                syn = flags & 0x02
                ack = flags & 0x10
                rst = flags & 0x04
                fin = flags & 0x01
                psh = flags & 0x08
                if syn and not ack:
                    return "possible_scan_syn"
                if rst and not ack and not syn:
                    return "possible_reset_flood"
                if fin and not ack and not syn and not psh:
                    return "possible_fin_scan"
        except Exception:
            return None
        return None

    def _handle_packet(self, pkt):

        print(pkt.summary()) 

        if not self.running:
            return

        self.counters["total"] += 1

        meta = self._pkt_ip_fields(pkt)
        suspicion = self._suspicion_hint(pkt)

        # protocol counters
        if meta["proto"] == "TCP":
            self.counters["tcp"] += 1
        elif meta["proto"] == "UDP":
            self.counters["udp"] += 1
        elif meta["proto"] == "ICMP":
            self.counters["icmp"] += 1

        http = self._parse_http(pkt)
        is_http = bool(http["host"] or http["path"] or http["ua"])
        if is_http:
            self.counters["http"] += 1

        if self.args.http_only and not is_http:
            return  # skip non-HTTP when --http-only is set

        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        info = ""
        if meta["proto"] == "TCP" and is_http:
            info = "HTTP request"
        elif DNS in pkt and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                info = f"DNS Q: {qname}"
            except Exception:
                info = "DNS query"
        elif meta["proto"]:
            info = meta["proto"]

        # Console output
        if not self.args.summary:
            src = f"{meta['src']}:{meta['sport']}" if meta["sport"] else meta["src"]
            dst = f"{meta['dst']}:{meta['dport']}" if meta["dport"] else meta["dst"]
            line = f"[{ts}] {src} -> {dst} {info} len={meta['length']}"
            if suspicion:
                line += f"  !!! {suspicion}"
            if is_http and (http["host"] or http["path"]):
                line += f"  HTTP {http['host'] or ''}{http['path'] or ''}"
            print(line)

        # CSV logging
        if self.csv_writer:
            self.csv_writer.writerow([
                ts, meta["src"], meta["sport"], meta["dst"], meta["dport"],
                meta["proto"], meta["length"], info, http["host"], http["path"],
                http["ua"], suspicion
            ])
            self.csv_file.flush()

        # PCAP collection
        if self.args.pcap_out is not None:
            self.pcap_packets.append(pkt)

        
    def _graceful_stop(self, *_):
        self.running = False
        print("\n[+] Stopping... writing outputs (if any).")

        # PCAP output
        if getattr(self.self_args, "pcap_out", None) and self.pcap_packets:
            try:
                wrpcap(self.self_args.pcap_out, self.pcap_packets, append=False)
                print(f"[+] PCAP written: {self.self_args.pcap_out}")
            except Exception as e:
                print(f"[!] Failed to write PCAP: {e}")

        # CSV output
        self._close_csv()

        # Print quick counters
        print(
            f"[Stats] total={self.counters['total']} "
            f"tcp={self.counters['tcp']} udp={self.counters['udp']} "
            f"icmp={self.counters['icmp']} http={self.counters['http']}"
        )

        sys.exit(0)


    def run(self):
        # Wire up signal handlers
        signal.signal(signal.SIGINT, self._graceful_stop)
        signal.signal(signal.SIGTERM, self._graceful_stop)

        # CSV if requested
        self._open_csv()

        iface = self.args.iface or conf.iface
        bpf = self.args.filter

        print(f"[+] Sniffing on: {iface}")
        if bpf:
            print(f"[+] BPF filter: {bpf}")
        if self.args.count:
            print(f"[+] Packet count limit: {self.args.count}")
        if self.args.timeout:
            print(f"[+] Timeout: {self.args.timeout}s")
        if self.args.csv_out:
            print(f"[+] CSV log: {self.args.csv_out}")
        if self.args.pcap_out:
            print(f"[+] PCAP path: {self.args.pcap_out}")
        if self.args.http_only:
            print(f"[+] HTTP-only mode enabled")

        # Start sniffer
        sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf,
            prn=self._handle_packet,
            store=False,
            count=self.args.count if self.args.count > 0 else 0
        )
        sniffer.start()

        # Wait for timeout or signals
        start = time.time()
        try:
            while self.running:
                if self.args.timeout and (time.time() - start) >= self.args.timeout:
                    self._graceful_stop()
                time.sleep(0.2)
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass


if __name__ == "__main__":
    Main().run()
