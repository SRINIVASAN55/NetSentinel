#!/usr/bin/env python3
"""
NetSentinel - Real-time Network Traffic Analyzer & Anomaly Detector
Author: Srinivasan S (SRINIVASAN55)
Captures and analyzes network packets, detects anomalies, and raises alerts.
"""

import sys
import time
import json
import socket
import struct
import argparse
import threading
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ─── Colors ───────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BLUE="\033[94m"; BOLD="\033[1m"; RESET="\033[0m"

BANNER = f"""{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                     Real-time Network Traffic Analyzer & Anomaly Detector v1.0
{C.RESET}"""

# ─── Data Models ──────────────────────────────────────────────────────────────
@dataclass
class Packet:
    timestamp: float
    src_ip:    str
    dst_ip:    str
    protocol:  str
    src_port:  int = 0
    dst_port:  int = 0
    length:    int = 0
    flags:     str = ""
    payload:   bytes = b""

@dataclass
class Alert:
    timestamp: str
    severity:  str
    rule:      str
    message:   str
    src_ip:    str = ""
    dst_ip:    str = ""
    detail:    str = ""

# ─── Packet Parser ────────────────────────────────────────────────────────────
class PacketParser:
    PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP"}
    WELL_KNOWN_PORTS = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
        3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 6379:"Redis",
        8080:"HTTP-Alt", 27017:"MongoDB", 9200:"Elasticsearch",
    }

    @staticmethod
    def parse_ip(raw: bytes) -> Optional[Packet]:
        try:
            ip_header = raw[:20]
            fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
            proto_num = fields[6]
            src_ip = socket.inet_ntoa(fields[8])
            dst_ip = socket.inet_ntoa(fields[9])
            ihl = (fields[0] & 0xF) * 4
            protocol = PacketParser.PROTOCOLS.get(proto_num, f"PROTO-{proto_num}")
            pkt = Packet(timestamp=time.time(), src_ip=src_ip, dst_ip=dst_ip,
                         protocol=protocol, length=len(raw))
            transport = raw[ihl:]
            if proto_num == 6 and len(transport) >= 20:    # TCP
                tcp = struct.unpack("!HHLLBBHHH", transport[:20])
                pkt.src_port = tcp[0]; pkt.dst_port = tcp[1]
                flags_byte = tcp[5]
                flag_bits = {0x01:"FIN",0x02:"SYN",0x04:"RST",0x08:"PSH",0x10:"ACK",0x40:"URG"}
                pkt.flags = "|".join(v for k, v in flag_bits.items() if flags_byte & k)
                pkt.payload = transport[20:]
            elif proto_num == 17 and len(transport) >= 8:  # UDP
                udp = struct.unpack("!HHHH", transport[:8])
                pkt.src_port = udp[0]; pkt.dst_port = udp[1]
                pkt.payload = transport[8:]
            return pkt
        except Exception:
            return None

# ─── Detection Engine ─────────────────────────────────────────────────────────
class DetectionEngine:
    # Thresholds
    PORT_SCAN_THRESHOLD = 15       # distinct ports in TIME_WINDOW
    SYN_FLOOD_THRESHOLD = 100      # SYN packets in TIME_WINDOW
    DNS_EXFIL_THRESHOLD = 30       # DNS queries from one IP in TIME_WINDOW
    ICMP_FLOOD_THRESHOLD = 50      # ICMP packets in TIME_WINDOW
    LARGE_PAYLOAD_THRESHOLD = 65000
    TIME_WINDOW = 10               # seconds

    # Suspicious ports
    SUSPICIOUS_PORTS = {4444,5555,6666,7777,8888,9999,1234,31337,12345,
                        54321,4321,1337,6969,6660,6661,6662,6663,6664,6665}

    # Plaintext credentials protocols
    CLEARTEXT_PORTS = {21:"FTP",23:"Telnet",110:"POP3",143:"IMAP",25:"SMTP"}

    def __init__(self):
        self.alerts: List[Alert] = []
        self.lock = threading.Lock()
        self._ip_ports:   Dict[str, set]  = defaultdict(set)
        self._syn_counts: Dict[str, int]  = defaultdict(int)
        self._dns_counts: Dict[str, int]  = defaultdict(int)
        self._icmp_count: Dict[str, int]  = defaultdict(int)
        self._last_reset  = time.time()

    def _reset_if_needed(self):
        if time.time() - self._last_reset > self.TIME_WINDOW:
            self._ip_ports.clear(); self._syn_counts.clear()
            self._dns_counts.clear(); self._icmp_count.clear()
            self._last_reset = time.time()

    def _alert(self, severity, rule, message, src="", dst="", detail=""):
        a = Alert(timestamp=datetime.now().strftime("%H:%M:%S"),
                  severity=severity, rule=rule, message=message,
                  src_ip=src, dst_ip=dst, detail=detail)
        with self.lock:
            self.alerts.append(a)
        color = {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,"MEDIUM":C.YELLOW,"LOW":C.GREEN}.get(severity,C.CYAN)
        print(f"\n  {color}[ALERT][{a.timestamp}][{severity}] {rule}: {message}{C.RESET}")
        if detail: print(f"    Detail: {detail}")

    def analyze(self, pkt: Packet):
        self._reset_if_needed()

        # Port scan detection
        if pkt.dst_port:
            self._ip_ports[pkt.src_ip].add(pkt.dst_port)
            if len(self._ip_ports[pkt.src_ip]) > self.PORT_SCAN_THRESHOLD:
                self._alert("HIGH","PORT_SCAN",
                    f"{pkt.src_ip} scanned {len(self._ip_ports[pkt.src_ip])} ports",
                    src=pkt.src_ip, dst=pkt.dst_ip,
                    detail=f"Ports: {sorted(self._ip_ports[pkt.src_ip])[-10:]}")
                self._ip_ports[pkt.src_ip].clear()

        # SYN flood detection
        if pkt.protocol == "TCP" and "SYN" in pkt.flags and "ACK" not in pkt.flags:
            self._syn_counts[pkt.src_ip] += 1
            if self._syn_counts[pkt.src_ip] > self.SYN_FLOOD_THRESHOLD:
                self._alert("CRITICAL","SYN_FLOOD",
                    f"SYN flood from {pkt.src_ip}: {self._syn_counts[pkt.src_ip]} SYNs/{self.TIME_WINDOW}s",
                    src=pkt.src_ip, dst=pkt.dst_ip)
                self._syn_counts[pkt.src_ip] = 0

        # DNS exfiltration
        if pkt.dst_port == 53 or pkt.src_port == 53:
            self._dns_counts[pkt.src_ip] += 1
            if self._dns_counts[pkt.src_ip] > self.DNS_EXFIL_THRESHOLD:
                self._alert("HIGH","DNS_EXFILTRATION",
                    f"Suspicious DNS burst from {pkt.src_ip}: {self._dns_counts[pkt.src_ip]} queries/{self.TIME_WINDOW}s",
                    src=pkt.src_ip)
                self._dns_counts[pkt.src_ip] = 0

        # ICMP flood
        if pkt.protocol == "ICMP":
            self._icmp_count[pkt.src_ip] += 1
            if self._icmp_count[pkt.src_ip] > self.ICMP_FLOOD_THRESHOLD:
                self._alert("HIGH","ICMP_FLOOD",
                    f"ICMP flood from {pkt.src_ip}: {self._icmp_count[pkt.src_ip]} packets/{self.TIME_WINDOW}s",
                    src=pkt.src_ip)
                self._icmp_count[pkt.src_ip] = 0

        # Suspicious ports (C2, backdoors)
        if pkt.dst_port in self.SUSPICIOUS_PORTS or pkt.src_port in self.SUSPICIOUS_PORTS:
            port = pkt.dst_port or pkt.src_port
            self._alert("HIGH","SUSPICIOUS_PORT",
                f"Traffic on suspicious port {port} — possible C2/backdoor",
                src=pkt.src_ip, dst=pkt.dst_ip)

        # Cleartext credentials
        if pkt.dst_port in self.CLEARTEXT_PORTS:
            svc = self.CLEARTEXT_PORTS[pkt.dst_port]
            if pkt.payload and len(pkt.payload) > 3:
                self._alert("MEDIUM","CLEARTEXT_CREDENTIALS",
                    f"Cleartext {svc} session detected on port {pkt.dst_port}",
                    src=pkt.src_ip, dst=pkt.dst_ip)

        # Large payload anomaly
        if pkt.length > self.LARGE_PAYLOAD_THRESHOLD:
            self._alert("MEDIUM","LARGE_PAYLOAD",
                f"Unusually large packet from {pkt.src_ip}: {pkt.length} bytes",
                src=pkt.src_ip, dst=pkt.dst_ip)

        # RST flood
        if pkt.protocol == "TCP" and "RST" in pkt.flags:
            if "FIN" not in pkt.flags and "ACK" not in pkt.flags:
                pass  # Could track RST counts here

# ─── Traffic Statistics ───────────────────────────────────────────────────────
class TrafficStats:
    def __init__(self):
        self.total_packets = 0; self.total_bytes = 0
        self.proto_counts: Dict[str,int] = defaultdict(int)
        self.top_talkers:  Dict[str,int] = defaultdict(int)
        self.top_ports:    Dict[int,int] = defaultdict(int)
        self._start = time.time()

    def update(self, pkt: Packet):
        self.total_packets += 1
        self.total_bytes   += pkt.length
        self.proto_counts[pkt.protocol] += 1
        self.top_talkers[pkt.src_ip]    += 1
        if pkt.dst_port: self.top_ports[pkt.dst_port] += 1

    def display(self):
        elapsed = max(1, time.time() - self._start)
        print(f"\n{C.BOLD}{'─'*55}{C.RESET}")
        print(f"{C.BOLD}  TRAFFIC STATISTICS  ({elapsed:.0f}s){C.RESET}")
        print(f"{'─'*55}")
        print(f"  Total Packets : {self.total_packets:,}")
        print(f"  Total Bytes   : {self.total_bytes:,} ({self.total_bytes/1024:.1f} KB)")
        print(f"  Packets/sec   : {self.total_packets/elapsed:.1f}")
        print(f"\n  Protocol Distribution:")
        for p, cnt in sorted(self.proto_counts.items(), key=lambda x: -x[1])[:8]:
            bar = "█" * min(30, int(cnt/max(self.total_packets,1)*30))
            print(f"    {p:<8} {cnt:>6,}  {C.CYAN}{bar}{C.RESET}")
        print(f"\n  Top Talkers (src IPs):")
        for ip, cnt in sorted(self.top_talkers.items(), key=lambda x:-x[1])[:5]:
            print(f"    {ip:<20} {cnt:>6,} packets")
        print(f"\n  Top Destination Ports:")
        for port, cnt in sorted(self.top_ports.items(), key=lambda x:-x[1])[:5]:
            svc = PacketParser.WELL_KNOWN_PORTS.get(port, "")
            print(f"    {port:<6} {svc:<12} {cnt:>6,} connections")

# ─── Main Capture Engine ──────────────────────────────────────────────────────
class NetSentinel:
    def __init__(self, interface: str = None, pcap_file: str = None,
                 bpf_filter: str = None, duration: int = 0, output: str = None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.duration  = duration
        self.output    = output
        self.engine    = DetectionEngine()
        self.stats     = TrafficStats()
        self._running  = True
        self._packets: List[Packet] = []

    def _log(self, msg, color=""):
        print(f"{color}{msg}{C.RESET}", flush=True)

    def _capture_live(self):
        """Live packet capture via raw socket (Linux, requires root)."""
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            if self.interface:
                s.bind((self.interface, 0))
            self._log(f"[✓] Capturing on {self.interface or 'all interfaces'} (raw socket)...", C.GREEN)
            start = time.time()
            while self._running:
                if self.duration and time.time() - start > self.duration:
                    break
                try:
                    s.settimeout(1.0)
                    raw, _ = s.recvfrom(65535)
                    pkt = PacketParser.parse_ip(raw)
                    if pkt:
                        self._process(pkt)
                except socket.timeout:
                    continue
            s.close()
        except PermissionError:
            self._log("[!] Raw socket requires root (sudo). Using demo mode...", C.YELLOW)
            self._demo_mode()
        except Exception as e:
            self._log(f"[!] Capture error: {e}. Using demo mode...", C.YELLOW)
            self._demo_mode()

    def _demo_mode(self):
        """Simulate packet capture for demonstration (no root needed)."""
        import random, ipaddress
        self._log("[*] Running in DEMO MODE — simulating network traffic...", C.YELLOW)
        self._log("[*] Run with sudo for live capture.\n", C.YELLOW)
        scenarios = [
            # Normal traffic
            lambda: Packet(time.time(), f"192.168.1.{random.randint(2,50)}",
                          "8.8.8.8", "UDP", src_port=random.randint(1024,65535),
                          dst_port=53, length=random.randint(60,200)),
            lambda: Packet(time.time(), f"192.168.1.{random.randint(2,50)}",
                          "1.1.1.1", "TCP", src_port=random.randint(1024,65535),
                          dst_port=443, flags="SYN", length=random.randint(60,100)),
            # Port scan simulation
            lambda: Packet(time.time(), "10.0.0.99", f"192.168.1.1",
                          "TCP", src_port=random.randint(1024,65535),
                          dst_port=random.choice([22,80,443,3306,5432,8080,8443,9200,6379,3389,
                                                   21,23,25,53,110,143,445,27017,random.randint(1,1024)]),
                          flags="SYN", length=60),
            # SYN flood
            lambda: Packet(time.time(), "172.16.0.1", "192.168.1.1",
                          "TCP", src_port=random.randint(1024,65535),
                          dst_port=80, flags="SYN", length=60),
            # Suspicious port
            lambda: Packet(time.time(), "10.0.0.5", "192.168.1.100",
                          "TCP", src_port=random.randint(1024,65535),
                          dst_port=4444, flags="SYN|ACK", length=100),
        ]
        start = time.time()
        inject_port_scan_at = 5   # seconds
        inject_syn_flood_at = 15
        inject_c2_at = 25
        while self._running:
            elapsed = time.time() - start
            if self.duration and elapsed > self.duration:
                break
            # Normal traffic
            pkt = random.choice(scenarios[:2])()
            self._process(pkt)
            # Anomaly injections
            if 5 < elapsed < 12:
                pkt = scenarios[2]()  # port scan
                self._process(pkt)
            if 15 < elapsed < 20:
                for _ in range(5):    # SYN flood burst
                    self._process(scenarios[3]())
            if 25 < elapsed < 30:
                self._process(scenarios[4]())  # C2 traffic
            time.sleep(0.05)

    def _process(self, pkt: Packet):
        self._packets.append(pkt)
        self.stats.update(pkt)
        self.engine.analyze(pkt)
        # Live packet display (compact)
        svc = PacketParser.WELL_KNOWN_PORTS.get(pkt.dst_port, "")
        ts  = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")[:12]
        flags_str = f" [{pkt.flags}]" if pkt.flags else ""
        port_str  = f":{pkt.dst_port}" + (f"/{svc}" if svc else "") if pkt.dst_port else ""
        print(f"  {C.CYAN}{ts}{C.RESET} {pkt.protocol:<6} "
              f"{pkt.src_ip:<18} → {pkt.dst_ip}{port_str}{flags_str} ({pkt.length}B)", flush=True)

    def save_report(self):
        fname = self.output or f"netsentinel_report_{int(time.time())}.json"
        report = {
            "captured_at": datetime.now().isoformat(),
            "total_packets": self.stats.total_packets,
            "total_bytes": self.stats.total_bytes,
            "alerts": [{"time":a.timestamp,"severity":a.severity,"rule":a.rule,
                        "message":a.message,"src":a.src_ip,"dst":a.dst_ip}
                       for a in self.engine.alerts],
            "protocol_dist": dict(self.stats.proto_counts),
            "top_talkers": dict(sorted(self.stats.top_talkers.items(), key=lambda x:-x[1])[:10]),
        }
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n{C.GREEN}[✓] Report saved: {fname}{C.RESET}")

    def run(self):
        print(BANNER)
        self._log(f"[*] NetSentinel starting...", C.BOLD)
        self._log(f"[*] Duration: {'∞' if not self.duration else f'{self.duration}s'}", C.BOLD)
        self._log(f"[*] Alerts will appear inline below\n", C.BOLD)
        print(f"{'─'*70}")
        print(f"  {'TIME':<13} {'PROTO':<7} {'SRC':<18} {'→'} DST:PORT [FLAGS] (SIZE)")
        print(f"{'─'*70}")
        try:
            self._capture_live()
        except KeyboardInterrupt:
            self._log("\n[*] Stopping...", C.YELLOW)
        self._running = False
        self.stats.display()
        print(f"\n{C.BOLD}  ALERTS SUMMARY ({len(self.engine.alerts)} total):{C.RESET}")
        for a in self.engine.alerts[-20:]:
            color = {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,"MEDIUM":C.YELLOW}.get(a.severity,C.CYAN)
            print(f"  {color}[{a.severity}]{C.RESET} {a.rule}: {a.message}")
        self.save_report()

def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel — Real-time Network Traffic Analyzer & Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python netsentinel.py                          # Live capture, all interfaces
  sudo python netsentinel.py -i eth0 -d 60           # eth0, 60 seconds
  python netsentinel.py --demo -d 30                 # Demo mode (no root needed)
        """
    )
    parser.add_argument("-i","--interface", help="Network interface to capture on")
    parser.add_argument("-d","--duration",  type=int, default=30, help="Capture duration in seconds (0=infinite)")
    parser.add_argument("-o","--output",    help="Output JSON report path")
    parser.add_argument("--demo",           action="store_true", help="Force demo mode (no root required)")
    args = parser.parse_args()
    sentinel = NetSentinel(interface=args.interface, duration=args.duration, output=args.output)
    if args.demo:
        sentinel._demo_mode_force = True
        try:
            sentinel._demo_mode()
        except KeyboardInterrupt:
            pass
        sentinel._running = False
        sentinel.stats.display()
        print(f"\n  ALERTS: {len(sentinel.engine.alerts)}")
        for a in sentinel.engine.alerts:
            color = {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,"MEDIUM":C.YELLOW}.get(a.severity,C.CYAN)
            print(f"  {color}[{a.severity}]{C.RESET} {a.rule}: {a.message}")
        sentinel.save_report()
    else:
        sentinel.run()

if __name__ == "__main__":
    main()
