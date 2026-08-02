# NetSentinel

*Packet-level network intrusion detection. No agents. No cloud.*

---

You plug it in. It watches. It tells you what's wrong.

NetSentinel captures live traffic and runs it through 7 detection rules — port scanning, ARP spoofing, DNS tunneling, SYN floods, unusual payloads, lateral movement, and C2 beaconing. When something matches, you get an alert with the packet context and a suggested response.

No root? No problem. Run `--demo` and it simulates a real attack scenario.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.8 or higher |
| OS | Linux, macOS (Windows: limited, no raw sockets) |
| Root/Admin | Required for live capture only. Demo mode needs nothing. |
| scapy | For live packet capture |

```bash
python3 --version        # must be 3.8+
pip install scapy        # for live capture
```

---

## Installation

```bash
git clone https://github.com/SRINIVASAN55/NetSentinel.git
cd NetSentinel
pip install -r requirements.txt
```

---

## Running It

### Demo mode — no root, no setup, works anywhere
```bash
python3 netsentinel.py --demo
```
Simulates a realistic attack (port scan → SYN flood → C2 beacon) and shows exactly what NetSentinel would alert on. Best way to evaluate it before deployment.

### Live capture on a network interface
```bash
# Find your interface name first
ip link show          # Linux
ifconfig              # macOS

# Start capturing (needs root)
sudo python3 netsentinel.py --interface eth0
sudo python3 netsentinel.py --interface wlan0
sudo python3 netsentinel.py -i eth0
```

### Capture for a fixed duration
```bash
# Capture for 60 seconds then exit
sudo python3 netsentinel.py --interface eth0 --duration 60
sudo python3 netsentinel.py -i eth0 -d 60

# Run indefinitely (default is 30s, use 0 for infinite)
sudo python3 netsentinel.py -i eth0 --duration 0
```

### Save alerts to a JSON report
```bash
sudo python3 netsentinel.py --interface eth0 --output alerts.json
sudo python3 netsentinel.py -i eth0 -d 120 -o /tmp/netsentinel_report.json
```

---

## All CLI Flags

| Flag | Short | Description | Default | Example |
|------|-------|-------------|---------|---------|
| `--interface` | `-i` | Network interface to capture on | — | `-i eth0` |
| `--duration` | `-d` | Capture duration in seconds (0 = infinite) | `30` | `-d 120` |
| `--output` | `-o` | Save JSON report to this path | — | `-o report.json` |
| `--demo` | | Run demo mode, no root needed | — | `--demo` |

---

## Output

```
[14:23:01] ⚠  PORT SCAN      src=192.168.1.105  ports=22,23,80,443,3389,8080…(+11)
[14:23:04] 🔴 SYN FLOOD      src=10.0.0.44      pps=8,400  target=10.0.0.1:80
[14:24:17] ⚠  DNS TUNNEL     src=10.0.0.12      query=aGVsbG8=.evil.io (high entropy)
[14:25:33] 🔴 C2 BEACON      dst=185.220.101.45 interval=240s±2s  (99.1% periodic)
```

---

## Detection Rules

```python
RULES = [
    "port_scan",       # >15 unique ports from single source in 60s
    "arp_spoof",       # ARP reply without prior request
    "dns_tunnel",      # high-entropy subdomain or oversized DNS payload
    "syn_flood",       # SYN:ACK ratio > 10:1 from single IP
    "payload_anomaly", # known-bad byte signatures in stream
    "lateral_movement",# internal SMB/RDP to multiple hosts
    "c2_beacon",       # periodic outbound at fixed intervals
]
```

---

## Troubleshooting

**`Operation not permitted` when starting capture**
→ You need root: `sudo python3 netsentinel.py -i eth0`

**`No module named 'scapy'`**
→ Run `pip install scapy` or `pip3 install scapy`

**Not sure which interface to use?**
→ Run `ip link show` (Linux) or `ifconfig` (macOS). Look for the interface with your IP.

**Want to test without real traffic?**
→ Use `--demo` mode — it works with zero permissions and zero traffic.

---

Made by [S. Srinivasan](https://github.com/SRINIVASAN55)
