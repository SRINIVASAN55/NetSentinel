# NetSentinel

*Packet-level network intrusion detection. No agents. No cloud.*

---

You plug it in. It watches. It tells you what's wrong.

NetSentinel captures live traffic and runs it through 7 detection rules — port scanning, ARP spoofing, DNS tunneling, SYN floods, unusual payloads, lateral movement, and C2 beaconing. When something matches, you get an alert with the packet context and a suggested response.

No root? No problem. Run `--demo` and it simulates a real attack scenario so you can evaluate it before deployment.

---

**Detection rules**

```python
RULES = [
    "port_scan",          # >15 unique ports from single source in 60s
    "arp_spoof",          # ARP reply without prior request
    "dns_tunnel",         # payload size > threshold or high-entropy subdomain
    "syn_flood",          # SYN:ACK ratio > 10:1 from single IP
    "payload_anomaly",    # known-bad byte signatures in stream
    "lateral_movement",   # internal SMB/RDP to multiple hosts
    "c2_beacon",          # periodic outbound at fixed intervals
]
```

---

**Running it**

```bash
# Live capture (needs root or cap_net_raw)
sudo python netsentinel.py --interface eth0

# Demo mode — no root needed, simulates attack traffic
python netsentinel.py --demo

# Alert on specific threats only
python netsentinel.py --rules port_scan,c2_beacon --interface eth0

# Write alerts to file
python netsentinel.py --interface eth0 --log alerts.jsonl
```

---

**Output**

```
[14:23:01] ⚠  PORT SCAN      src=192.168.1.105  ports=22,23,80,443,3389,8080…(+11)
[14:23:04] 🔴 SYN FLOOD      src=10.0.0.44      pps=8,400  target=10.0.0.1:80
[14:24:17] ⚠  DNS TUNNEL     src=10.0.0.12      query=aGVsbG8=.evil.io (high entropy)
[14:25:33] 🔴 C2 BEACON      dst=185.220.101.45 interval=240s±2s  (99.1% periodic)
```

---

**Requirements**

- Python 3.8+
- `scapy` for live capture
- Nothing else

---

Made by [S. Srinivasan](https://github.com/SRINIVASAN55)
