<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=6&height=80&text=📡%20NetSentinel&fontSize=34&fontColor=ffffff" width="100%"/>

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Network](https://img.shields.io/badge/Network-Analysis-blue?style=for-the-badge)]()
[![IDS](https://img.shields.io/badge/IDS-Anomaly%20Detection-purple?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Real-time network traffic analyzer and anomaly detection system.**  
Captures raw packets, identifies threats (port scans, SYN floods, C2 traffic, DNS exfiltration) and generates detailed reports — with a **demo mode that needs no root access**.

</div>

---

## ✨ Detection Rules

| Threat | Detection Method | Severity |
|---|---|---|
| 🔍 **Port Scan** | 15+ distinct ports from one IP in 10s | HIGH |
| 🌊 **SYN Flood** | 100+ SYN packets from one IP in 10s | CRITICAL |
| 🧬 **DNS Exfiltration** | 30+ DNS queries from one IP in 10s | HIGH |
| 💥 **ICMP Flood** | 50+ ICMP packets from one IP in 10s | HIGH |
| 👾 **C2 / Backdoor** | Traffic on ports 4444, 31337, 1337, etc. | HIGH |
| 🔓 **Cleartext Creds** | FTP/Telnet/POP3/IMAP sessions detected | MEDIUM |
| 📦 **Large Payload** | Packets >65KB | MEDIUM |

---

## 🚀 Quick Start

```bash
git clone https://github.com/SRINIVASAN55/NetSentinel.git
cd NetSentinel

# Demo mode — no root, no install needed
python netsentinel.py --demo -d 30

# Live capture (requires root on Linux)
sudo python netsentinel.py -i eth0 -d 60

# Capture and save report
sudo python netsentinel.py -i eth0 -d 120 -o report.json
```

---

## 📋 CLI Options

```
  -i INTERFACE  --interface   Network interface (e.g. eth0, wlan0)
  -d DURATION   --duration    Capture duration in seconds (default: 30, 0=infinite)
  -o OUTPUT     --output      JSON report output path
  --demo                      Run in demo/simulation mode (no root needed)
```

---

## 📊 Sample Output

```
[*] Capturing on eth0...

  12:34:56.123  TCP    192.168.1.5        → 8.8.8.8:443/HTTPS [SYN] (64B)
  12:34:56.456  UDP    192.168.1.5        → 8.8.8.8:53/DNS (100B)
  12:34:57.001  TCP    10.0.0.99          → 192.168.1.1:22/SSH [SYN] (60B)

  [ALERT][12:34:57][HIGH] PORT_SCAN: 10.0.0.99 scanned 16 ports
    Detail: [21, 22, 80, 443, 3306, 5432, 8080, 8443, 9200, 6379...]

  [ALERT][12:34:58][CRITICAL] SYN_FLOOD: 172.16.0.1 sent 102 SYNs/10s

─────────────────────────────────────
  Protocol Distribution:
    TCP      1,204  ████████████████████
    UDP        389  ██████
    ICMP        47  █
```

---

## 📄 License

MIT License © 2024 [Srinivasan S](https://github.com/SRINIVASAN55)
