<div align="center">
<img src="https://capsule-render.vercel.app/api?type=slice&color=0:001233,100:023e8a&height=120&text=📡%20NetSentinel&fontSize=40&fontColor=00b4d8&fontAlignY=70&rotate=-5" width="100%"/>

<br/>

> *"Every packet tells a story. NetSentinel reads them all."*

[![Live Detection](https://img.shields.io/badge/⚡_LIVE_DETECTION-00b4d8?style=for-the-badge)]()
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![No Root Demo](https://img.shields.io/badge/Demo_Mode-No_Root_Needed-90e0ef?style=for-the-badge)]()
[![IDS](https://img.shields.io/badge/7_Threat_Rules-023e8a?style=for-the-badge)]()

</div>

---

## 🛰️ What It Detects — In Real Time

```
12:34:57  TCP  10.0.0.99 ──────────────────→ 192.168.1.1:22  [SYN]  60B
12:34:57  TCP  10.0.0.99 ──────────────────→ 192.168.1.1:80  [SYN]  60B
12:34:57  TCP  10.0.0.99 ──────────────────→ 192.168.1.1:443 [SYN]  60B
          ... 13 more ports ...

  ╔══════════════════════════════════════════════════════╗
  ║  🔴 [HIGH] PORT_SCAN                                 ║
  ║  10.0.0.99 scanned 16 distinct ports in 10s         ║
  ║  Ports: [21,22,80,443,3306,5432,8080,8443,9200...]  ║
  ╚══════════════════════════════════════════════════════╝

12:34:58  TCP  172.16.0.1 ─────────────────→ 192.168.1.1:80  [SYN]  (×102)

  ╔══════════════════════════════════════════════════════╗
  ║  🚨 [CRITICAL] SYN_FLOOD                            ║
  ║  172.16.0.1 → 102 SYN packets in 10 seconds        ║
  ╚══════════════════════════════════════════════════════╝
```

---

## 🧠 Detection Engine

| Rule | Trigger | Severity |
|---|---|---|
| `PORT_SCAN` | 15+ distinct ports from one IP / 10s | 🔴 HIGH |
| `SYN_FLOOD` | 100+ SYN packets from one IP / 10s | 🚨 CRITICAL |
| `DNS_EXFILTRATION` | 30+ DNS queries from one IP / 10s | 🔴 HIGH |
| `ICMP_FLOOD` | 50+ ICMP packets from one IP / 10s | 🔴 HIGH |
| `SUSPICIOUS_PORT` | Traffic on 4444, 31337, 1337, 6969… | 🔴 HIGH |
| `CLEARTEXT_CREDS` | FTP / Telnet / POP3 / IMAP session | 🟡 MEDIUM |
| `LARGE_PAYLOAD` | Single packet > 65 KB | 🟡 MEDIUM |

---

## ⚡ Quick Start

```bash
git clone https://github.com/SRINIVASAN55/NetSentinel
cd NetSentinel

# ── Demo mode (no sudo, no install needed) ──────────────
python netsentinel.py --demo -d 30

# ── Live capture on eth0 (Linux, requires sudo) ─────────
sudo python netsentinel.py -i eth0 -d 120

# ── Save JSON report ────────────────────────────────────
sudo python netsentinel.py -i eth0 -d 60 -o report.json
```

---

## 📊 Traffic Stats Dashboard

```
  Protocol Distribution:
    TCP      1,847  ████████████████████████
    UDP        423  █████
    ICMP        89  █

  Top Talkers:
    192.168.1.5     612 packets
    10.0.0.99       289 packets   ← suspicious

  Top Ports:
    443    HTTPS     891 connections
    53     DNS       210 connections
    4444   ???         3 connections  ⚠
```

---

<p align="center">
  Built by <a href="https://github.com/SRINIVASAN55">SRINIVASAN55</a> ·
  <a href="https://linkedin.com/in/srinivasan132">LinkedIn</a>
</p>
