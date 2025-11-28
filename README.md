# 🧠 **KINFO v1.4 — Advanced Incident Response & Pentest Toolkit**  
*Premium Edition — Enterprise-Grade Documentation*

![Bash](https://img.shields.io/badge/Language-Bash-blue?logo=gnu-bash)
![Version](https://img.shields.io/badge/Version-1.4-green)
![Updated](https://img.shields.io/badge/Updated-Nov_2025-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Build-Stable-success)

## 🎯 Ringkasan Eksekutif
**KINFO v1.4** adalah toolkit respons insiden, OSINT, dan pemindaian keamanan yang dirancang untuk CSIRT, pentester, dan administrator server.

## 📦 Fitur Utama
### Remote Security Scanner
- Subdomain Engine v1.4  
- Reverse IP Multi-source  
- Webshell Finder Ultimate  
- WordPress Deep Detect  
- Judi/Slot Deep Scanner  

### Local Incident Response Mode
Mengumpulkan artefak lengkap: system info, cron, network, log, disk, credential hunter, dan hashes.

## Diagram Arsitektur (Mermaid)
```mermaid
flowchart TD
    A[User CLI] --> B[KINFO Core Engine]
    B --> C1[Remote Scanner]
    B --> C2[Incident Response Collector]
    C1 --> D1[Subdomain Engine]
    C1 --> D2[Directory Enum]
    C1 --> D3[Judi Scanner]
    C1 --> D4[WP Deep Detect]
    C1 --> D5[Webshell Ultimate]
    C2 --> E1[System Info]
    C2 --> E2[Logs]
    C2 --> E3[Credential Hunter]
```

## Cara Penggunaan
```
bash kinfo.sh
bash kinfo.sh --subdomain example.com
bash kinfo.sh --revip 1.2.3.4
bash kinfo.sh --ir
```

## Struktur Output
```
outputkinfo/
└── 2025-11-27_21-32-02/
    ├── system/
    ├── subdomain/
    ├── reverseip/
    ├── webshell/
    ├── wp-scan/
    ├── judi-scan/
    └── summary.txt
```

## Changelog v1.4
- Integrasi IR Collector  
- Subdomain Engine improved  
- Webshell Ultimate DB  
- Reverse IP Multi-source  
- WP Deep Detect upgrade  
- Deep judi/slot path generator  

## Pengembang
Saeful Bahri — CSIRT Diskominfo Subang

## Lisensi
MIT License
