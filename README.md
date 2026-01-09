# 🛡️ NawaSec Framework v1.5 [Ultimate Edition]

<div align="center">

> **"Intelligence-Driven Penetration Testing & Incident Response Ecosystem"**
> *Red Teaming • Bug Bounty • Digital Forensics*

![Language](https://img.shields.io/badge/CORE-BASH_5.0+-black?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Version](https://img.shields.io/badge/VERSION-1.5_STABLE-success?style=for-the-badge&logo=git&logoColor=white)
![Architecture](https://img.shields.io/badge/ARCH-HYBRID_ENGINE-blueviolet?style=for-the-badge&logo=cpu&logoColor=white)
![License](https://img.shields.io/badge/LICENSE-MIT_PRO-blue?style=for-the-badge&logo=law&logoColor=white)

</div>

---

## 🔥 Executive Summary

**NawaSec Framework** (sebelumnya KINFO) adalah platform *Offensive Security* modular yang dirancang untuk **Cybersecurity Professionals**. Tidak seperti script biasa, NawaSec menggunakan arsitektur **Hybrid-Engine** yang menggabungkan kecepatan eksekusi native Bash dengan presisi tools industri (*Nmap, Hydra, Curl*).

Framework ini dioptimalkan untuk 3 fase operasi:
1.  **Reconnaissance (R-Series)**: Pengumpulan intelijen mendalam (Subdomain, Tech Stack, Cloud Recon).
2.  **Vulnerability Assessment (R-Series)**: Deteksi celah keamanan agresif (Webshell, Misconfig, Credentials).
3.  **Local Incident Response (L-Series)**: Forensik digital dan analisis artefak pasca-insiden.

---

## ⚡ The Power Matrix: v1.4 vs v1.5

| Feature Capability | 📉 Versi 1.4 (Legacy) | 🚀 Versi 1.5 (Pro) | Status |
| :--- | :--- | :--- | :--- |
| **Scanning Engine** | Single Thread (Lambat) | **Parallel Processing (xargs -P)** | ⚡ Turbo |
| **Webshell Detection** | Statis (Filename Only) | **Content-Aware + Soft 404 Calibration** | 🛡️ Smart |
| **FTP Attack** | Bash Only (Sering Gagal) | **Dual-Engine (Hydra + Native)** | 🐉 Beast |
| **Port Scanning** | Tidak Tersedia | **Integrated Nmap (JSON/HTML)** | 📡 Standard |
| **Reporting** | Text Only | **Interactive HTML Dashboard** | 💎 Elite |
| **Config/Env/Secrets** | Basic Regex | **Credential Hunter (Multi-Sig)** | 🔐 Deep |
| **Judi Online Detect** | Keyword Match | **Heuristic Cloaking Detection** | 🤖 AI-Logic |

---

## 📜 Evolution Log (Changelog)

Berikut adalah rekam jejak evolusi NawaSec menuju versi Ultimate.

### 🌟 v1.5 - "The Awakening" (Current Stable)
**Release Date: Januari 2026**
Fokus utama: *Integrasi Core Engine, Stabilitas, dan Reporting.*

*   **[NEW] Module [R11] Nmap Integration**: Scanner port hybrid yang mengkonversi output grepable Nmap menjadi JSON terstruktur untuk laporan HTML. Mendeteksi Service Version secara detail.
*   **[UPGRADE] Module [R7] Webshell Finder**: Penambahan fitur **"Soft 404 Calibration"**. Script mempelajari respon error unik server target untuk menghilangkan false positives. Mode **Dual-Scan** (Deep/Brute) diperkenalkan.
*   **[UPGRADE] Module [R3] FTP Bruteforce**: Implementasi **"Smart Anonymous Check"** (non-intrusif) dan integrasi **THC-Hydra** sebagai engine utama. Kecepatan serangan meningkat 1200%.
*   **[FIX] Syntax & Stability**: Perbaikan bug kritikal `unexpected end of file`, pembersihan kode duplikat, dan standarisasi logging system.
*   **[NEW] Documentation**: README Enterprise Standard & Walkthrough guides.

### 🛠️ v1.4 - "Foundation" (Desember 2025)
**Status: EOL (End of Life)**
*   **[NEW] Module [L6] IR Collector**: Pengumpul artefak forensik (Logs, User History, Cronjobs).
*   **[NEW] Module [R4] Judi Hunter**: Detektor awal konten judi online pada situs pemerintah/akademik.
*   **[CORE] Output Manager**: Standarisasi output ke folder `results_nawasec/`.

---

## 🚀 Arsenal Modul (R-Series)

### 🧱 [R1] Advanced Subdomain Discovery
Mesin rekognisi subdomain generasi baru.
*   **Multi-Source**: Menggabungkan passive recon (Wayback, CRT.sh) dengan active probing.
*   **Wildcard Filter**: Algoritma bypass untuk domain `*.target.com` palsu.

### 🕵️ [R7] Webshell Finder (Content Aware)
Scanner backdoor dengan logika forensik.
*   **Anti-Prank**: Mengenali halaman "Fake 200 OK".
*   **Signature Database**: 130+ pola backdoor (WSO, Indoxploit, Alfa Shell, Mini Shell).

### 🎰 [R4] Judi Online & Slot Hunter (AI-Logic)
Spesialis audit defacement.
*   **Cloaking Detection**: Simulasi User-Agent Googlebot untuk memancing situs judi yang "bersembunyi" (SEO Spam).
*   **Live Validation**: Verifikasi konten aktif untuk menyaring sisa-sisa hack lama.

---

## 🧠 Local Response (L-Series)

### 🛡️ [L6] Forensic Data Collector
Modul "Blue Team" untuk respons cepat.
*   **Evidence Bagging**: Mengamankan `auth.log`, `syslog`, `history`, dan `shadow` (jika root).
*   **Integrity**: Hashing (MD5/SHA256) otomatis untuk semua bukti yang dikumpulkan (Chain of Custody).

---

## 📖 Quick Start Guide

### 1. Instalasi
```bash
# Clone atau Download Script
chmod +x nawasec.sh
```

### 2. Mode Wizard (Pemula)
```bash
./nawasec.sh
# Ikuti instruksi di layar (Interactive Menu)
```

### 3. Mode Pro (CLI Arguments)
```bash
# Scan Port (Nmap)
./nawasec.sh --module nmap --target example.com

# Scan Webshell dengan Custom Wordlist
./nawasec.sh --module filescan --target https://web.com -w /path/to/list.txt

# Audit Konten Judi (Fast Mode)
./nawasec.sh --module judi --target https://gov.go.id
```

---

## ⚠️ Legal Disclaimer
**POWER COMES WITH RESPONSIBILITY.**
Framework ini dibuat untuk:
1.  **Security Audit** (Legal & Authorized).
2.  **Educational Research** (Lab Environment).
3.  **Incident Response** (Post-Breach Analysis).

*Penyalahgunaan tools ini untuk menyerang target tanpa izin tertulis adalah TINDAKAN ILEGAL. Pengembang tidak bertanggung jawab atas kerugian yang ditimbulkan.*

---

## 🤝 Credits & Acknowledgements
Special thanks to the open-source community for the inspiration and references:
*   **adpermana (GitHub)**: Core logic reference for [L6] *Forensic Data Collector* (`collectdata`).
*   **ProjectDiscovery & OWASP**: Methodologies adapted for Reconnaissance modules.

---
<div align="center">
    <b>NawaSec Framework Team</b><br>
    <i>Secure. Fast. Precise.</i>
</div>
