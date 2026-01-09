# 🛡️ NawaSec Framework v1.5 [Enterprise Edition]

> **"Intelligence-Driven Penetration Testing & Incident Response Ecosystem"**
> *Built for Red Teams, Bug Hunters, and Security Analysts.*

![Language](https://img.shields.io/badge/Language-Bash_5.0+-000000?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.5_Ultimate-22c55e?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-3b82f6?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux_|_WSL2_|_MacOS-purple?style=for-the-badge)

**NawaSec Framework** (formerly KINFO) adalah toolkit keamanan siber modular yang dirancang untuk melakukan **Reconnaissance Mendalam**, **Vulnerability Assessment Agresif**, dan **Digital Forensics/Incident Response (DFIR)**.

Dibangun dengan arsitektur **Hybrid-Engine**, NawaSec menggabungkan kecepatan eksekusi native Bash dengan kekuatan tools industri standar (*Nmap, Hydra, Curl, OpenSSL*) untuk memberikan hasil audit yang akurat, terstruktur, dan siap untuk pelaporan eksekutif.

---

## 🚀 Fitur Unggulan (v1.5 Upgrade)

### 🧱 [R1] Advanced Subdomain Discovery
Mesin rekognisi subdomain generasi baru dengan kapabilitas:
*   **Multi-Source Intelligence**: Menggabungkan passive recon (Wayback Machine, CRT.sh) dan active brute-force.
*   **Wildcard Bypass Logic**: Algoritma cerdas untuk memfilter domain wildcard palsu.
*   **Live Validation**: Verifikasi HTTP/S otomatis untuk menyaring domain mati.

### 🤠 [R3] FTP Bruteforce (Dual-Engine Architecture)
Modul serangan kredensial FTP yang adaptif:
*   **Smart Anonymous Check**: Mendeteksi konfigurasi *Anonymous Login* tanpa memicu alarm intrusi berat.
*   **Hydra Turbo Mode**: Integrasi seamless dengan THC-Hydra untuk throughput serangan tinggi (1000+ tries/min).
*   **Legacy Fallback**: Mode "Stealth" menggunakan native FTP client jika Hydra tidak tersedia.

### 🎰 [R4] Judi Online & Slot Hunter (AI-Logic)
Detektor konten ilegal khusus untuk audit kepatuhan (Kominfo/ISP):
*   **Cloaking Detection**: Algoritma heuristik untuk membongkar situs judi yang menyamar (SEO Spam) yang hanya muncul untuk User-Agent Googlebot atau Mobile.
*   **Hybrid Dorking**: Kombinasi Google/Bing Dorks dengan wordlist custom (30 keywords prioritas + external list).
*   **False Positive Reduction**: Validasi konten real-time untuk membedakan situs berita vs situs judi aktif.

### 🕵️ [R7] Webshell Finder (Content Aware)
Scanner backdoor dan web shell dengan presisi tinggi:
*   **Soft 404 Calibration**: Fitur "Anti-Prank" yang mempelajari respon 404 server untuk menghindari ribuan false positives pada server yang dikonfigurasi unik.
*   **Dual-Scan Mode**:
    *   **Deep Scan**: Menggunakan database internal (130+ signature: WSO, Indoxploit, Alfa, Mini Shell).
    *   **Brute Mode**: Dukungan wordlist eksternal masif via flag `-w`.
*   **Heuristic Analysis**: Mengenalis varian shell yang diobfuskasi berdasarkan pola respons HTTP.

### � [R11] Nmap Port Scanner (Integrated)
Pembungkus cerdas untuk Nmap Security Scanner:
*   **Structured Parsing**: Mengkonversi output *Grepable* (`-oG`) Nmap menjadi format JSON terstandarisasi.
*   **HTML Ready**: Menampilkan tabel port terbuka, service version, dan banner dalam laporan HTML interaktif.
*   **Auto-Install**: Mekanisme self-healing untuk menginstal Nmap jika belum tersedia.

### � [L6] IR Collector (Forensic Grade)
Modul respons insiden lokal untuk mengamankan bukti digital:
*   **Artifact Collection**: Mengumpulkan System Logs, Cron Jobs, User History, dan Network Connections.
*   **Evidence Integrity**: Hash verification untuk semua file yang dikumpulkan.
*   **SIEM Compatible**: Output dalam format JSON yang mudah di-ingest oleh Wazuh, Splunk, atau ELK Stack.

---

## � Visualisasi & Pelaporan

Fitur pelaporan NawaSec didesain untuk **C-Level Executives** dan **Technical Teams**:
*   **HTML Dashboard v1.5**: Laporan tunggal interaktif dengan fitur *Search, Sort, & Filter*.
*   **Cyberpunk UI**: Antarmuka CLI dengan tema Neon kontras tinggi untuk visibilitas maksimal di terminal.
*   **Structured JSON**: Semua modul menghasilkan log mentah dalam format JSON (`results_nawasec/*.json`) untuk integrasi API.

---

## � Cara Penggunaan

### Prasyarat
Pastikan sistem operasi berbasis Linux (Kali, Ubuntu, Parrot, atau WSL2 di Windows).

### Instalasi Cepat
```bash
# 1. Berikan izin eksekusi
chmod +x nawasec.sh

# 2. Jalankan (Mode Wizard Interaktif)
./nawasec.sh
```

### Mode CLI (Profesional)
Untuk otomasi atau penggunaan dalam pipeline CI/CD:

```bash
# Scan Webshell dengan Wordlist Custom
./nawasec.sh --module filescan --target https://target-site.com -w /path/to/wordlist.txt

# Scan Port Nmap & Generate HTML Report
./nawasec.sh --module nmap --target 192.168.1.10 --output-format json

# Audit Judi Online (Mode Stealth)
./nawasec.sh --module judi --target https://news-site.com --rate-limit 1
```

---

## 📂 Struktur Proyek
```text
SistemPentest/
├── nawasec.sh          # Core Engine Script (v1.5)
├── README.md           # Dokumentasi Utama
├── CHANGELOG           # Riwayat Versi Detil
├── wordlist.txt        # Built-in Web Wordlist
├── ftpbrute.txt        # Built-in FTP Credentials
├── judilist.txt        # Built-in Gambling Keywords
└── results_nawasec/    # [OUTPUT] Folder Hasil Scan
    ├── *.json          # Log Data Terstruktur
    └── *.html          # Laporan Akhir User-Friendly
```

---

## ⚠️ Disclaimer & Etika
**NawaSec Framework** dikembangkan murni untuk tujuan **Edukasi, Riset Keamanan, dan Audit Legal**.
*   Pengguna bertanggung jawab penuh atas segala tindakan yang dilakukan menggunakan tools ini.
*   Dilarang keras menggunakan framework ini untuk menyerang sistem tanpa izin tertulis dari pemilik (Unauthorized Access).
*   Pengembang tidak bertanggung jawab atas kerusakan atau konsekuensi hukum yang timbul dari penyalahgunaan.

---
**Verified by NawaSec Team** | *Secure. Fast. Precise.*
