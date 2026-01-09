# 🛡️ NawaSec Framework v1.5 [Ultimate Edition]

> **"Power & Precision"** - The Advanced Pentest Suite.
> *Featuring Dual-Engine Architecture & Smart Calibration.*

![Bash](https://img.shields.io/badge/Language-Bash_5.0-blue?logo=gnu-bash&style=flat-square)
![Version](https://img.shields.io/badge/Version-1.5-success?style=flat-square)
![Logic](https://img.shields.io/badge/Logic-Hybrid-purple?style=flat-square)
![Status](https://img.shields.io/badge/Status-Stable-blue?style=flat-square)

**NawaSec v1.5** adalah framework penetrasi testing modular yang menggabungkan kecepatan native Bash dengan kekuatan tools eksternal (Hydra, Nmap, Curl). Dirancang untuk stabilitas dan pelaporan profesional.

---

## ⚡ Fitur Utama (v1.5 Power-Ups)

### 🤠 [R3] FTP Bruteforce (Dual-Engine)
*   **Smart Login**: Otomatis mendeteksi dan mencoba login `anonymous` sebelum melakukan brute force.
*   **Hydra Turbo**: Integrasi seamless dengan `hydra` untuk kecepatan 10x lipat. Fallback otomatis ke Native Bash jika Hydra tidak ada.

### 🕵️ [R7] Webshell Finder (Content Aware)
*   **Soft 404 Calibration**: Anti-Prank. Otomatis mengenali halaman error palsu (Soft 404) untuk meminimalisir false positives.
*   **Dual Mode**: 
    *   *Deep Scan*: Menggunakan built-in wordlist (130+ path webshell populer).
    *   *Brute Mode*: Support eksternal wordlist via `-w`.

### 📡 [R11] Nmap Port Scanner (Hybrid)
*   **HTML-Ready**: Output Nmap diparsing ke format JSON terstruktur.
*   **Smart Inventory**: Mendeteksi Service & Version secara detail untuk ditampilkan di laporan.

### 🎰 [R4] Judi Online Hunter (AI-Logic)
*   **Cloaking Detection**: Algoritma cerdas untuk mendeteksi situs judi yang menyamar (hanya muncul untuk Googlebot/Mobile).
*   **Live Validation**: Verifikasi aktif memastikan target benar-benar "Gacor" atau hanya sisa hack index.

---

## 💎 Visual & Reporting
*   **HTML Reporting v1.5**: Dashboard interaktif dengan tabel, sorting, dan highlighting.
*   **JSON logging**: Semua modul menghasilkan log JSON standar untuk kemudahan parsing.
*   **Clean Output**: Sistem folder terstruktur di `results_nawasec/`.

---

## 📖 Cara Penggunaan

### Instalasi & Run
```bash
chmod +x nawasec.sh
./nawasec.sh
```

### Menu Mode (Interaktif)
Jalankan tanpa argumen untuk masuk ke menu GUI berbasis teks (Wizard).

### CLI Mode (Profesional)
```bash
# Contoh: Scan Webshell pada target spesifik
./nawasec.sh --module filescan --target https://example.com

# Contoh: Scan Port dengan Nmap
./nawasec.sh --module nmap --target example.com
```

---

## ⚠️ Disclaimer
Tools ini dibuat untuk tujuan **Edukasi dan Audit Keamanan Legal**. Pengembang tidak bertanggung jawab atas penyalahgunaan tools ini untuk tindakan ilegal.
*Respect the law, hack responsibly.*

---
**NawaSec Framework Team** | *Crafted with ❤️ and ☕*
