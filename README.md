# 🧠 KINFO v2.8 — Incident Response & Pentest Toolkit

![Bash](https://img.shields.io/badge/Language-Bash-blue?logo=gnu-bash)
![Version](https://img.shields.io/badge/Version-2.8-green)
![Updated](https://img.shields.io/badge/Updated-5_Nov_2025-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **KINFO v2.8** adalah toolkit all-in-one untuk **Incident Response (IR)** dan **Pemindaian Keamanan Jaringan (Pentest)**.  
> Dirancang khusus untuk membantu **tim CSIRT**, **admin server**, dan **peneliti keamanan** dalam melakukan triage cepat, analisis sistem, serta deteksi ancaman secara efisien — baik secara **lokal** maupun **remote**.

---

## 🆕 Pembaruan Utama di Versi 2.8

| 🔧 Fitur Baru | Deskripsi Singkat |
|:--------------|:------------------|
| 🧱 **Logging System & Debug Mode** | Sekarang setiap modul memiliki log berwarna dan flag `--debug` serta `--logfile` untuk audit penuh. |
| ⚙️ **Enhanced Dependency Checker** | Validasi otomatis terhadap dependensi wajib & opsional (curl, jq, nslookup, ftp, netstat, dll). |
| 📁 **Auto Output Directory** | Semua hasil otomatis disimpan di folder `outputkinfo/` lengkap dengan timestamp. |
| 🔄 **Peningkatan Modul Remote** | `subdomain`, `direnum`, `ftpbrute`, `judi`, dan `reverseip` diperbarui dengan performa paralel tinggi dan struktur JSON. |
| 💻 **Peningkatan Modul Lokal (IR)** | `localusers` dan `localcron` kini memberikan hasil lebih detail termasuk siapa yang login, cron user lain, serta modifikasi file penting. |
| 🚀 **CLI dan GUI Mode Terpadu** | Mode `interaktif` dan `non-interaktif` kini sepenuhnya konsisten dan bisa digunakan otomatis di server headless. |
| 🧰 **Lisensi MIT Resmi** | Lisensi MIT sudah tersemat langsung di header script. |
| 🔒 **Improved Error Handling** | Mekanisme `trap` dan cleanup otomatis untuk menghapus file temporer setelah eksekusi. |

---

## 🧭 Struktur Modul

### 🌐 Remote Scanner (Eksternal)

| Modul | Deskripsi |
|:------|:-----------|
| `subdomain` | Subdomain Finder (crt.sh, bufferover.run, AlienVault, ThreatCrowd). |
| `direnum` | Directory & file enumeration menggunakan wordlist. |
| `ftpbrute` | FTP Bruteforce otomatis (username:password list). |
| `judi` | Deteksi konten **judi online** via keyword & Bing dork. |
| `reverseip` | Reverse IP Lookup menggunakan viewdns.info. |
| `extract` | Ekstraksi domain dan header keamanan otomatis. |
| `webscan` | Pemindaian webshell berdasarkan path umum. |
| `envscan` | Deteksi file `.env`, backup, debug, konfigurasi bocor. |
| `wpcheck` | Deteksi halaman registrasi WordPress. |
| `zoneh` | Pengambil domain berdasarkan notifier di Zone-H. |

---

### 💻 Local Incident Response (Internal)

| Modul | Fungsi |
|:------|:--------|
| `filescan` | Deteksi file webshell pada direktori lokal (pattern eval, exec, system, base64_decode, dll). |
| `localps` | Deteksi proses aktif mencurigakan (www-data, apache, nginx, httpd). |
| `localnet` | Analisis koneksi jaringan aktif (LISTEN, ESTABLISHED). |
| `localusers` | Enumerasi user, login aktif, dan perubahan file /etc/passwd. |
| `localcron` | Enumerasi crontab semua user dan direktori cron.* |
| `ftpclient` | Mini FTP shell interaktif bawaan (manual mode). |

---

## ⚙️ Instalasi

```bash
# Clone repository (atau salin langsung script kinfo.sh)
git clone https://github.com/yourrepo/kinfo.git
cd kinfo

# Jadikan executable
chmod +x kinfo.sh
```

> **Catatan:**  
> KINFO hanya membutuhkan tool standar Linux seperti `curl`, `jq`, `grep`, `ps`, `ss`, `netstat`, dan `ftp`.

---

## 🚀 Cara Penggunaan

### 🧩 Mode Interaktif (Menu CLI)
```bash
./kinfo.sh
```
Kemudian pilih salah satu mode:
- `[R] Remote Scanner`
- `[L] Local Incident Response`
- `[Q] Quit`

Contoh tampilan menu:
```
┌──(user)-[KINFO]
└─$ MODE: LOCAL INCIDENT RESPONSE

 [1] Webshell Finder [File Enumeration]
 [2] Pengecekan Proses Mencurigakan
 [3] Pengecekan Koneksi Jaringan
 [4] Pengecekan User & Login
 [5] Pengecekan Cron Mendalam
 [6] Mini Shell FTP Client
 [7] Kembali ke Menu Utama
```

---

### 🧩 Mode Non-Interaktif (CLI Automation)

#### Contoh Remote
```bash
./kinfo.sh --module subdomain -t example.com -o hasil_subdomain.txt
./kinfo.sh --module direnum -t https://example.com -w wordlist.txt --parallel 25
./kinfo.sh --module ftpbrute -t 192.168.1.10:21 --ftp-list ftpbrute.txt
```

#### Contoh Lokal
```bash
./kinfo.sh --module filescan -t /var/www/html -f json
./kinfo.sh --module localnet
./kinfo.sh --module localcron --output-file cronreport.txt
```

---

## 📋 Opsi Lengkap

| Opsi | Fungsi |
|:------|:--------|
| `--module <nama>` | Menentukan modul yang dijalankan. |
| `-t, --target` | Target domain/IP/URL atau direktori lokal. |
| `-w, --wordlist` | Wordlist custom untuk enumerasi direktori. |
| `--ftp-list` | File berisi kombinasi user:password untuk FTP brute. |
| `--judi-list` | File berisi keyword deteksi judi online. |
| `-o, --output-file` | Nama file output hasil scan. |
| `-f, --output-format` | Format output (`text` / `json`). |
| `-p, --parallel` | Jumlah proses paralel (default: 20). |
| `-r, --rate-limit` | Delay antar request (detik). |
| `-l, --logfile` | Simpan log detail ke file tertentu. |
| `-d, --debug` | Aktifkan mode debug (verbose). |
| `-h, --help` | Tampilkan panduan lengkap. |

---

## 📁 Struktur Output

Setiap hasil scan disimpan di:
```
outputkinfo/
 ├── kinfo_subdomain_1730788322.txt
 ├── kinfo_filescan_1730788345.json
 └── kinfo_localnet_1730788367.txt
```

Format JSON sangat cocok untuk integrasi dengan **SIEM, ELK Stack, Splunk, atau Wazuh**.

---

## 🧠 Tips Profesional

- Gunakan **mode JSON (`-f json`)** untuk parsing hasil otomatis.  
- Jalankan **modul lokal (`filescan`, `localnet`, `localps`)** secara berkala di server produksi.  
- Simpan hasil dengan **log file (`-l report.log`)** untuk audit forensik.  
- Gunakan `--debug` untuk menelusuri proses secara detail.

---

## 🧩 Troubleshooting Umum

| Masalah | Kemungkinan Penyebab | Solusi |
|:---------|:--------------------|:--------|
| `Dependensi wajib tidak ditemukan` | `curl`, `grep`, atau `jq` belum terpasang | Jalankan `sudo apt install curl grep jq` |
| Tidak ada hasil scan | Rate-limit terlalu tinggi atau site block UA | Gunakan `--rate-limit 1` atau ubah User-Agent |
| Gagal membuat folder output | Permission folder | Jalankan `sudo ./kinfo.sh` atau ubah izin folder |
| Mode interaktif tidak muncul | Terminal tidak mendukung input | Gunakan shell interaktif (bash/zsh) |

---

## 🧰 Arsitektur Teknis

```
KINFO.sh
│
├── Remote Modules
│   ├── Subdomain Finder
│   ├── Directory Enum
│   ├── FTP Brute
│   ├── Judi Finder
│   ├── Reverse IP
│   ├── Webshell / ENV / WP Checker
│   └── Zone-H Grabber
│
├── Local Modules
│   ├── FileScan
│   ├── LocalPS
│   ├── LocalNet
│   ├── LocalUsers
│   ├── LocalCron
│   └── Mini FTP Client
│
└── Output Manager → outputkinfo/
```

---

## 🧩 Contoh Output

**Subdomain Scan (Text Mode)**
```
KINFO Enhanced Subdomain Finder Results
Target: example.com
Total Found (API): 21 | DNS Live: 12 | HTTP Live: 8
====================================
[200] https://admin.example.com
[403] https://api.example.com
```

**Filescan (JSON Mode)**
```json
[
  {
    "file": "/var/www/html/shell.php",
    "size": "14K",
    "modified": "2025-11-05 09:45:12",
    "matched_keyword": "eval"
  }
]
```

---

## 📜 Lisensi

Lisensi: **MIT License**  
> Bebas digunakan, dimodifikasi, dan dikembangkan — dengan mencantumkan kredit kepada pembuat asli.

---

## 👨‍💻 Pengembang
- **Saeful** — Pengembang utama & integrasi keamanan.    

📎 Telegram: [@jejakintel](https://t.me/jejakintel)  
---

> “KINFO adalah toolkit deteksi yang berpikir seperti penyerang, tapi bekerja seperti analis keamanan.”
