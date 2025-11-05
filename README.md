+===========================+
| _  _____ _   _ _____ ___  |
| |/ /_ _| \ | |  ___/ _ \ |
| ' / | ||  \| | |_ | | | |
| . \ | || |\  |  _|| |_| |
|_|\_\___|_| \_|_|   \___/ |
+===========================+

# 🧠 KINFO v2.7 — Incident Response & Pentest Toolkit

![Bash](https://img.shields.io/badge/Language-Bash-blue?logo=gnu-bash)
![Version](https://img.shields.io/badge/Version-2.7-green)
![Updated](https://img.shields.io/badge/Updated-5_Nov_2025-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **KINFO** adalah toolkit gabungan untuk **Incident Response lokal** dan **Pemindaian Keamanan Remote**, dibuat untuk membantu tim CSIRT, pentester, dan analis keamanan dalam melakukan triage cepat, enumerasi, serta deteksi anomali sistem.

---

## 🆕 Fitur Baru v2.7

| Fitur | Deskripsi |
|:------|:-----------|
| ⚙️ **Split Menu (Local & Remote)** | Mode interaktif kini dipisah jelas antara `Remote Scanner` dan `Local IR` untuk efisiensi. |
| 💾 **Output Folder Otomatis** | Semua hasil otomatis tersimpan di folder `outputkinfo/` di lokasi script. |
| 🧩 **Parallel Scanning & JSON Output** | Setiap modul mendukung mode paralel dan format output `--output-format json`. |
| 🧰 **Lokal IR Modules Baru** | Tambahan modul: `localusers` (cek login & user) dan `localcron` (cek cron job mendalam). |
| 🧾 **Non-Interaktif CLI Mode** | Jalankan langsung modul tertentu via argumen `--module`. Cocok untuk otomatisasi server. |
| 🧠 **Debug & Logging System** | Gunakan flag `--debug` untuk log detail dan `--logfile` untuk simpan ke file. |

---

## 🧭 Struktur Menu

### 🛰️ **REMOTE SCANNER**
Digunakan untuk enumerasi & pengujian eksternal terhadap domain/IP target.

| Modul | Deskripsi |
|:------|:-----------|
| `subdomain` | Enhanced Subdomain Finder (via crt.sh, bufferover.run, AlienVault, ThreatCrowd). |
| `direnum` | Directory & File Enumeration berbasis wordlist. |
| `ftpbrute` | FTP Bruteforce menggunakan kombinasi username:password. |
| `judi` | Pendeteksi konten **judi online** via keyword & Bing dork. |
| `reverseip` | Reverse IP lookup via viewdns.info & whois fallback. |
| `extract` | Ekstraksi domain + pemeriksaan header keamanan. |
| `webscan` | Pencarian webshell via path umum. |
| `envscan` | Pendeteksian file `.env`, backup, debug, dan konfigurasi sensitif. |
| `wpcheck` | Pendeteksi halaman registrasi pada situs WordPress. |
| `zoneh` | Pengambil domain berdasarkan notifier di Zone-H. |

---

### 💻 **LOCAL INCIDENT RESPONSE**
Untuk investigasi mesin lokal (host tempat script dijalankan).

| Modul | Deskripsi |
|:------|:-----------|
| `filescan` | Memindai file PHP/ASP/JSP mencurigakan (indikasi webshell). |
| `localps` | Menampilkan & memeriksa proses mencurigakan (apache/nginx/php). |
| `localnet` | Cek koneksi jaringan `ESTABLISHED` & `LISTEN`. |
| `localusers` | Menampilkan user login aktif, histori login, dan file `/etc/passwd`. |
| `localcron` | Enumerasi cron job dari semua user & direktori cron. |
| `ftpclient` | Mini shell FTP interaktif bawaan (khusus mode interaktif). |

---

## ⚙️ Instalasi

```bash
# Clone repo atau copy script
git clone https://github.com/yourrepo/kinfo.git
cd kinfo

# Jadikan executable
chmod +x kinfo.sh
```

> 💡 *Tidak perlu dependensi besar — hanya utilitas standar Linux seperti `curl`, `grep`, `jq`, `ps`, `ss`, `netstat`, `ftp`, dan `whois`.*

---

## 🚀 Cara Penggunaan

### 🔹 Mode Interaktif
Jalankan tanpa argumen untuk mode GUI berbasis CLI:
```bash
./kinfo.sh
```
Lalu pilih:
- `[R] Remote Scanner`
- `[L] Local IR`
- `[Q] Quit`

Contoh navigasi:
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

### 🔹 Mode Non-Interaktif (CLI)
Gunakan argumen `--module` untuk menjalankan secara otomatis:

#### Contoh Remote:
```bash
./kinfo.sh --module subdomain -t example.com -o hasil_subdomain.txt
./kinfo.sh --module direnum -t https://example.com -w wordlist.txt --parallel 30
./kinfo.sh --module ftpbrute -t 192.168.1.10:21 --ftp-list ftpbrute.txt
```

#### Contoh Lokal:
```bash
./kinfo.sh --module filescan -t /var/www/html -f json
./kinfo.sh --module localnet
./kinfo.sh --module localcron --output-file croncheck.txt
```

---

## 🧩 Opsi Lengkap

| Opsi | Deskripsi |
|:------|:-----------|
| `--module <nama>` | Menentukan modul yang dijalankan. |
| `-t, --target` | Target domain/IP/URL atau path lokal. |
| `-w, --wordlist` | Wordlist untuk enumerasi direktori. |
| `--ftp-list` | File wordlist FTP (user:pass). |
| `--judi-list` | File keyword untuk deteksi judi online. |
| `-o, --output-file` | Nama file output (akan tersimpan di `outputkinfo/`). |
| `-f, --output-format` | Format output: `text` (default) atau `json`. |
| `-p, --parallel` | Jumlah proses paralel (default: 20). |
| `-r, --rate-limit` | Delay antar request (detik). |
| `-l, --logfile` | File log (opsional). |
| `-d, --debug` | Mode debug dengan output detail. |
| `-h, --help` | Menampilkan bantuan lengkap. |

---

## 📁 Struktur Output

Hasil pemindaian otomatis tersimpan di folder:
```
outputkinfo/
 ├── kinfo_subdomain_1730788322.txt
 ├── kinfo_filescan_1730788345.txt
 └── kinfo_localnet_1730788367.txt
```

Setiap file mencatat waktu scan, target, hasil, dan log penting.

---

## 🧠 Tips Penggunaan

- Gunakan **mode JSON (`-f json`)** untuk integrasi dengan tools SIEM atau parser log.
- Gunakan **`--parallel`** untuk mempercepat enumerasi target besar.
- Jalankan **modul lokal secara berkala** di server produksi untuk deteksi dini (terutama `filescan` & `localnet`).
- Aktifkan **mode debug (`-d`)** saat melakukan troubleshooting.

---

## 🔒 Contoh Output

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

## 🧩 Arsitektur Fungsional

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

## 🧩 Troubleshooting Umum

| Masalah | Penyebab | Solusi |
|:---------|:----------|:--------|
| ❌ `Dependensi wajib tidak ditemukan` | `curl` / `grep` / `jq` belum terinstall | `sudo apt install curl grep jq` |
| ⚠️ Tidak ada hasil scan | Rate limit terlalu tinggi atau site block UA | Gunakan `--rate-limit 1` atau ubah `User-Agent` |
| 🔒 Gagal akses folder output | Permission `outputkinfo` belum dibuat | Jalankan dengan `sudo` atau ubah izin folder |
| 🧩 Mode interaktif tidak muncul | Terminal tidak mendukung `read` | Jalankan di shell interaktif (bash/zsh) |

---

## 🧰 Kontributor

- **Saeful Bahri (CSIRT Diskominfo Subang)** — pengembang utama & integrasi keamanan.  
- **Gemini Refactor Team** — refactoring v2.7, modularisasi, JSON, dan parallel scan.

---

## 📜 Lisensi

Distribusi di bawah lisensi **MIT License**  
> Bebas digunakan, dimodifikasi, dan dikembangkan dengan tetap mencantumkan kredit pembuat asli.

---

### 💬 Kontak
📎 Telegram: [@jejakintel](https://t.me/jejakintel)  
📧 Email: csirt@subang.go.id  
🌐 Website: [https://cloud.subang.go.id/](https://cloud.subang.go.id/)

---

> “KINFO bukan hanya scanner, tapi juga detektor intuisi — bantu tim IR berpikir lebih cepat dari serangan.”
