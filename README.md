# 🧠 KINFO v1.3 — Incident Response & Pentest Toolkit

![Bash](https://img.shields.io/badge/Language-Bash-blue?logo=gnu-bash)
![Version](https://img.shields.io/badge/Version-1.3-green)
![Updated](https://img.shields.io/badge/Updated-Nov_2025-blueviolet)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **KINFO** adalah toolkit respons insiden dan pemindaian keamanan berbasis CLI yang dirancang untuk **tim CSIRT**, **administrator server**, dan **peneliti keamanan siber**.  
> Versi 1.3 membawa fitur utama **Data Collection System** untuk otomatisasi audit keamanan sistem lokal.

---

## 🆕 Pembaruan Versi 1.3

| Fitur Baru / Ditingkatkan | Deskripsi |
|:---------------------------|:-----------|
| 🧩 **Collect Data (Forensic Collector)** | Mengumpulkan data sistem otomatis: info host, user, login, cron, koneksi jaringan, proses aktif, dan statistik disk. |
| ⚙️ **Pemilahan Mode Remote & Lokal** | Menu CLI kini memisahkan mode Remote Scanner dan Local Incident Response. |
| 📁 **Struktur Output Baru** | Semua hasil disimpan otomatis di `outputkinfo/` dengan timestamp unik. |
| 🧱 **Enhanced Dependency Checker** | Pemeriksaan dependensi wajib dan opsional dengan notifikasi warna. |
| 💾 **Format JSON Terpadu** | Semua modul mendukung `--output-format json` untuk integrasi SIEM / Wazuh. |
| 🧰 **Parallel Execution** | Pemrosesan paralel lebih efisien pada subdomain, direnum, dan judi finder. |

---

## 📦 Instalasi

```bash
# Clone repository
git clone https://github.com/kangaman/kinfo.git
cd kinfo

# Jadikan executable
chmod +x kinfo.sh
```

**Dependensi wajib:**
```
curl, grep, jq, find, stat, sed, sort, uniq, wc, mktemp
```

**Dependensi opsional:**
```
nslookup, ftp, whois, netstat, ss, last, lastlog, ps
```

---

## ⚙️ Penggunaan

### 🎛️ Mode Interaktif (CLI Menu)

```bash
./kinfo.sh
```

Pilih mode:
- `[R] Remote Scanner`
- `[L] Local Incident Response`
- `[Q] Quit`

### ⚡ Mode Non-Interaktif (Otomatisasi CLI)

Contoh:
```bash
# Subdomain Finder
./kinfo.sh --module subdomain -t example.com -f json

# Directory Enumeration
./kinfo.sh --module direnum -t https://example.com -w wordlist.txt

# Collect Data (Lokal)
./kinfo.sh --module collectdata --output-format json
```

---

## 🧭 Struktur Modul

### 🌐 Remote Scanner
| Kode | Modul | Deskripsi |
|------|--------|-----------|
| R1 | subdomain | Enhanced Subdomain Finder |
| R2 | direnum | Directory/File Enumeration |
| R3 | ftpbrute | FTP Brute Force |
| R4 | judi | Judi Online Finder |
| R5 | reverseip | Reverse IP Lookup |
| R6 | extract | Extract Domain & Header Check |
| R7 | webscan | Webshell Finder (remote dirscan) |
| R8 | envscan | ENV & Debug Method Scanner |
| R9 | wpcheck | WordPress Registration Finder |
| R10 | zoneh | Grab Domain dari Zone-H |

---

### 💻 Local Incident Response
| Kode | Modul | Fungsi |
|------|--------|--------|
| L1 | filescan | Pendeteksi webshell lokal berbasis pattern |
| L2 | localps | Analisis proses mencurigakan |
| L3 | localnet | Pengecekan koneksi jaringan aktif |
| L4 | localusers | Audit user login dan akun aktif |
| L5 | localcron | Analisis cron job mendalam |
| L6 | ftpclient | Mini FTP Shell Interaktif |
| L7 | collectdata 🆕 | Koleksi data sistem otomatis untuk analisis forensik |

---

## 🧩 Fitur Baru — `Collect Data`

Fitur ini merupakan hasil pengembangan dari referensi GitHub [adpermana](https://github.com/adpermana), namun dimodifikasi untuk mendukung:
- Audit lokal tanpa dependensi tambahan.
- Output dalam **JSON** (untuk integrasi dengan Wazuh/ELK).
- Logging interaktif dengan warna dan timestamp.
- Kompatibel untuk **Ubuntu**, **Debian**, **CentOS**, dan **Kali Linux**.

Contoh hasil output (JSON):
```json
{
  "hostname": "server01",
  "os": "Ubuntu 22.04 LTS",
  "uptime": "3 days, 4:22",
  "users_logged_in": ["root", "www-data"],
  "network_connections": ["ESTABLISHED :22", "LISTEN :80"],
  "cron_jobs": ["root - /usr/bin/backup.sh"],
  "disk_usage": "45%",
  "timestamp": "2025-11-05T09:10:12Z"
}
```

Lokasi penyimpanan:  
```
outputkinfo/collect_<timestamp>.json
```

---

## 📁 Struktur Output

```
outputkinfo/
 ├── kinfo_subdomain_1730788322.txt
 ├── kinfo_filescan_1730788345.json
 ├── kinfo_collect_1730788370.json
 └── logs/
```

---

## 🧠 Tips Operasional

- Jalankan dengan flag `--debug` untuk melihat proses detail.
- Gunakan format `--output-format json` agar mudah diolah oleh SIEM.
- Hasil `collectdata` dapat dipakai untuk baseline konfigurasi sistem.
- Disarankan dijalankan sebagai **root** agar semua data bisa dikumpulkan penuh.

---

## ⚙️ Troubleshooting

| Masalah | Penyebab | Solusi |
|----------|-----------|--------|
| `Dependensi wajib tidak ditemukan` | `jq`, `curl`, atau `grep` tidak ada | Jalankan `sudo apt install jq curl grep` |
| `Tidak ada output` | Permission error atau mode salah | Jalankan sebagai root / periksa target |
| `Output kosong` | Format target salah | Gunakan domain/IP/URL yang valid |
| `Cannot write to output` | Izin folder `outputkinfo/` | Jalankan `chmod -R 755 outputkinfo` |

---

## 📜 Lisensi

**MIT License**  
© 2025 Saeful Bahri  
Bebas digunakan, dimodifikasi, dan dikembangkan — selama mencantumkan kredit pembuat asli.

---

## 👨‍💻 Pengembang

- **Saeful Bahri** — Pengembang utama & integrasi CSIRT Diskominfo Subang  
- Referensi pengembangan `collectdata`: [adpermana (GitHub)](https://github.com/adpermana)

📎 Telegram: [@jejakintel](https://t.me/jejakintel)  
🌐 Website: [https://cloud.subang.go.id/](https://cloud.subang.go.id/)  
📧 Email: csirt@subang.go.id  

---

> “KINFO 1.3 bukan sekadar scanner, tapi toolkit forensik cepat untuk memahami apa yang benar-benar terjadi di sistemmu.”
