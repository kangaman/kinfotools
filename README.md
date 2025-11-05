# KINFO — Incident Response & Recon Toolkit

```
  _  __ _       ____  
 | |/ /(_)_ __ |  _ \ ___  _ __    ___
 | ' / | | '_ \| |_) / _ \| '_ \  / _ \
 | . \ | | | | |  _ < (_) | | | || (_) |
 |_|\_\|_|_| |_|_| \_\___/|_| |_| \___/
```

**Versi:** `1.3` · **Update:** `5 November 2025` · **Kontak:** `https://jejakintel.t.me/`

> Ringkas, sopan, dan efektif — KINFO membantu tim CSIRT melakukan triage awal, enumerasi, dan pemeriksaan cepat.  
> **Catatan penting:** gunakan hanya pada sistem yang kamu miliki atau yang telah mendapatkan izin eksplisit.

---

## Daftar Isi
- [Tentang KINFO](#tentang-kinfo)  
- [Fitur Utama](#fitur-utama)  
- [Persyaratan & Dependensi](#persyaratan--dependensi)  
- [Instalasi](#instalasi)  
- [Penggunaan Cepat (Examples)](#penggunaan-cepat-examples)  
- [Struktur File & Wordlists](#struktur-file--wordlists)  
- [Alur Kerja Rekomendasi (Triage)](#alur-kerja-rekomendasi-triage)  
- [Tips Pengoperasian Aman](#tips-pengoperasian-aman)  
- [Troubleshooting](#troubleshooting)  
- [Pengembangan & Kontribusi](#pengembangan--kontribusi)  
- [Lisensi](#lisensi)  
- [Changelog Singkat](#changelog-singkat)

---

## Tentang KINFO
KINFO adalah toolkit berbasis **Bash** (menu-driven CLI) yang dirancang untuk membantu tim respons insiden dan penetration tester pada tahap reconnaissance dan triage awal. Fitur utamanya: pengumpulan subdomain, enumerasi direktori/file, pemeriksaan `.env`/debug, deteksi webshell, pengecekan WordPress registration, reverse IP lookup, dan utilitas FTP sederhana.

Singkatnya: **cepat menemukan masalah → lakukan verifikasi manual → laporkan**.  
Humor singkat: alat ini cerdas, bukan garang—biar investigasi rapi, bukan rusuh.

---

## Fitur Utama
- Banner & menu interaktif untuk kemudahan penggunaan.  
- **Enhanced Subdomain Finder** (crt.sh, Bufferover, OTX, ThreatCrowd, SecurityTrails + resolving).  
- **Directory / File Enumeration** berdasar `wordlist.txt`.  
- **FTP Bruteforce** via `ftpbrute.txt` (format `user:pass`).  
- **Judi Online Finder** (pencarian kata kunci via `judilist.txt`).  
- **Reverse IP Lookup** (viewdns.info fallback / whois).  
- **Auto HTTPS & Security Headers Check** (HSTS, CSP, X-Frame-Options, dll).  
- **Webshell Finder**: remote path scan & lokal file enumeration (pattern-based).  
- **ENV & Debug Scanner**: temukan `.env`, `phpinfo`, backup DB, swagger, dll.  
- **WordPress Registration Finder**.  
- **Grab Domain dari Zone-H**.  
- **Mini Shell FTP Client** (wrapper sederhana untuk `ftp`).

---

## Persyaratan & Dependensi
**Minimal (harus ada):**
- `bash`, `curl`, `grep`, `find`, `stat`, `sed`, `awk`, `sort`, `uniq`, `wc`

**Direkomendasikan (dipakai fitur tertentu):**
- `jq` (parsing JSON)  
- `nslookup` / `dig` / `host`  
- `nc` (netcat)  
- `ftp` (client)  
- `whois`

**Instalasi dependensi (Debian/Ubuntu contoh):**
```bash
sudo apt update
sudo apt install -y curl grep findutils coreutils jq dnsutils netcat ftp whois
```

---

## Instalasi

1. Clone atau simpan `kinfo.sh` di folder kerja repositori.  
2. Jadikan executable:
```bash
chmod +x kinfo.sh
```
3. Jalankan:
```bash
./kinfo.sh
# atau
bash kinfo.sh
```

---

## Penggunaan Cepat (Examples)

Setelah menjalankan `./kinfo.sh`, ikuti prompt menu.

### 1) Enhanced Subdomain Finder
- Pilih `1` → masukkan `example.com`.  
- Output: `/tmp/subdomains_example.com.txt` dan `kinfo_subdomains_example.com_<timestamp>.txt`.

### 2) Directory / File Enumeration
- Pilih `2` → masukkan `https://sub.example.com`.  
- Pastikan `wordlist.txt` tersedia di folder yang sama.  
- Hasil disimpan: `kinfo_enum_<timestamp>.txt`.

### 3) FTP Bruteforce
- Pilih `3` → masukkan host (port default `21`).  
- Pastikan `ftpbrute.txt` berformat `username:password`.  
- Hasil sukses disimpan: `kinfo_ftp_success_<host>_<timestamp>.txt`.

### 7) Webshell Finder (Dir Scan - remote)
- Pilih `7` → masukkan target URL.  
- Skrip akan memeriksa path umum untuk admin/webshell; hasil di `/tmp/webscan_<timestamp>.txt`.

### 8) Webshell Finder (File Enumeration - lokal)
- Pilih `8` → masukkan path lokal (atau tekan Enter untuk `.`).  
- Skrip memeriksa file PHP/ASP/JSP untuk pola berbahaya (`eval`, `base64_decode`, `gzinflate`, `system`, dll.).

> Untuk automasi / CI: pertimbangkan menambahkan mode non-interaktif (`--target`, `--wordlist`, `--output`) pada pengembangan berikutnya.

---

## Struktur File & Wordlists

Letakkan file pendukung di direktori yang sama dengan `kinfo.sh`:

- `wordlist.txt` — daftar path direktori/file (satu entri per baris).  
- `ftpbrute.txt` — `username:password` per baris untuk brute.  
- `judilist.txt` — kata kunci untuk mendeteksi konten judi.

**Contoh `wordlist.txt`:**
```
admin
login
wp-admin
uploads
config.php
.env
backup.zip
```

---

## Output & temp files (lokasi)

- `/tmp/subdomains_<domain>.txt`  
- `kinfo_subdomains_<domain>_<timestamp>.txt`  
- `/tmp/webscan_<timestamp>.txt`  
- `kinfo_enum_<timestamp>.txt`

> Catatan: pindahkan hasil dari `/tmp` jika ingin menyimpan permanen — `/tmp` biasanya dibersihkan otomatis oleh sistem.

---

## Alur Kerja Rekomendasi (Triage cepat)

1. Jalankan **Subdomain Finder** (menu `1`) untuk mendapatkan cakupan domain.  
2. Pilih subdomain prioritas → jalankan **Directory Enumeration** (menu `2`) memakai `wordlist.txt` kecil dahulu.  
3. Jalankan **ENV & Debug Scanner** (menu `9`) untuk memeriksa kebocoran konfigurasi.  
4. Jika punya akses ke kode sumber: jalankan **Webshell File Enumeration** (menu `8`).  
5. Catat temuan, verifikasi manual (tangkap layar / log server), dan buat laporan insiden resmi.

---

## Tips Pengoperasian Aman

- **Hanya** gunakan pada sistem milikmu atau yang memiliki izin eksplisit.  
- Mulai dari wordlist **kecil → medium → besar** agar tidak memicu proteksi.  
- Terapkan delay / rate-limit bila target sensitif.  
- Simpan semua bukti (screenshot, response body, timestamp) untuk audit.  
- Verifikasi semua temuan secara manual sebelum menyatakan adanya kompromi.

---

## Troubleshooting

- **Permission denied** → jalankan `chmod +x kinfo.sh`.  
- **Missing command** → instal dependensi yang dibutuhkan (`curl`, `jq`, `ftp`, `nc`, dll.).  
- **Wordlist tidak ditemukan** → pastikan `wordlist.txt` ada di folder eksekusi.  
- **API rate limit / response kosong** → beri jeda, atau gunakan API key bila tersedia.  
- **False positives** → periksa body response; lakukan verifikasi manual.

---

## Pengembangan & Kontribusi

Saran peningkatan prioritas:
- Mode non-interaktif (CLI args / `--target`, `--wordlist`, `--output`).  
- Opsi `--delay` / rate-limiting per request.  
- Output terstruktur (JSON / CSV) untuk integrasi SIEM.  
- Dependency-check awal dan installer (`Makefile` atau `setup.sh`).

Jika mau, saya dapat membantu membuat PR contoh untuk:
- Arg parsing sederhana (`getopts`),  
- Menambahkan output JSON untuk modul tertentu, atau  
- Menyediakan `wordlist` terkurasi kecil untuk testing.

---

## Lisensi

Direkomendasikan: **MIT License** (ringan dan permisif).  
Jika setuju, tambahkan file `LICENSE` berisi teks MIT dan sertakan header lisensi di file skrip.

---

## Changelog Singkat

- **v1.3** (5 Nov 2025) — Banner, menu interaktif, enhanced subdomain & utilitas FTP.  
- Fitur: enumerasi file, webshell scan, ENV & debug checks, Zone-H grab.

---

## Penutup & Catatan Hukum

KINFO disediakan sebagai alat bantu untuk riset keamanan dan respons insiden. Penggunaan tanpa izin adalah tanggung jawab pengguna dan dapat melanggar hukum. Pengembang **tidak** bertanggung jawab atas penyalahgunaan.

---

