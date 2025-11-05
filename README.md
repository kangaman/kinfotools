# KINFO — Incident Response & Recon Toolkit

```
+===========================+
| _  _____ _   _ _____ ___  |
| |/ /_ _| \ | |  ___/ _ \ |
| ' / | ||  \| | |_ | | | |
| . \ | || |\  |  _|| |_| |
|_|\_\___|_| \_|_|   \___/ |
+===========================+
```

**Versi:** `2.6` · **Update:** `5 November 2025` · **Contact:** `https://jejakintel.t.me/`

> KINFO adalah toolkit cepat dan modular untuk tim respons insiden (CSIRT) dan pentester — fokus pada reconnaissance, triage lokal & jarak jauh, dan pemeriksaan cepat.  
> **Penting:** gunakan **hanya** pada sistem yang Anda miliki atau yang sudah mendapat izin eksplisit.

---

## Ringkasan versi 2.6 — Apa yang baru / diperbarui
Versi `2.6` membawa beberapa perbaikan dan fitur baru dibanding versi sebelumnya (2.5):

- **Modul Local IR baru:** ditambahkan modul lokal untuk investigasi in-situ:
  - `localps` (Modul 13) — pengecekan proses mencurigakan (user web server umum).
  - `localnet` (Modul 14) — pengecekan koneksi jaringan (LISTEN / ESTABLISHED) menggunakan `ss`/`netstat`.
  - `localusers` (Modul 15) — pemeriksaan user (uid >=1000 / uid 0) dan crontab root/current user.
- **Refactor & Stabilitas:** perapihan struktur kode, generalisasi helper (logging, temp files, cleanup), dan validasi dependensi yang lebih jelas.
- **Mode non-interaktif (CLI):** jalankan per-modul lewat flags (`--module`, `--target`, dsb.) untuk automasi / CI.
- **Output JSON & Logging:** dukungan output `json` untuk integrasi SIEM / pipeline; logging terpisah dengan opsi `--logfile`.
- **Paralelisasi & Rate-limit:** semua modul remote/lokal menggunakan `xargs -P` paralel dan opsi `--parallel/-p` serta `--rate-limit/-r`.
- **ENV & Debug Scanner diperluas (modul 9):** daftar paths diperbanyak (backup .sql, zip/rar, banyak subfolder backup/sql/uploads, swagger/actuator/health, dll).
- **Cleanup file temporer & trap EXIT:** file temporer dikelola rapi dan dihapus saat skrip keluar.
- **Mini FTP client (interaktif)** tetap ada untuk akses cepat, plus peringatan jika modul FTP hanya interaktif.
- **Peningkatan user-agent & dork user-agent** untuk modul pencarian konten (bing dork).

---

## Fitur Utama (ringkas)
- Enhanced Subdomain Finder (crt.sh, bufferover, OTX, ThreatCrowd) + DNS & HTTP live-check.  
- Directory / File Enumeration dengan wordlist + ukuran file (size) dan HTTP status.  
- FTP bruteforce (wordlist `username:password`) dan mini FTP client.  
- Judi Online Finder (keywords + Bing dork).  
- Reverse IP lookup (viewdns.info + fallback whois).  
- Extract domain & security header check (HSTS, CSP, X-Frame-Options).  
- Webshell Finder: remote dirscan + local file enumeration (pattern-based).  
- ENV & Debug Scanner (luas: .env, backup.sql, swagger, actuator, dll.).  
- WordPress registration finder.  
- Zone-H grabber.  
- Local IR modules: process, network, users & cron checks.  
- Non-interactive CLI, JSON output, logging, parallel jobs, rate limiting.  

---

## Persyaratan & Dependensi
**Wajib:** `bash`, `curl`, `grep`, `find`, `stat`, `sed`, `sort`, `uniq`, `wc`, `mktemp`, `xargs`  
**Direkomendasikan / Opsional (mempengaruhi fitur tertentu):** `jq`, `nslookup`/`dig`/`host`, `nc` (netcat), `ftp`, `whois`, `ps`, `ss`/`netstat`, `sudo` (untuk localnet details)

Contoh instalasi (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install -y curl grep findutils coreutils jq dnsutils netcat ftp whois procps iproute2
```

> Skrip akan memeriksa dependensi wajib saat startup dan menolak berjalan jika yang wajib tidak ditemukan. Dependensi opsional hanya akan memperingatkan.

---

## Instalasi
1. Simpan `kinfo.sh` di folder kerja:
```bash
cp kinfo.sh ~/tools/kinfo/kinfo.sh
cd ~/tools/kinfo
```
2. Jadikan executable:
```bash
chmod +x kinfo.sh
```
3. (Opsional) Siapkan wordlists di direktori yang sama:
- `wordlist.txt` — untuk `direnum`, `webscan` fallback  
- `ftpbrute.txt` — untuk `ftpbrute` (format `user:pass`)  
- `judilist.txt` — untuk `judi` module

4. Jalankan:
- Interaktif:
```bash
./kinfo.sh
```
- Non-interaktif (example):
```bash
./kinfo.sh --module subdomain --target example.com -f json -o subdomains.json
```

---

## Cara Penggunaan — Interaktif & CLI (Non-Interaktif)

### Mode Interaktif (menu)
Jalankan `./kinfo.sh` tanpa argumen. Menu akan menampilkan pilihan:
- REMOTE SCANNER: 1..11 (subdomain, direnum, ftpbrute, judi, reverseip, extract, webscan, envscan, wpcheck, zoneh)
- LOCAL IR: 8,12..15 (filescan, ftpclient, localps, localnet, localusers)
- Pilih angka, masukkan target ketika diminta.

Output interaktif disimpan sementara ke `/tmp/kinfo_interactive_<timestamp>.txt`.

### Mode Non-Interaktif (CLI)
Contoh umum:
```bash
./kinfo.sh --module <module> -t <target> -o <output_file> -f json -p 30 -r 0.5 -l kinfo.log
```

Flags penting:
- `--module <name>` : modul, mis. `subdomain`, `direnum`, `filescan`, `envscan`, `localps`, `localnet`, `localusers`  
- `-t, --target <str>` : domain/URL/IP atau path lokal (untuk `filescan`)  
- `-w, --wordlist <file>` : wordlist path (default: `./wordlist.txt`)  
- `--ftp-list <file>` : ftp list path (default: `./ftpbrute.txt`)  
- `--judi-list <file>` : judi list path (default: `./judilist.txt`)  
- `-o, --output-file <file>` : simpan output; default `kinfo_<module>_<ts>.txt` (text) atau `/dev/stdout` bila json  
- `-f, --output-format <fmt>` : `text` (default) atau `json`  
- `-p, --parallel <num>` : jumlah proses paralel (default: 20)  
- `-r, --rate-limit <sec>` : jeda antar permintaan (default: 0)  
- `-l, --logfile <file>` : simpan log (format teks timestamped)  
- `-d, --debug` : aktifkan mode debug (verbose)  
- `-h, --help` : tampilkan pesan bantuan

---

## Contoh Perintah

1. Enhanced Subdomain Finder (JSON output):
```bash
./kinfo.sh --module subdomain --target example.com -f json -o subdomains.json
```

2. Directory enumeration (with custom wordlist, 50 parallel, 0.2s delay):
```bash
./kinfo.sh --module direnum --target https://sub.example.com -w ./wordlist.txt -p 50 -r 0.2 -o found.txt
```

3. Local file scan (scan kode sumber web lokal):
```bash
./kinfo.sh --module filescan --target /var/www/html -p 30 -f json -o suspicious_files.json
```

4. Local network & process checks:
```bash
# check processes (localps)
./kinfo.sh --module localps
# check network (may require sudo)
sudo ./kinfo.sh --module localnet -o localnet.txt
# check users & cron
./kinfo.sh --module localusers -o users_cron.txt
```

5. Run ENV scanner with log:
```bash
./kinfo.sh --module envscan --target example.com -o env_findings.txt -l kinfo_env.log
```

---

## Output & Lokasi File
- Output default untuk non-interactive: `kinfo_<module>_<timestamp>.txt` (text) atau `/dev/stdout` jika `-f json` dan `-o` tidak diberikan.
- Skrip membuat file temporer di `/tmp/kinfo_*` yang dibersihkan otomatis pada exit.
- Gunakan `-l <logfile>` untuk menyimpan log aktivitas dan pesan debug.

---

## Troubleshooting Singkat (versi 2.6)
- **Permission denied** → `chmod +x kinfo.sh`  
- **Missing dependencies** → jalankan `check_dependencies` (scripting) atau install manual paket yang direkomendasikan. Skrip akan exit jika dep wajib tidak ditemukan.  
- **Modul lokal membutuhkan sudo** → `localnet` untuk melihat nama program di `ss`/`netstat` sering butuh sudo.  
- **No results dari API** → periksa koneksi, rate-limit, atau layanan API (crt.sh/bufferover/OTX/ThreatCrowd).  
- **FTP gagal** → server mungkin FTPS; gunakan `lftp` atau `curl --ftp-ssl` eksternal.  
- **False positives** → verifikasi manual; simpan response body atau screenshot untuk bukti.  
- Untuk debug verbose: tambahkan `-d -l kinfo_debug.log` dan kirim log untuk analisis.

---

## Etika & Legal
Gunakan **hanya** untuk audit internal, pentest dengan izin, atau penelitian. Pemindaian tanpa izin dapat menimbulkan konsekuensi hukum.

---

## Changelog Singkat
- **v2.6** (5 Nov 2025) — Tambahan Local IR Modules (13–15), refactor logging/tempfile/cleanup, perbaikan envscan, CLI non-interaktif, JSON output, paralelisasi & rate-limit.  
- **v2.5** — Refactor besar, paralelisasi, mode non-interaktif, JSON, logging, perluasan envscan.  
- Versi awal — fitur enumerasi, webshell scan, Zone-H grab, FTP utilities.

---

## Ingin bantuan tambahan?
Saya bisa langsung:
- Menambahkan `LICENSE` (MIT) file,  
- Menyisipkan `CONTRIBUTING.md` dan `CODE_OF_CONDUCT.md`,  
- Membuat contoh `wordlist.txt` / `judilist.txt` terkurasi kecil untuk testing, atau  
- Membuat PR patch untuk menambahkan `--config` (read config file) atau contoh systemd service.

Ketik singkat (mis. `license`, `contrib`, `wordlist`)—saya akan buatkan file siap pakai.
