
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

**## Instalasi**
**Minimal (harus ada):**
- `bash`, `curl`, `grep`, `find`, `stat`, `sed`, `awk`, `sort`, `uniq`, `wc`


---

**## Tentang KINFO**
KINFO adalah toolkit berbasis **Bash** (menu-driven CLI) yang dirancang untuk membantu tim respons insiden dan penetration tester pada tahap reconnaissance dan triage awal. Fitur utamanya: pengumpulan subdomain, enumerasi direktori/file, pemeriksaan `.env`/debug, deteksi webshell, pengecekan WordPress registration, reverse IP lookup, dan utilitas FTP sederhana.

Singkatnya: **cepat menemukan masalah → lakukan verifikasi manual → laporkan**.  
Humor singkat: alat ini cerdas, bukan garang—biar investigasi rapi, bukan rusuh.

---
