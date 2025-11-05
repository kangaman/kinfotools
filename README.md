# kinfotools

`kinfotools` adalah sebuah toolkit script shell yang dirancang untuk **Respon Insiden (Incident Response)** dan **Penetration Testing (Pentest)**. Toolkit ini menyediakan serangkaian alat berbasis menu untuk melakukan berbagai tugas reconnaissance dan pemindaian keamanan.

## Fitur Utama

Toolkit ini menyediakan menu interaktif dengan 12 fungsi utama:

1.  **Enhanced Subdomain Finder:** Mencari subdomain menggunakan berbagai sumber online (seperti crt.sh, bufferover.run, alienvault, dll).
2.  **Directory/File Enumeration:** Melakukan enumerasi direktori dan file pada URL target menggunakan wordlist kustom (`wordlist.txt`).
3.  **FTP Bruteforce (FTP/FTPS):** Mencoba login bruteforce ke server FTP menggunakan daftar username/password dari `ftpbrute.txt`.
4.  **Judi Online Finder:** Secara otomatis mencari konten terkait judi online pada sebuah domain dan subdomainnya menggunakan kata kunci dari `judilist.txt`.
5.  **Reverse IP Lookup:** Menemukan domain lain yang di-hosting pada alamat IP yang sama menggunakan layanan eksternal.
6.  **Extract Domain [Auto Add HTTPS]:** Sebuah utilitas untuk memproses daftar domain (misalnya, dari file) dan secara otomatis menambahkan prefix `https://`.
7.  **Webshell Finder [DirScan]:** Memindai URL target untuk menemukan kemungkinan adanya webshell berdasarkan daftar path umum.
8.  **Webshell Finder [File Enumeration]:** Mencari file webshell di dalam direktori lokal dengan memeriksa konten file untuk kata kunci yang mencurigakan.
9.  **ENV & Debug Method Scanner:** Memindai URL target untuk file konfigurasi sensitif yang terekspos (seperti `.env`) dan metode debug.
10. **WordPress Registration Finder:** Mencari halaman registrasi pengguna yang terbuka pada situs berbasis WordPress.
11. **Grab Domain from Zone-H:** Mengambil daftar domain yang dilaporkan oleh "notifier" tertentu di Zone-H.
12. **Mini Shell FTP Client:** Sebuah klien FTP interaktif sederhana langsung dari shell.

## Persyaratan

Script ini adalah script Bash dan membutuhkan beberapa tools command-line standar agar berfungsi penuh, termasuk:

* `curl`
* `jq` (untuk mem-parsing output JSON dari beberapa API)
* `nslookup`
* `nc` (netcat)
* `whois`
* `find`

### File Pendukung

Beberapa fitur memerlukan file wordlist eksternal yang harus berada di direktori yang sama dengan `kinfo.sh`:

* `wordlist.txt`: Diperlukan oleh fitur Enumerasi Direktori/File.
* `ftpbrute.txt`: Diperlukan oleh fitur FTP Bruteforce.
* `judilist.txt`: Diperlukan oleh fitur Judi Online Finder.

## Cara Penggunaan

1.  Pastikan semua file yang diperlukan (script dan wordlist) berada dalam satu direktori.
2.  Berikan izin eksekusi pada script:
    ```bash
    chmod +x kinfo.sh
    ```
3.  Jalankan script:
    ```bash
    ./kinfo.sh
    ```
4.  Pilih opsi yang diinginkan dari menu yang ditampilkan.

## Informasi

* **Versi:** 1.3 (Update: 5 November 2025)
* **Kontak:** https://jejakintel.t.me/
