#!/bin/bash

# KINFO - Incident Response & Pentest Toolkit
# Versi: 1.4 (Integrasi Kolektor Artefak IR)
#
# Hak Cipta (c) 2025 Saeful
# Kontak: https://jejakintel.t.me/
#
# Dilisensikan di bawah Lisensi MIT. Lihat file LICENSE terlampir atau di:
# https://opensource.org/licenses/MIT
#
# --- Lisensi MIT ---
#
# Dengan ini diberikan izin, tanpa biaya, kepada siapa pun yang memperoleh salinan
# perangkat lunak ini dan file dokumentasi terkait ("Perangkat Lunak"), untuk berurusan
# dalam Perangkat Lunak tanpa batasan, termasuk namun tidak terbatas pada hak
# untuk menggunakan, menyalin, memodifikasi, menggabungkan, menerbitkan, mendistribusikan, mensublisensikan,
# dan/atau menjual salinan Perangkat Lunak, dan untuk mengizinkan orang yang menerima
# Perangkat Lunak untuk melakukan hal yang sama, dengan tunduk pada ketentuan berikut:
#
# Pemberitahuan hak cipta di atas dan pemberitahuan izin ini harus disertakan dalam semua
# salinan atau bagian substansial dari Perangkat Lunak.
#
# PERANGKAT LUNAK INI DISEDIAKAN "SEBAGAIMANA ADANYA", TANPA JAMINAN APA PUN, BAIK TERSURAT MAUPUN
# TERSIRAT, TERMASUK NAMUN TIDAK TERBATAS PADA JAMINAN DAPAT DIPERDAGANGKAN,
# KESESUAIAN UNTUK TUJUAN TERTENTU DAN TANPA PELANGGARAN. DALAM KEADAAN APA PUN
# PENULIS ATAU PEMEGANG HAK CIPTA TIDAK BERTANGGUNG JAWAB ATAS KLAIM, KERUSAKAN ATAU
# KEWAJIBAN LAINNYA, BAIK DALAM TINDAKAN KONTRAK, KESALAHAN ATAU LAINNYA, YANG TIMBUL DARI,
# KELUAR DARI ATAU SEHUBUNGAN DENGAN PERANGKAT LUNAK ATAU PENGGUNAAN ATAU URUSAN LAIN DALAM
# PERANGKAT LUNAK.
# --- Akhir Lisensi MIT ---


# --- KONFIGURASI GLOBAL ---
VERSION="1.4"
KINFO_USER_AGENT="Mozilla/5.0 KINFO/$VERSION"
DORK_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"

# --- LOKASI SCRIPT & FOLDER OUTPUT ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/outputkinfo"
# *** BARU v1.4: Folder untuk Koleksi IR Penuh ***
IR_DATA_DIR="$SCRIPT_DIR/IRdata"

# --- WARNA ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- LOGGING & DEBUG ---
DEBUG_MODE=0
LOG_FILE=""

log() {
    local level="$1"
    local color="$2"
    local message="$3"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local formatted_log="[$timestamp] [$level] $message"
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${color}${formatted_log}${NC}" >&2
    else
        echo -e "${color}${formatted_log}${NC}"
    fi
    if [[ -n "$LOG_FILE" ]]; then
        echo "$formatted_log" >> "$LOG_FILE"
    fi
}
log_info() { log "INFO" "$GREEN" "$1"; }
log_warn() { log "WARN" "$YELLOW" "$1"; }
log_error() { log "ERROR" "$RED" "$1"; }
log_debug() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
        log "DEBUG" "$PURPLE" "$1"
    fi
}
log_result() { log "RESULT" "$CYAN" "$1"; }

# --- CLEANUP ---
TEMP_FILES=()
cleanup() {
    log_debug "Menjalankan cleanup... Menghapus file temporer."
    if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
        rm -f "${TEMP_FILES[@]}"
    fi
}
trap cleanup EXIT
add_temp_file() {
    local f
    f=$(mktemp "/tmp/kinfo_XXXXXX")
    TEMP_FILES+=("$f")
    echo "$f"
}

# --- VALIDASI & DEPENDENSI ---
check_dependencies() {
    log_debug "Memeriksa dependensi..."
    local missing_deps=0
    for cmd in curl grep find stat sed sort uniq wc mktemp; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Dependensi WAJIB tidak ditemukan: $cmd"
            missing_deps=1
        fi
    done
    for cmd in jq nslookup nc ftp whois ps netstat ss last lastlog who file; do
        if ! command -v "$cmd" &>/dev/null; then
            log_warn "Dependensi opsional tidak ditemukan: $cmd. Beberapa fitur mungkin tidak berfungsi."
        fi
    done
    if [[ $missing_deps -eq 1 ]]; then
        log_error "Harap install dependensi wajib dan coba lagi."
        exit 1
    fi
    # Buat kedua folder output
    if ! mkdir -p "$OUTPUT_DIR"; then
        log_error "Gagal membuat folder output di: $OUTPUT_DIR"; exit 1
    fi
    if ! mkdir -p "$IR_DATA_DIR"; then
        log_error "Gagal membuat folder IRdata di: $IR_DATA_DIR"; exit 1
    fi
    log_debug "Folder output dipastikan ada di: $OUTPUT_DIR dan $IR_DATA_DIR"
}

# --- BANNER & BANTUAN (USAGE) ---
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
+===========================+
| _  _____ _   _ _____ ___  |
|| |/ /_ _| \ | |  ___/ _ \ |
|| ' / | ||  \| | |_ | | | ||
|| . \ | || |\  |  _|| |_| ||
||_|\_\___|_| \_|_|   \___/ |
+===========================+
EOF
    echo -e "${NC}"
    echo "========================================="
    echo "  KINFO - Incident Response Toolkit      "
    echo "  Version: $VERSION | By: Saeful"
    echo "  Contact: https://jejakintel.t.me/      "
    echo "  Output disimpan di: $OUTPUT_DIR"
    echo "  Output Koleksi IR di: $IR_DATA_DIR"
    echo "========================================="
    echo ""
}
show_usage() {
    echo "KINFO - Incident Response & Pentest Toolkit (v$VERSION)"
    echo ""
    echo "Usage: $0 [MODE_FLAGS] [OPTIONS]"
    echo ""
    echo "MODE INTERAKTIF (Default):"
    echo "  $0"
    echo ""
    echo "MODE NON-INTERAKTIF (CLI):"
    echo "  Dibutuhkan: --module <nama_modul>"
    echo ""
    echo "MODULES (REMOTE) - (Membutuhkan --target <domain/ip/url>)"
    echo "  subdomain       : [R1] Enhanced Subdomain Finder"
    echo "  direnum         : [R2] Directory/File Enumeration"
    echo "  ftpbrute        : [R3] FTP Bruteforce"
    echo "  judi            : [R4] Judi Online Finder"
    echo "  reverseip       : [R5] Reverse IP Lookup"
    echo "  extract         : [R6] Extract Domain & Auto Add HTTPS"
    echo "  webscan         : [R7] Webshell Finder [DirScan]"
    echo "  envscan         : [R8] ENV & Debug Method Scanner"
    echo "  wpcheck         : [R9] WordPress Registration Finder"
    echo "  zoneh           : [R10] Grab Domain from Zone-H"
    echo ""
    echo "MODULES (LOKAL) - (Memindai mesin ini)"
    echo "  filescan        : [L1] Webshell Finder [File Enumeration] (membutuhkan --target <path>)"
    echo "  localps         : [L2] Pengecekan Proses Mencurigakan (Lokal)"
    echo "  localnet        : [L3] Pengecekan Koneksi Jaringan (Lokal)"
    echo "  localusers      : [L4] Pengecekan User & Login (Lokal)"
    echo "  localcron       : [L5] Pengecekan Cron Mendalam (Lokal)"
    echo "  localcollect    : [L6] Kumpulkan Artefak Sistem (Full) (membutuhkan --target <path>)"
    echo ""
    echo "OPTIONS:"
    echo "  -t, --target <str>        : Target (domain, URL, IP, atau path lokal untuk 'filescan'/'localcollect')"
    echo "  -w, --wordlist <file>     : Path ke wordlist (default: $SCRIPT_DIR/wordlist.txt)"
    echo "  -o, --output-file <file>  : Simpan output ke file (Nama saja, akan ditempatkan di $OUTPUT_DIR)"
    echo "  -f, --output-format <fmt> : Format output: text (default), json"
    echo "  -p, --parallel <num>      : Jumlah proses paralel (default: 20)"
    echo "  -l, --logfile <file>      : Path ke file log"
    echo "  -d, --debug               : Aktifkan mode debug (verbose)"
    echo "  -h, --help                : Tampilkan pesan bantuan ini"
    echo ""
}

# --- [R1] ENHANCED SUBDOMAIN FINDER (v1.4 Optimized) ---

# Fungsi Helper 1: Resolve DNS
resolve_subdomain() { 
    local S="$1"
    if nslookup "$S" >/dev/null 2>&1; then 
        echo "$S"
    fi
}
export -f resolve_subdomain

# Fungsi Helper 2: Cek HTTP (FIXED JQ ERROR)
check_subdomain_http() {
    local S="$1"; local RF="$2"; local UA="$3"
    for P in "https" "http"; do
        local U="$P://$S"
        # Mengambil status code dengan timeout cepat
        local SC
        SC=$(curl -sL -I -o /dev/null -w "%{http_code}" --max-time 5 "$U" -A "$UA")
        
        # Filter status code yang valid (2xx, 3xx, 401, 403)
        if [[ "$SC" =~ ^(2|3|401|403) ]]; then
            # FIX: Variabel internal jq disamakan dengan argumen (--arg status)
            jq -n --arg url "$U" --arg status "$SC" '{"url": $url, "status": $status}' >> "$RF"
            break
        fi
    done
}
export -f check_subdomain_http

# Fungsi Utama Modul R1
run_module_subdomain() {
    log_info "Memulai Enhanced Subdomain Finder v1.4..."
    
    # --- 1. SETUP & VALIDASI INPUT ---
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    
    # Sanitasi input (hapus http/https/www/path)
    local ST
    ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    
    if [[ -z "$ST" ]]; then log_error "Input target tidak valid."; return 1; fi
    log_info "[*] Target Scan: $ST"
    
    # File temporary untuk menampung hasil mentah
    local TFA; TFA=$(add_temp_file) 
    
    # --- 2. WILDCARD DNS CHECK (Fitur Baru v1.4) ---
    # Mencegah ribuan subdomain palsu jika server disetting "Catch-All"
    log_info "[*] Memeriksa Wildcard DNS..."
    local RAND_SUB="kinfo-wildcard-check-$(date +%s).$ST"
    local WILDCARD_FILTER=0
    
    if nslookup "$RAND_SUB" >/dev/null 2>&1; then
        log_warn "[!] PERINGATAN: Wildcard DNS terdeteksi! Server merespon untuk subdomain acak."
        log_warn "    Hasil scan mungkin mengandung false positives. Filter ketat diaktifkan."
        WILDCARD_FILTER=1
    else
        log_info "[OK] Tidak ada Wildcard DNS. Melanjutkan scan standar."
    fi

    # --- 3. PASSIVE ENUMERATION (Multi-Source Parallel) ---
    log_info "[*] Mengambil data dari 5 sumber publik (Parallel Fetching)..."
    
    # Sumber 1: CRT.SH (Certificate Transparency)
    (
        curl -s "https://crt.sh/?q=%.${ST}&output=json" -A "$KINFO_USER_AGENT" | \
        jq -r '.[].name_value' 2>/dev/null | grep -Po '(\S+\.)+\S+' >> "$TFA"
    ) & PID1=$!
    
    # Sumber 2: HACKERTARGET (API Gratis - Sangat Akurat)
    (
        curl -s "https://api.hackertarget.com/hostsearch/?q=${ST}" -A "$KINFO_USER_AGENT" | \
        cut -d',' -f1 | grep -v "API count exceeded" >> "$TFA"
    ) & PID2=$!
    
    # Sumber 3: ANUBIS / JLDC (Database Subdomain Besar)
    (
        curl -s "https://jldc.me/anubis/subdomains/${ST}" -A "$KINFO_USER_AGENT" | \
        jq -r '.[]' 2>/dev/null >> "$TFA"
    ) & PID3=$!

    # Sumber 4: ALIENVAULT (OTX Passive DNS)
    (
        curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${ST}/passive_dns" -A "$KINFO_USER_AGENT" | \
        jq -r '.passive_dns[].hostname' 2>/dev/null >> "$TFA"
    ) & PID4=$!

    # Sumber 5: RAPIDDNS (Web Scraping)
    (
        curl -s "https://rapiddns.io/subdomain/${ST}?full=1" -A "$KINFO_USER_AGENT" | \
        grep -oP '(?<=<td>)[a-zA-Z0-9.-]+\.'${ST}'(?=</td>)' >> "$TFA"
    ) & PID5=$!

    # --- OPSIONAL: API BERBAYAR ---
    # Isi API Key di bawah ini jika punya (misal: SecurityTrails)
    local SECURITYTRAILS_KEY="" 
    
    if [[ -n "$SECURITYTRAILS_KEY" ]]; then
        log_info "[*] API Key ditemukan. Mengambil dari SecurityTrails..."
        (
            curl -s "https://api.securitytrails.com/v1/domain/${ST}/subdomains" \
            -H "APIKEY: $SECURITYTRAILS_KEY" | jq -r '.subdomains[]' | sed "s/$/.$ST/" >> "$TFA"
        ) & PID_SEC=$!
        wait $PID_SEC
    fi

    # Tunggu semua proses background selesai
    wait $PID1 $PID2 $PID3 $PID4 $PID5
    
    # --- 4. CLEANING & FILTERING ---
    log_info "[*] Membersihkan & mengurutkan hasil..."
    local TFC; TFC=$(add_temp_file)
    
    # Membersihkan karakter wildcard (*.), spasi, dan duplikat
    grep "$ST" "$TFA" | grep -v "*" | sed 's/^\.//' | sort -u > "$TFC"
    
    local total; total=$(wc -l < "$TFC")
    log_info "[+] Ditemukan total $total kandidat subdomain unik (Passive Data)."

    # --- 5. DNS RESOLUTION (Validasi Aktif) ---
    log_info "[*] Melakukan DNS Resolution (Cek domain aktif) - Proses: $PARALLEL_JOBS..."
    local TFD; TFD=$(add_temp_file)
    
    # Validasi masal menggunakan xargs parallel
    cat "$TFC" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "resolve_subdomain {}" >> "$TFD"
    
    local dlc; dlc=$(wc -l < "$TFD")
    log_info "[+] Ditemukan $dlc subdomain yang TERDAFTAR di DNS (Live)."

    # --- 6. HTTP CHECK (Cek Web Server) ---
    log_info "[*] Melakukan HTTP Check (Cek website aktif) - Proses: $PARALLEL_JOBS..."
    local TFH; TFH=$(add_temp_file)
    export KINFO_USER_AGENT; export TFH
    
    # Cek HTTP/HTTPS parallel
    cat "$TFD" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "check_subdomain_http \"{}\" \"$TFH\" \"$KINFO_USER_AGENT\""
    
    local hlc; hlc=$(wc -l < "$TFH")
    log_info "[+] Ditemukan $hlc subdomain yang memiliki WEB SERVER (HTTP/S)."

    # --- 7. OUTPUT GENERATION (FIXED: Full Save + Summary View) ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        # Format JSON (Tetap Full Data)
        jq -n --arg target "$ST" \
              --arg total_passive "$total" \
              --arg total_dns "$dlc" \
              --arg total_http "$hlc" \
              --argjson passive_sources "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TFC")" \
              --argjson dns_live "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TFD")" \
              --argjson http_live "$(jq -s '.' "$TFH")" \
              '{target: $target, stats: {passive: $total_passive, dns_live: $total_dns, http_live: $total_http}, data: {passive: $passive_sources, dns_live: $dns_live, http_live: $http_live}}' > "$OUTPUT_FILE"
        
        # Tampilkan JSON ke layar jika tidak disimpan ke file khusus
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi

    else
        # Format TEXT (Human Readable)
        # 1. Simpan HASIL LENGKAP ke File Output
        {
            echo "KINFO Enhanced Subdomain Finder v1.4"
            echo "Target: $ST"
            echo "Scan Time: $(date)"
            echo "Stats: Passive Candidate($total) | DNS Live($dlc) | HTTP Live($hlc)"
            echo "===================================="
            echo "[+] HTTP LIVE SUBDOMAINS (Web Server Aktif):"
            cat "$TFH" | jq -r '"[\(.status)] \(.url)"'
            echo ""
            echo "[+] DNS LIVE ONLY (Terdaftar DNS, tapi Web/HTTP Mati):"
            comm -23 <(sort "$TFD") <(cat "$TFH" | jq -r '.url' | sed -E 's~^https?://~~' | sort)
        } > "$OUTPUT_FILE"

        # 2. Tampilkan RINGKASAN ke Layar (Agar terminal tidak macet)
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then
            # Tampilkan Header + 25 Baris Pertama
            head -n 25 "$OUTPUT_FILE"
            
            # Hitung sisa baris yang tidak tampil
            local total_lines
            total_lines=$(wc -l < "$OUTPUT_FILE")
            local hidden_lines=$((total_lines - 25))
            
            if [[ $hidden_lines -gt 0 ]]; then
                echo ""
                echo -e "\033[1;33m(..dan $hidden_lines baris lainnya disembunyikan dari layar..)\033[0m"
                echo -e "\033[1;32m[+] Hasil LENGKAP telah disimpan di: $OUTPUT_FILE\033[0m"
            fi
        else
            # Jika user mau output ke stdout (misal di-pipe), tampilkan semua
            cat "$OUTPUT_FILE"
        fi
    fi
    
    log_info "Pencarian subdomain selesai."
}

# ====================================================================
# --- [R2] DIRECTORY/FILE ENUMERATION ---
check_url_path() {
    local BU="$1"; local P="$2"; local RL="$3"; local UA="$4"; local RF="$5"
    local FU="${BU}/${P}"; sleep "$RL"
    local R; R=$(curl -sIL "$FU" --connect-timeout 3 --max-time 5 -H "User-Agent: $UA" 2>/dev/null)
    local SL; SL=$(echo "$R" | head -n 1); local SC; SC=$(echo "$SL" | grep -oE '[0-9]{3}' | head -1)
    if [[ "$SC" =~ ^(200|301|302|401|403)$ ]]; then
        local SZ="N/A"; if [[ "$SC" == "200" ]]; then SZ=$(curl -s "$FU" --connect-timeout 3 --max-time 5 -H "User-Agent: $UA" 2>/dev/null | wc -c); fi
        jq -n --arg url "$FU" --arg status "$SC" --arg size "$SZ" '{"url": $url, "status": $status, "size": $size}' >> "$RF"
    fi
}
export -f check_url_path
run_module_direnum() {
    log_info "Memulai Directory/File Enumeration..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    if [[ ! -f "$WORDLIST" ]]; then log_error "Wordlist tidak ditemukan di: $WORDLIST"; return 1; fi
    local total; total=$(grep -vE "^\s*#|^\s*$" "$WORDLIST" | wc -l)
    log_info "[*] Memulai enumerasi pada $TARGET ($WORDLIST: $total entri, Paralel: $PARALLEL_JOBS, Rate: $RATE_LIMIT""s)"
    local TJL; TJL=$(add_temp_file); export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export TJL
    grep -vE "^\s*#|^\s*$" "$WORDLIST" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\""
    local fc; fc=$(wc -l < "$TJL"); log_info "[+] Enumerasi selesai. Ditemukan $fc item."
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada item yang ditemukan."; return 0; fi
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then OD=$(jq -s '.' "$TJL"); else
        OD=$(cat <<EOF
Directory/File Enumeration Results
Target: $TARGET
Wordlist: $WORDLIST
Scan Time: $(date)
==================================
$(cat "$TJL" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort)
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [R3] FTP BRUTEFORCE ---
check_ftp_cred() {
    local H="$1"; local P="$2"; local U="$3"; local PW="$4"; local RF="$5"
    local LR; LR=$(echo -e "user $U $PW\nquit" | ftp -n "$H" "$P" 2>&1)
    if echo "$LR" | grep -qi "login successful\|230\|welcome"; then
        jq -n --arg host "$H" --arg port "$P" --arg user "$U" --arg pass "$PW" \
            '{"host": $host, "port": $port, "username": $user, "password": $pass}' >> "$RF"
    fi
}
export -f check_ftp_cred
run_module_ftpbrute() {
    log_info "Memulai FTP Bruteforce..."
    local H; H=$(echo "$TARGET" | cut -d':' -f1); local P; P=$(echo "$TARGET" | cut -d':' -f2)
    if [[ "$H" == "$P" ]]; then P=21; fi
    if [[ -z "$H" ]]; then log_error "Target host diperlukan."; return 1; fi
    if ! command -v ftp &>/dev/null; then log_error "Perintah 'ftp' tidak ditemukan."; return 1; fi
    if [[ ! -f "$FTP_LIST" ]]; then log_error "Wordlist FTP tidak ditemukan di: $FTP_LIST"; return 1; fi
    if ! nc -z "$H" "$P" 2>/dev/null; then log_error "Tidak dapat terhubung ke $H:$P"; return 1; fi
    log_info "[*] Terhubung ke $H:$P. Memulai brute force (Paralel: $PARALLEL_JOBS)..."
    local TJL; TJL=$(add_temp_file); export H; export P; export TJL
    grep -vE "^\s*#|^\s*$" "$FTP_LIST" | grep ':' | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_ftp_cred \"$H\" \"$P\" \"$(echo {} | cut -d':' -f1)\" \"$(echo {} | cut -d':' -f2-)\" \"$TJL\""
    local fc; fc=$(wc -l < "$TJL"); log_info "[+] Bruteforce selesai."
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada kredensial valid yang ditemukan."; return 0; fi
    log_result "[SUCCESS] Ditemukan $fc kredensial valid!"
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then OD=$(jq -s '.' "$TJL"); else
        OD=$(cat "$TJL" | jq -r '"[+] HOST: \(.host):\(.port) - USER: \(.username) - PASS: \(.password)"')
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# -----------------------------------------------
# --- [R4] JUDI ONLINE FINDER (v1.4 Deep Scan) ---

# Fungsi Helper 1: Cek Konten URL terhadap Wordlist
check_judi_content() {
    local U="$1"      # URL to check
    local KLF="$2"    # Path ke judilist.txt
    local RF="$3"     # File Output Sementara
    local UA="$4"     # User Agent

    # Download konten (Maksimal 10 detik)
    # Kita ambil 50KB pertama saja agar cepat, biasanya inject ada di header/body atas
    local CONTENT
    CONTENT=$(curl -sL "$U" -r 0-50000 --max-time 10 -H "User-Agent: $UA" 2>/dev/null)
    
    if [[ -z "$CONTENT" ]]; then return; fi
    
    # OPTIMASI PENTING: Gunakan 'grep -Fwf' untuk mencocokkan semua keyword sekaligus
    # -F: Fixed string (cepat), -w: Whole word (akurat), -f: Ambil pola dari file
    local MATCH
    MATCH=$(echo "$CONTENT" | grep -Fwf "$KLF" | head -1)
    
    if [[ -n "$MATCH" ]]; then
        # Jika ketemu keyword judi
        log_debug "[FOUND] Indikasi di $U (Key: $MATCH)"
        jq -n --arg method "deep_scan" --arg url "$U" --arg keyword "$MATCH" \
            '{"method": $method, "url": $url, "keyword": $keyword}' >> "$RF"
    fi
}
export -f check_judi_content

# Fungsi Helper 2: Bing Dork Scan (Mencari halaman yang sudah terindeks)
check_judi_bing() {
    local TD="$1"     # Target Domain
    local K="$2"      # Keyword
    local RF="$3"     # Result File
    local UA="$4"     # User Agent Khusus Browser
    
    # Query: site:target.com "keyword"
    local Q
    Q=$(printf "site:%s \"%s\"" "$TD" "$K" | jq -sRr @uri)
    local BU="https://www.bing.com/search?q=$Q"
    
    local R
    R=$(curl -sL --max-time 10 -A "$UA" "$BU")
    
    # Validasi hasil Bing
    if echo "$R" | grep -iq "$TD" && ! echo "$R" | grep -iqE "(Tidak ada hasil untuk|No results for)"; then
        # Ekstrak URL dari hasil Bing (regex sederhana untuk href)
        local FOUND_URL
        FOUND_URL=$(echo "$R" | grep -oP 'href="https?://'${TD}'[^"]+"' | head -1 | cut -d'"' -f2)
        
        if [[ -z "$FOUND_URL" ]]; then FOUND_URL="$BU"; fi

        jq -n --arg method "bing_dork" --arg url "$FOUND_URL" --arg keyword "$K" \
            '{"method": $method, "url": $url, "keyword": $keyword}' >> "$RF"
    fi
}
export -f check_judi_bing

# Fungsi Utama Modul R4
run_module_judi() {
    log_info "Memulai Judi Online Finder v1.4 [Deep Path Scan]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    
    local ST
    ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    
    if [[ -z "$ST" ]]; then log_error "Input target tidak valid."; return 1; fi
    
    if [[ ! -f "$JUDI_LIST" ]]; then 
        log_error "Wordlist Judi tidak ditemukan di: $JUDI_LIST"
        return 1
    fi
    
    local kc
    kc=$(grep -vE "^\s*#|^\s*$" "$JUDI_LIST" | wc -l)
    log_info "[*] Target: $ST"
    log_info "[*] Database Keyword: $JUDI_LIST ($kc keywords)"

    # --- 2. DEEP PATH GENERATION (Fitur Baru v1.4) ---
    # Kita akan scan path-path kritis yang sering disusupi
    local COMMON_PATHS=(
        ""                      # Homepage
        "blog/" "news/" "berita/" "artikel/" 
        "wp-content/uploads/" "wp-includes/" 
        "images/" "img/" "assets/" "css/" "js/" 
        "data/" "files/" "media/" "public/" 
        "admin/" "user/" "tmp/"
    )
    
    local SCAN_URLS=()
    for P in "${COMMON_PATHS[@]}"; do
        SCAN_URLS+=("https://$ST/$P")
        SCAN_URLS+=("http://$ST/$P")
    done
    
    local total_urls=${#SCAN_URLS[@]}
    log_info "[*] Memulai Metode 1: Deep Content Scan ($total_urls paths strategis)..."
    
    local TJL; TJL=$(add_temp_file)
    local TUL; TUL=$(add_temp_file)
    
    # Siapkan daftar URL untuk xargs
    printf "%s\n" "${SCAN_URLS[@]}" > "$TUL"
    
    export JUDI_LIST; export KINFO_USER_AGENT; export TJL
    
    # Jalankan Scan Konten secara Paralel
    cat "$TUL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_judi_content \"{}\" \"$JUDI_LIST\" \"$TJL\" \"$KINFO_USER_AGENT\""

    # --- 3. BING DORK SCAN ---
    log_info "[*] Memulai Metode 2: Bing Dork Scan (Mencari halaman terindeks)..."
    log_info "    (Mengambil 5 keyword acak dari wordlist untuk efisiensi)"
    
    # Ambil 5 keyword acak agar tidak memicu blokir Bing berlebihan
    local RANDOM_KEYS
    RANDOM_KEYS=$(shuf -n 5 "$JUDI_LIST")
    
    export DORK_UA
    echo "$RANDOM_KEYS" | xargs -P 5 -I {} \
        bash -c "check_judi_bing \"$ST\" \"{}\" \"$TJL\" \"$DORK_UA\""

    local fc
    fc=$(wc -l < "$TJL")
    log_info "[+] Scan selesai. Indikasi ditemukan: $fc"
    
    if [[ "$fc" -eq 0 ]]; then 
        log_warn "Tidak ada konten judi yang terdeteksi."; return 0; 
    fi

    # --- 4. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$ST" '{target: $target, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "Judi Online Finder Results (v1.4 Deep Scan)"
            echo "Domain: $ST"
            echo "Scan Time: $(date)"
            echo "=================================="
            cat "$TJL" | jq -r '"[!] (\(.method)) \(.url) -> Keyword: \(.keyword)"'
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
}

# --- [R5] REVERSE IP LOOKUP (v1.4 Multi-Source) ---
run_module_reverseip() {
    log_info "Memulai Reverse IP Lookup v1.4 [Multi-Source]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target IP Address diperlukan."; return 1; fi
    local IP="$TARGET"
    
    # Validasi Format IP (IPv4 Sederhana)
    if [[ ! $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then 
        log_error "Format IP tidak valid: $IP (Harus berupa IP Address, contoh: 103.10.10.1)"
        return 1
    fi
    
    log_info "[*] Target IP: $IP"
    log_info "[*] Mengambil data dari 3 sumber (ViewDNS, HackerTarget, RapidDNS)..."
    
    local TFA; TFA=$(add_temp_file)
    
    # --- 2. MULTI-SOURCE FETCHING (Parallel) ---
    
    # Sumber 1: ViewDNS.info (Sering limit, tapi akurat)
    (
        local VDU="https://viewdns.info/reverseip/?host=$IP&t=1"
        curl -s "$VDU" -H "User-Agent: $KINFO_USER_AGENT" | \
        grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' >> "$TFA"
    ) & PID1=$!
    
    # Sumber 2: HackerTarget (API Gratis)
    (
        curl -s "https://api.hackertarget.com/reverseiplookup/?q=$IP" \
        -H "User-Agent: $KINFO_USER_AGENT" | \
        grep -v "API count exceeded" | grep -v "No records found" >> "$TFA"
    ) & PID2=$!
    
    # Sumber 3: RapidDNS (Web Scraping - Database Besar)
    (
        curl -s "https://rapiddns.io/sameip/$IP?full=1" \
        -H "User-Agent: $KINFO_USER_AGENT" | \
        grep -oP '(?<=<td>)[a-zA-Z0-9.-]+(?=</td>)' | grep -v "Same IP" >> "$TFA"
    ) & PID3=$!
    
    # Tunggu semua proses background selesai
    wait $PID1 $PID2 $PID3
    
    # --- 3. CLEANING & FILTERING ---
    local TFC; TFC=$(add_temp_file)
    
    # Bersihkan, urutkan, hapus duplikat, dan hapus IP target itu sendiri dari daftar
    sort -u "$TFA" | grep -v "$IP" | sed '/^$/d' > "$TFC"
    
    local total; total=$(wc -l < "$TFC")
    log_info "[+] Lookup selesai. Ditemukan $total domain yang ter-hosting di IP $IP."
    
    # Fallback ke WHOIS jika tidak ada domain ditemukan
    if [[ $total -eq 0 ]]; then
        log_warn "[*] Tidak ada domain ditemukan di sumber pasif." 
        log_info "[*] Mencoba menarik informasi WHOIS NetBlock..."
        
        if command -v whois &>/dev/null; then
            local WR
            # Ambil info kepemilikan IP (OrgName, NetName, dll)
            WR=$(whois "$IP" 2>/dev/null | grep -iE "^(NetName|OrgName|Organization|descr|netname|owner):")
            
            if [[ -n "$WR" ]]; then
                echo "# INFO KEPEMILIKAN IP (WHOIS):" > "$TFC"
                echo "$WR" >> "$TFC"
                log_info "[+] Informasi WHOIS ditemukan."
            else
                log_error "[!] Tidak ada info domain maupun WHOIS untuk IP $IP"
            fi
        else
            log_warn "[!] Perintah 'whois' tidak terinstall di sistem ini."
        fi
    fi

    # --- 4. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -n --arg ip "$IP" --arg total "$total" \
           --argjson domains "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TFC")" \
           '{target_ip: $ip, total_domains_found: $total, domains: $domains}' > "$OUTPUT_FILE"
           
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "Reverse IP Lookup Results (v1.4 Multi-Source)"
            echo "Target IP: $IP"
            echo "Scan Time: $(date)"
            echo "Total Domains Found: $total"
            echo "=================================="
            cat "$TFC"
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
}

# --------------------------------------------------------
# --- [R6] EXTRACT DOMAIN & CHECK HEADERS ---
run_module_extract() {
    log_info "Memulai Extract Domain & Auto Add HTTPS..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    local U="$TARGET"; local E; E=$(echo "$U"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    if [[ "$U" != *"//"* ]]; then E=$(echo "$U"|cut -d'/' -f1|sed 's/^www\.//'); fi
    local FU="https://$E"; log_info "[*] URL Asli: $U"; log_info "[*] Ekstrak Domain: $E"; log_info "[*] HTTPS URL: $FU"
    local TH; TH=$(add_temp_file)
    local SC; SC=$(curl -sI "$FU" --max-time 5 -o "$TH" -w "%{http_code}" -H "User-Agent: $KINFO_USER_AGENT")
    local SH=(); mapfile -t SH < <(grep -i "x-frame-options\|content-security-policy\|strict-transport-security" "$TH")
    log_info "[*] Status Kode: $SC"
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg original "$U" --arg domain "$E" --arg https_url "$FU" --arg status "$SC" \
            --argjson headers "$(printf "%s\n" "${SH[@]}"|jq -Rsc 'split("\n")|map(select(length > 0))')" \
            '{"original_url": $original, "extracted_domain": $domain, "https_url": $https_url, "status_code": $status, "security_headers": $headers}')
    else
        OD=$(cat <<EOF
Extract Domain & Header Check
Original: $U
Extracted: $E
HTTPS URL: $FU
==================================
Status Code: $SC
Security Headers:
$(printf "%s\n" "${SH[@]}" | sed 's/^/  /')
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}
# ------------------------------------------------------
# --- [R7] WEBSHELL FINDER (v1.4 Ultimate: Smart Scan + Massive Wordlist) ---

# Fungsi Helper: Smart Path Checker (Anti-Soft 404 & Content Verification)
check_path_smart() {
    local BU="$1"     # Base URL
    local P="$2"      # Path to check
    local RL="$3"     # Rate Limit
    local UA="$4"     # User Agent
    local RF="$5"     # Result File
    local IG_SZ="$6"  # Ignore Size (Ukuran Soft 404)

    local FU="${BU}/${P}"
    if [[ "$RL" -gt 0 ]]; then sleep "$RL"; fi

    # 1. TAHAP PERTAMA: Cek Header & Size (Cepat)
    # Gunakan curl head (-I) dulu atau range byte kecil untuk efisiensi
    local DATA
    DATA=$(curl -sL -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 3 --max-time 5 -H "User-Agent: $UA" "$FU")
    
    local SC=$(echo "$DATA" | cut -d':' -f1)
    local SZ=$(echo "$DATA" | cut -d':' -f2)

    # Validasi Awal: Status Code OK
    if [[ "$SC" =~ ^(200|301|302|401|403)$ ]]; then
        
        # LOGIKA SOFT 404: Abaikan jika ukuran file sama dengan halaman error
        if [[ "$IG_SZ" -gt 0 && "$SZ" -eq "$IG_SZ" ]]; then
            return # Skip, ini halaman palsu
        fi

        # 2. TAHAP KEDUA: Content Verification (Hanya jika status 200)
        # Kita cek apakah ini benar-benar webshell/login page atau file zonk
        local INFO="Found"
        
        if [[ "$SC" == "200" ]]; then
            # Download sebagian isi file (Maksimal 2KB pertama saja agar cepat)
            local BODY
            BODY=$(curl -sL -r 0-2000 --connect-timeout 3 --max-time 5 -H "User-Agent: $UA" "$FU")
            
            # Cek Keyword Khas Halaman Login / Webshell
            # Keyword ditambah: c99, r57, indoxploit, alfa, hacked, hacked by
            if echo "$BODY" | grep -qEi "type=['\"]?password|name=['\"]?pass|value=['\"]?login|multipart/form-data|wso|indoxploit|b374k|alfa|hacked by"; then
                INFO="CONFIRMED SHELL (Login Form/Signature Detect)"
            elif [[ "$SZ" -lt 50 ]]; then
                 # File 200 OK tapi ukurannya sangat kecil (< 50 bytes) biasanya zonk/blank
                 INFO="Suspicious (Small Size)"
            else
                 INFO="Potential File"
            fi
        fi

        # Simpan hasil valid dengan Info Tambahan
        jq -n --arg url "$FU" --arg status "$SC" --arg size "$SZ" --arg info "$INFO" \
            '{"url": $url, "status": $status, "size": $size, "info": $info}' >> "$RF"
    fi
}
export -f check_path_smart

run_module_webscan() {
    log_info "Memulai Webshell Finder v1.4 Ultimate [Massive Wordlist]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::') # Hapus trailing slash
    
    log_info "[*] Target: $TARGET"

    # --- 2. SOFT 404 CALIBRATION ---
    log_info "[*] Melakukan kalibrasi Soft 404..."
    local RAND_PATH="kinfo_chk_$(date +%s)"
    local IGNORE_SIZE=0
    
    local CALIB_DATA
    CALIB_DATA=$(curl -sL -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 5 -H "User-Agent: $KINFO_USER_AGENT" "$TARGET/$RAND_PATH")
    local CALIB_SC=$(echo "$CALIB_DATA" | cut -d':' -f1)
    local CALIB_SZ=$(echo "$CALIB_DATA" | cut -d':' -f2)

    if [[ "$CALIB_SC" == "200" ]]; then
        IGNORE_SIZE="$CALIB_SZ"
        log_warn "[!] Soft 404 Aktif! Filter size: $IGNORE_SIZE bytes."
    else
        log_info "[OK] Server normal (404 berfungsi)."
    fi

    # --- 3. WORDLIST ULTIMATE (Lengkap & Terkelompok) ---
    local WSP=(
        # --- [GROUP 1] ALFA TEAM & VARIAN ---
        "alfa.php" "alfav4.php" "alfav5.php" "alfashell.php" "solevisible.php" 
        "alfa-rex.php" "alfacgi.api" "alfa.jpeg.php"
        
        # --- [GROUP 2] INDOXPLOIT & INDONESIAN SHELLS ---
        "indoxploit.php" "idx.php" "indo.php" "indosec.php" "idx_config.php" 
        "pacul.php" "kurama.php" "kuro.php" "bypas.php" "bypass.php"
        
        # --- [GROUP 3] WSO / ORB / B374K / GECKO ---
        "wso.php" "wso2.php" "wso2.5.php" "wso_4.2.5.php" "gecko.php" 
        "b374k.php" "b374k_mini.php" "marijuana.php" "101.php" "0.php"
        
        # --- [GROUP 4] LEGACY (C99, R57) ---
        "c99.php" "r57.php" "c100.php" "kaefer.php" "angel.php" "g6.php"
        
        # --- [GROUP 5] STEALTH / SHORT NAMES (Sering Lolos WAF) ---
        "x.php" "s.php" "u.php" "w.php" "d.php" "ws.php" "ak47.php" "404.php" 
        "1.php" "2.php" "a.php" "b.php" "test.php" "t.php" "mini.php" "tiny.php" 
        "shell.php" "cmd.php" "sh.php" "backdoor.php" "bd.php"
        
        # --- [GROUP 6] DECEPTIVE NAMES (Menyamar jadi file sistem) ---
        "phpinfo.php" "info.php" "radio.php" "content.php" "about.php" "lock.php"
        "images.php" "css.php" "login.php" "admin.php" "error.php" "install.php" 
        "update.php" "ajax.php" "assets.php" "index_old.php" "index_bak.php"
        
        # --- [GROUP 7] UPLOADERS & DATABASE TOOLS ---
        "upload.php" "uploader.php" "up.php" "adminer.php" "pma.php" "db.php" 
        "sql.php" "mysql.php" "manager.php" "files.php"
        
        # --- [GROUP 8] TARGETED PATHS (WordPress/Config) ---
        "wp-content/uploads/shell.php" "wp-content/uploads/2024/shell.php"
        "wp-content/uploads/2025/shell.php" "wp-includes/shell.php"
        "wp-admin/user/shell.php" "configuration.php" "wp-config.php" 
        "config.php" "web.config" ".env" ".git/config" "composer.json"
        
        # --- [GROUP 9] BYPASS EXTENSIONS ---
        "shell.phtml" "shell.php5" "shell.php.bak" "s.phtml" "u.phtml"
    )
    
    local total=${#WSP[@]}
    log_info "[*] Memulai Deep Scan pada $TARGET"
    log_info "    (Mode: Content Verification, Wordlist: $total item, Paralel: $PARALLEL_JOBS)..."
    
    local TJL; TJL=$(add_temp_file)
    local TPL; TPL=$(add_temp_file)
    printf "%s\n" "${WSP[@]}" > "$TPL"
    
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export TJL; export IGNORE_SIZE
    
    # --- 4. EXECUTION ---
    cat "$TPL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_path_smart \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\" \"$IGNORE_SIZE\""
    
    local fc; fc=$(wc -l < "$TJL")
    log_info "[+] Scan selesai. Kandidat ditemukan: $fc"
    
    if [[ "$fc" -eq 0 ]]; then 
        log_warn "Tidak ada webshell yang ditemukan."; return 0; 
    fi

    # --- 5. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$TARGET" --arg soft404_size "$IGNORE_SIZE" \
           '{target: $target, soft404_size: $soft404_size, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "Webshell/Dir Scan Results (v1.4 Ultimate)"
            echo "Target: $TARGET"
            echo "Scan Time: $(date)"
            echo "Soft 404 Filter Size: $IGNORE_SIZE bytes"
            echo "=================================="
            # Menampilkan Status, Info Validasi, URL, dan Ukuran
            cat "$TJL" | jq -r '"[\(.status)] [\(.info)] \(.url) (Size: \(.size))"' | sort -k 2
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
}

# ------------------------------------------------------
# --- [R8] ENV & DEBUG SCANNER (v1.4 Credential Hunter) ---

# Menggunakan fungsi 'check_path_smart' yang sudah dibuat di modul R7.
# Pastikan modul R7 sudah diupdate agar fungsi tersebut tersedia.

run_module_envscan() {
    log_info "Memulai ENV & Config Scanner v1.4 [Credential Hunter]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    
    log_info "[*] Target: $TARGET"

    # --- 2. SOFT 404 CALIBRATION ---
    # Penting agar tidak tertipu halaman 404 kustom
    log_info "[*] Kalibrasi Soft 404..."
    local RAND_PATH="kinfo_env_check_$(date +%s)"
    local IGNORE_SIZE=0
    
    local CALIB_DATA
    CALIB_DATA=$(curl -sL -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 5 -H "User-Agent: $KINFO_USER_AGENT" "$TARGET/$RAND_PATH")
    local CALIB_SC=$(echo "$CALIB_DATA" | cut -d':' -f1)
    local CALIB_SZ=$(echo "$CALIB_DATA" | cut -d':' -f2)

    if [[ "$CALIB_SC" == "200" ]]; then
        IGNORE_SIZE="$CALIB_SZ"
        log_warn "[!] Soft 404 Aktif! Mengabaikan respon dengan ukuran $IGNORE_SIZE bytes."
    else
        log_info "[OK] Respon server normal."
    fi

    # --- 3. WORDLIST CONFIG & EXPOSURE ---
    local EF=(
        # --- PRIORITY 1: ENV FILES ---
        ".env" ".env.example" ".env.local" ".env.dev" ".env.production" 
        ".env.bak" ".env.old" ".env.save" "core/.env" "app/.env" 
        "config/.env" "local.env"
        
        # --- PRIORITY 2: CONFIG FILES ---
        "config.php" "wp-config.php" "wp-config.php.bak" "configuration.php" 
        "local_settings.py" "config.js" "database.yml" "settings.php" 
        "db_config.php" "db.php" "connect.php"
        
        # --- PRIORITY 3: CLOUD & GIT EXPOSURE ---
        ".git/config" ".git/HEAD" ".vscode/sftp.json" ".idea/workspace.xml" 
        "docker-compose.yml" "Dockerfile" "package.json" "composer.json"
        ".aws/credentials" "aws.yml" "gcloud/credentials.db"
        
        # --- PRIORITY 4: BACKUPS & DUMPS ---
        "backup.sql" "database.sql" "db_backup.sql" "dump.sql" 
        "backup.zip" "site.tar.gz" "www.zip" "public_html.zip"
        "storage/logs/laravel.log" "debug.log" "error_log"
        
        # --- PRIORITY 5: DEBUG INFO ---
        "phpinfo.php" "info.php" "test.php" "server-status" 
        "api/docs" "swagger/index.html" "actuator/health" "actuator/env"
    )
    
    local total=${#EF[@]}
    log_info "[*] Memulai Scan Sensitif pada $TARGET"
    log_info "    (Total Wordlist: $total, Mode: Regex Hunter)..."
    
    local TJL; TJL=$(add_temp_file)
    local TPL; TPL=$(add_temp_file)
    printf "%s\n" "${EF[@]}" > "$TPL"
    
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export TJL; export IGNORE_SIZE
    
    # --- 4. EXECUTION (Using check_path_smart from R7) ---
    # Kita menggunakan fungsi smart dari R7 karena sudah punya fitur download & regex
    # Regex di R7 sudah mencakup "password", "db_password", dll.
    
    cat "$TPL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_path_smart \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\" \"$IGNORE_SIZE\""
    
    local fc; fc=$(wc -l < "$TJL")
    log_info "[+] Scan selesai. Item sensitif potensial: $fc"
    
    if [[ "$fc" -eq 0 ]]; then 
        log_warn "Tidak ada file konfigurasi sensitif yang ditemukan."; return 0; 
    fi

    # --- 5. CREDENTIAL ANALYSIS (Post-Processing) ---
    # Analisis lanjutan: Memberi highlight jika hasil mengandung kata kunci 'DB_PASSWORD' dll.
    # Karena 'check_path_smart' sudah memberi label [CONFIRMED SHELL] atau [Info],
    # Kita filter ulang untuk modul ENV ini.
    
    log_info "[*] Menganalisis hasil untuk kredensial..."
    local FINAL_OUT; FINAL_OUT=$(add_temp_file)
    
    while IFS= read -r line; do
        # Parse JSON output dari check_path_smart
        local url; url=$(echo "$line" | jq -r '.url')
        local info; info=$(echo "$line" | jq -r '.info // "Found"')
        local status; status=$(echo "$line" | jq -r '.status')
        local size; size=$(echo "$line" | jq -r '.size')
        
        # Labeling ulang agar sesuai konteks ENV
        if [[ "$info" == *"CONFIRMED"* ]]; then
            info="[!!!] CRITICAL: LEAKED CREDENTIALS"
        elif [[ "$url" == *".env"* || "$url" == *"config"* ]]; then
             if [[ "$status" == "200" && "$size" -gt 50 ]]; then
                info="[!] HIGH: POTENTIAL CONFIG"
             fi
        fi
        
        echo "[$status] $info $url (Size: $size)" >> "$FINAL_OUT"
    done < "$TJL"

    # --- 6. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$TARGET" --arg soft404_size "$IGNORE_SIZE" \
           '{target: $target, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "ENV & Config Scanner Results (v1.4 Credential Hunter)"
            echo "Target: $TARGET"
            echo "Scan Time: $(date)"
            echo "Soft 404 Filter Size: $IGNORE_SIZE bytes"
            echo "=================================="
            cat "$FINAL_OUT" | sort -k 2
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
}


# --- [R9] WP CHECK & USER ENUM (v1.4 Deep Detect) ---

run_module_wpcheck() {
    log_info "Memulai WP Check & User Enumeration v1.4..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    local ST; ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    local WU="https://$ST"
    
    log_info "[*] Target: $WU"

    # --- 2. DEEP WORDPRESS DETECTION (Perbaikan Bug v1.3) ---
    log_info "[*] Memverifikasi CMS WordPress..."
    local IS_WP=0
    
    # Metode A: Cek keberadaan wp-login.php (Paling Akurat)
    local LOGIN_CHECK
    LOGIN_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$WU/wp-login.php" -A "$KINFO_USER_AGENT")
    
    # Metode B: Cek REST API Endpoint
    local API_CHECK
    API_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$WU/wp-json/" -A "$KINFO_USER_AGENT")
    
    # Metode C: Cek Source Code (wp-content)
    local BODY_CHECK
    BODY_CHECK=$(curl -sL "$WU" -r 0-5000 -A "$KINFO_USER_AGENT" | grep -qi "wp-content\|wordpress" && echo "YES" || echo "NO")

    if [[ "$LOGIN_CHECK" == "200" || "$API_CHECK" == "200" || "$BODY_CHECK" == "YES" ]]; then
        log_info "[OK] Terkonfirmasi: Target adalah WordPress."
        IS_WP=1
    else
        log_warn "[!] Gagal mendeteksi footprint WordPress (wp-login: $LOGIN_CHECK, wp-json: $API_CHECK)."
        log_warn "    Script akan tetap mencoba, namun hasil mungkin tidak akurat."
    fi

    local TF_RES; TF_RES=$(add_temp_file)

    # --- 3. USER ENUMERATION (Fitur Baru v1.4) ---
    log_info "[*] Mencoba Enumerasi User (Teknik REST API)..."
    local USERS_FOUND=""
    local API_URL="$WU/wp-json/wp/v2/users"
    
    # Tarik data JSON
    local API_DATA
    API_DATA=$(curl -sL --max-time 10 "$API_URL" -A "$KINFO_USER_AGENT")
    
    # Validasi apakah response adalah JSON array valid
    if echo "$API_DATA" | jq -e '.[0].id' >/dev/null 2>&1; then
        # Parsing Username & Nama
        USERS_FOUND=$(echo "$API_DATA" | jq -r '.[] | "User ID: \(.id) | Login: \(.slug) | Name: \(.name)"')
        local user_count
        user_count=$(echo "$USERS_FOUND" | wc -l)
        
        log_result "[CRITICAL] Ditemukan $user_count user terekspos via API!"
        echo "--- USER ENUMERATION RESULT ---" >> "$TF_RES"
        echo "$USERS_FOUND" >> "$TF_RES"
        echo "" >> "$TF_RES"
    else
        log_info "[-] REST API User Enumeration ditutup/diproteksi."
        echo "--- USER ENUMERATION RESULT ---" >> "$TF_RES"
        echo "Protected / Not Found" >> "$TF_RES"
        echo "" >> "$TF_RES"
    fi

    # --- 4. REGISTRATION PAGE FINDER ---
    log_info "[*] Mencari Halaman Registrasi Terbuka..."
    local RP=("wp-login.php?action=register" "wp-signup.php" "register" "signup" "my-account" "registration")
    local FOUND_REG=""
    
    for P in "${RP[@]}"; do
        local FULL_URL="$WU/$P"
        local SC
        SC=$(curl -sL -o /dev/null -w "%{http_code}" "$FULL_URL" -A "$KINFO_USER_AGENT")
        
        if [[ "$SC" == "200" ]]; then
            # Cek konten lagi untuk memastikan bukan soft 404 atau halaman login biasa
            local CONTENT
            CONTENT=$(curl -sL "$FULL_URL" -r 0-3000 -A "$KINFO_USER_AGENT")
            if echo "$CONTENT" | grep -qi "user_login\|user_email"; then
                FOUND_REG="$FULL_URL"
                log_result "[+] Halaman Registrasi Ditemukan: $FOUND_REG"
                break
            fi
        fi
    done

    if [[ -z "$FOUND_REG" ]]; then
        log_info "[-] Tidak ada halaman registrasi terbuka yang ditemukan."
        FOUND_REG="Not Found"
    fi

    # --- 5. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        # Siapkan array users untuk JSON
        local JSON_USERS="[]"
        if [[ -n "$USERS_FOUND" ]]; then
             JSON_USERS=$(echo "$API_DATA" | jq '[.[] | {id: .id, login: .slug, name: .name}]')
        fi
        
        jq -n --arg domain "$ST" \
              --arg is_wp "$IS_WP" \
              --arg reg_url "$FOUND_REG" \
              --argjson users "$JSON_USERS" \
              '{domain: $domain, is_wordpress: ($is_wp=="1"), registration_url: $reg_url, exposed_users: $users}' > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "WordPress Scan Results (v1.4 Deep Detect)"
            echo "Target: $ST"
            echo "WordPress Detected: $( [[ "$IS_WP" -eq 1 ]] && echo "YES" || echo "NO" )"
            echo "=================================="
            echo "[+] REGISTRATION URL:"
            echo "    $FOUND_REG"
            echo ""
            echo "[+] EXPOSED USERS (REST API):"
            if [[ -n "$USERS_FOUND" ]]; then
                echo "$USERS_FOUND"
            else
                echo "    [-] Tidak ada user terekspos / API diproteksi."
            fi
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
}


# --- [R10] GRAB DOMAIN DARI ZONE-H ---
run_module_zoneh() {
    log_info "Memulai Grab Domain dari Zone-H..."
    if [[ -z "$TARGET" ]]; then log_error "Nama Notifier diperlukan."; return 1; fi
    local N="$TARGET"; local ZU="http://www.zone-h.org/archive/notifier=$N"
    log_info "[*] Mengambil data dari Zone-H untuk notifier: $N"
    local R; R=$(curl -s "$ZU" --connect-timeout 10 -H "User-Agent: $KINFO_USER_AGENT" 2>/dev/null)
    if [[ -z "$R" ]]; then log_error "Gagal mengambil data dari Zone-H"; return 1; fi
    local TD; TD=$(add_temp_file); echo "$R" | grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' | grep -v "Domain" | sort -u > "$TD"
    local dc; dc=$(wc -l < "$TD"); if [[ $dc -eq 0 ]]; then log_warn "Tidak ada domain ditemukan."; return 0; fi
    log_info "[+] Ditemukan $dc domain."
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg notifier "$N" --argjson domains "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TD")" '{"notifier": $notifier, "domains": $domains}')
    else
        OD=$(cat <<EOF
Zone-H Grabber Results
Notifier: $N
Scan Time: $(date)
======================
$(cat "$TD")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [L1] WEBSHELL FINDER [FILE ENUM] ---
check_file_suspicious() {
    local F="$1"; local KR="$2"; local RF="$3"
    local FS; FS=$(stat -c%s "$F" 2>/dev/null || echo 0)
    if [[ "$FS" -gt 1000000 ]]; then return; fi
    local MK; MK=$(grep -E -o "$KR" "$F" 2>/dev/null | head -1)
    if [[ -n "$MK" ]]; then
        local SZ; SZ=$(du -h "$F" 2>/dev/null | cut -f1)
        local M; M=$(stat -c %y "$F" 2>/dev/null | cut -d'.' -f1)
        jq -n --arg file "$F" --arg size "$SZ" --arg modified "$M" --arg keyword "$MK" \
            '{"file": $file, "size": $size, "modified": $modified, "matched_keyword": $keyword}' >> "$RF"
    fi
}
export -f check_file_suspicious
run_module_filescan() {
    log_info "Memulai Webshell Finder [File Enumeration]..."
    if [[ -z "$TARGET" ]]; then log_error "Target path direktori lokal diperlukan."; return 1; fi
    local SD="$TARGET"; if [[ ! -d "$SD" ]]; then log_error "Direktori tidak ada: $SD"; return 1; fi
    local SKW=("eval" "base64_decode" "gzinflate" "exec" "system" "passthru" "shell_exec" "assert" "preg_replace.*\/e" "create_function" "call_user_func" "array_map" "ob_start" "error_reporting\(0\)" "\$_(POST|GET|REQUEST|COOKIE|SERVER)" "file_put_contents" "fwrite" "fopen" "curl_exec" "file_get_contents" "include" "require" "chr\(" "ord\(" "hex2bin" "str_rot13" "strrev" "GLOBALS" "FLAG" "password" "token" "key" "secret")
    local KR; KR=$(printf "%s|" "${SKW[@]}"); KR="${KR%|}"
    log_info "[*] Memindai file mencurigakan di: $SD (Paralel: $PARALLEL_JOBS)..."
    local TJL; TJL=$(add_temp_file); export KR; export TJL
    find "$SD" -type f \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php3" -o -iname "*.php4" -o -iname "*.php5" -o -iname "*.inc" -o -iname "*.asp" -o -iname "*.aspx" -o -iname "*.jsp" \) -print0 2>/dev/null | \
    xargs -0 -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_file_suspicious \"{}\" \"$KR\" \"$TJL\""
    local fc; fc=$(wc -l < "$TJL"); log_info "[+] Pemindaian selesai. Ditemukan $fc file mencurigakan."
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada file mencurigakan yang ditemukan."; return 0; fi
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then OD=$(jq -s '.' "$TJL"); else
        OD=$(cat <<EOF
Webshell File Enumeration Results
Directory: $SD
Scan Time: $(date)
==================================
$(cat "$TJL" | jq -r '"[!] \(.file) (Size: \(.size), Keyword: \(.keyword))"')
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [L2] CEK PROSES LOKAL ---
run_module_local_ps() {
    log_info "Memulai Pengecekan Proses Mencurigakan (Lokal)..."
    if ! command -v ps &>/dev/null; then log_error "Perintah 'ps' tidak ditemukan."; return 1; fi
    local WU="www-data|apache|nginx|httpd|nobody"
    log_info "Mencari proses yang berjalan sebagai: $WU"
    local TP; TP=$(add_temp_file)
    ps aux | grep -E "$WU" | grep -v "grep" > "$TP"
    local fc; fc=$(wc -l < "$TP"); log_info "[+] Ditemukan $fc proses yang cocok."
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --argjson processes "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TP")" \
            '{"module": "local_processes", "web_users_checked": $WU, "processes": $processes}')
    else
        OD=$(cat <<EOF
Pengecekan Proses Lokal (Web Users)
Waktu: $(date)
User dicek: $WU
==================================
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
$(cat "$TP")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [L3] CEK JARINGAN LOKAL ---
run_module_local_net() {
    log_info "Memulai Pengecekan Koneksi Jaringan (Lokal)..."
    local NC=""
    if command -v ss &>/dev/null; then NC="ss -antp";
    elif command -v netstat &>/dev/null; then NC="netstat -antp";
    else log_error "Perintah 'netstat' atau 'ss' tidak ditemukan."; return 1; fi
    log_info "Menjalankan '$NC'. Mencari koneksi ESTABLISHED atau LISTEN..."
    local TN; TN=$(add_temp_file)
    (echo "HEADER: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name"; \
     sudo $NC 2>/dev/null | grep -E "(ESTABLISHED|LISTEN)") > "$TN"
    local fc; fc=$(( $(wc -l < "$TN") - 1 )); log_info "[+] Ditemukan $fc koneksi menarik."
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg command_used "$NC" --argjson connections "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TN")" \
            '{"module": "local_network", "command": $command_used, "connections": $connections}')
    else
        OD=$(cat <<EOF
Pengecekan Jaringan Lokal (ESTABLISHED & LISTEN)
Waktu: $(date)
Perintah: $NC (Mungkin perlu sudo untuk melihat nama program)
==================================
$(cat "$TN")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [L4] CEK USER & LOGIN LOKAL ---
run_module_local_users() {
    log_info "Memulai Pengecekan User & Login (Lokal)..."
    local TI; TI=$(add_temp_file)
    echo "--- User Yang Sedang Login (who) ---" >> "$TI"
    (who -u 2>/dev/null || echo "Perintah 'who' tidak tersedia.") >> "$TI"
    echo "" >> "$TI"; echo "--- Histori Login (last - 20 entri) ---" >> "$TI"
    (last -n 20 2>/dev/null || echo "Perintah 'last' tidak tersedia.") >> "$TI"
    echo "" >> "$TI"; echo "--- Terakhir Login (lastlog - 10 terbaru) ---" >> "$TI"
    (lastlog 2>/dev/null | head -n 11 || echo "Perintah 'lastlog' tidak tersedia.") >> "$TI"
    echo "" >> "$TI"; echo "--- Modifikasi File User (Baru/Diubah) ---" >> "$TI"
    (ls -l /etc/passwd /etc/shadow /etc/group 2>/dev/null || echo "Tidak dapat membaca file user.") >> "$TI"
    echo "" >> "$TI"; echo "--- /etc/passwd (User uid >= 1000 atau uid = 0) ---" >> "$TI"
    (awk -F: '($3 >= 1000 || $3 == 0) {print}' /etc/passwd 2>/dev/null) >> "$TI"
    log_info "[+] Pengecekan user dan login selesai."
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg info "$(cat "$TI")" '{"module": "local_users_login", "info": $info}')
    else
        OD=$(cat <<EOF
Pengecekan User & Login Lokal
Waktu: $(date)
==================================
$(cat "$TI")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [L5] CEK CRON MENDALAM LOKAL ---
run_module_local_cron() {
    log_info "Memulai Pengecekan Cron Mendalam (Lokal)..."
    local TI; TI=$(add_temp_file)
    echo "--- Crontab (root) ---" >> "$TI"
    (sudo crontab -l -u root 2>/dev/null || echo "Tidak ada crontab untuk root.") >> "$TI"
    echo "" >> "$TI"; echo "--- Crontab (current user: $USER) ---" >> "$TI"
    (crontab -l 2>/dev/null || echo "Tidak ada crontab untuk $USER.") >> "$TI"
    echo "" >> "$TI"; echo "--- Crontab User Lain (/var/spool/cron/) ---" >> "$TI"
    (sudo ls -l /var/spool/cron/crontabs/ 2>/dev/null || sudo ls -l /var/spool/cron/ 2>/dev/null || echo "Tidak ada/bisa membaca file cron user lain.") >> "$TI"
    echo "" >> "$TI"; echo "--- Cron Drop-ins (/etc/cron.d, etc) ---" >> "$TI"
    (sudo ls -l /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null || echo "Tidak dapat membaca /etc/cron* direktori.") >> "$TI"
    log_info "[+] Pengecekan cron selesai."
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg info "$(cat "$TI")" '{"module": "local_cron", "info": $info}')
    else
        OD=$(cat <<EOF
Pengecekan Cron Mendalam Lokal
Waktu: $(date)
==================================
$(cat "$TI")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- *** BARU v3.0 *** [L6] KUMPULKAN ARTEFAK SISTEM (FULL) ---
# Helper dari UbuntuIR.sh untuk mengambil history semua user
get_all_history() {
    local history_file="$1"
    log_info "Mengumpulkan .bash_history dari semua user..."
    
    # Fungsi nested untuk memproses per user
    _process_user_history() {
        local user_dir="$1"
        local user_name
        user_name=$(basename "$user_dir")
        local HIST_FILE="$user_dir/.bash_history"
        
        if [[ -f "$HIST_FILE" ]]; then
            echo -e "\n========================================================" >> "$history_file"
            echo "🧑‍💻 USER: $user_name ($HIST_FILE)" >> "$history_file"
            echo "========================================================" >> "$history_file"
            sudo cat "$HIST_FILE" >> "$history_file" 2>/dev/null
        fi
    }
    
    # Loop semua user home dir
    for i in /home/*; do
        [ -d "$i" ] && _process_user_history "$i"
    done
    _process_user_history "/root"
}

# Helper dari UbuntuIR.sh untuk mengambil cron semua user
get_all_crons() {
    local cron_file="$1"
    log_info "Mengumpulkan crontab dari semua user..."
    
    for user in $(cut -f1 -d: /etc/passwd); do
        echo -e "\n========================================================" >> "$cron_file"
        echo "⏱️  CRON UNTUK USER: $user" >> "$cron_file"
        echo "========================================================" >> "$cron_file"
        sudo crontab -l -u "$user" >> "$cron_file" 2>/dev/null || echo "Tidak ada cron untuk $user" >> "$cron_file"
    done
}

run_module_local_collect() {
    log_info "Memulai Koleksi Artefak Sistem (Full)..."
    
    # Modul ini WAJIB root
    if [[ $EUID -ne 0 ]]; then
        log_error "Modul ini harus dijalankan sebagai root. Gunakan 'sudo ./kinfo.sh ...'"
        return 1
    fi
    
    if [[ -z "$TARGET" ]]; then
        log_warn "Target path tidak diset. Menggunakan '/var/www' sebagai default."
        TARGET="/var/www"
    fi
    local SCAN_PATH="$TARGET"
    if [[ ! -d "$SCAN_PATH" ]]; then
        log_error "Direktori '$SCAN_PATH' tidak ditemukan. Membatalkan."
        return 1
    fi
    log_info "Path target untuk pemindaian file: $SCAN_PATH"

    # Buat direktori koleksi
    local TIMESTAMP
    TIMESTAMP=$(date "+%Y%m%d-%H%M%S")
    local COLLECT_DIR="$IR_DATA_DIR/IR-Collection-$TIMESTAMP"
    if ! mkdir -p "$COLLECT_DIR"; then
        log_error "Gagal membuat direktori koleksi: $COLLECT_DIR"; return 1
    fi
    log_info "Artefak akan disimpan di: $COLLECT_DIR"

    # Meniru koleksi dari UbuntuIR.sh
    log_info "Mengumpulkan Info Sistem..."
    date > "$COLLECT_DIR/0_DateTime.txt"
    uname -a > "$COLLECT_DIR/1_KernelVersion.txt"
    cat /etc/*-release > "$COLLECT_DIR/2_OSVersion.txt"
    
    log_info "Mengumpulkan Info Proses & Servis..."
    ps aux > "$COLLECT_DIR/3_ProcessList_aux.txt"
    top -b -n 1 > "$COLLECT_DIR/4_TopRunning.txt"
    
    log_info "Mengumpulkan Info Jaringan..."
    (netstat -tulnp || ss -tuln) > "$COLLECT_DIR/8_Network_Listen.txt" 2>/dev/null
    (netstat -antup || ss -antup) > "$COLLECT_DIR/9_Network_All.txt" 2>/dev/null
    (netstat -antup || ss -antup) | grep "ESTA" > "$COLLECT_DIR/10_Network_Established.txt" 2>/dev/null
    w > "$COLLECT_DIR/11_Users_LoggedOn.txt"
    cat /etc/resolv.conf > "$COLLECT_DIR/12_DNS.txt"
    cat /etc/hostname > "$COLLECT_DIR/13_Hostname.txt"
    cat /etc/hosts > "$COLLECT_DIR/14_Hosts.txt"

    log_info "Mengumpulkan Info User..."
    get_all_history "$COLLECT_DIR/5_All_BashHistory.txt"
    cat /etc/passwd > "$COLLECT_DIR/15_Users_Passwd.txt"
    cat /etc/passwd | grep "bash" > "$COLLECT_DIR/16_Users_Bash.txt"
    lastlog > "$COLLECT_DIR/17_Lastlog.txt"
    last > "$COLLECT_DIR/18_Last.txt"
    
    log_info "Mengumpulkan Info Cron..."
    ls -al /etc/cron* > "$COLLECT_DIR/6_Cron_etc.txt"
    ls -al /var/spool/cron/crontabs/ > "$COLLECT_DIR/7_Cron_spool.txt" 2>/dev/null
    get_all_crons "$COLLECT_DIR/7-2_Cron_AllUsers.txt"
    
    log_info "Mengumpulkan Info File System (Ini mungkin butuh waktu)..."
    log_info "Listing /home..."
    ls -alrtR /home > "$COLLECT_DIR/19_Homedir_List.txt" 2>/dev/null
    log_info "Listing $SCAN_PATH..."
    ls -alrtR "$SCAN_PATH" > "$COLLECT_DIR/20_ScanPath_List.txt" 2>/dev/null
    
    log_info "Mencari file yang baru diubah di $SCAN_PATH..."
    find "$SCAN_PATH" -type f -mtime -30 -ls > "$COLLECT_DIR/24_LastModified30d.txt" 2>/dev/null
    find "$SCAN_PATH" -type f -ctime -30 -ls > "$COLLECT_DIR/25_NewFiles30d.txt" 2>/dev/null
    
    log_info "Mencari indikator Webshell di /home (Ini mungkin butuh waktu)..."
    grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|fclose|readfile) *\(" /home/ > "$COLLECT_DIR/21_BackdoorScan_Home.txt" 2>/dev/null
    
    log_info "Mencari indikator Webshell di $SCAN_PATH (Ini mungkin butuh waktu)..."
    grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|fclose|readfile) *\(" "$SCAN_PATH" > "$COLLECT_DIR/22_BackdoorScan_ScanPath.txt" 2>/dev/null

    log_info "Mencari indikator Judi di $SCAN_PATH (Ini mungkin butuh waktu)..."
    grep -Rinw "$SCAN_PATH" -e "gacor" -e "maxwin" -e "thailand" -e "sigmaslot" -e "zeus" -e "cuan" > "$COLLECT_DIR/23_JudiScan_ScanPath.txt" 2>/dev/null
    
    log_info "Koleksi artefak selesai."
    
    # Kompresi hasil
    log_info "Mengkompres hasil..."
    local TAR_FILE="$IR_DATA_DIR/IR-Collection-$TIMESTAMP.tar.gz"
    if tar -czf "$TAR_FILE" -C "$IR_DATA_DIR" "$(basename "$COLLECT_DIR")"; then
        log_result "Sukses! Koleksi artefak disimpan di: $TAR_FILE"
        log_info "Menghapus folder data mentah..."
        rm -rf "$COLLECT_DIR"
    else
        log_error "Gagal mengkompres data. Data mentah disimpan di: $COLLECT_DIR"
    fi
}

# --- [L7] MINI SHELL FTP CLIENT (INTERAKTIF SAJA) ---
mini_ftp_client() {
    log_info "Memulai Mini Shell FTP Client..."
    local H P U PW; read -p "Enter FTP host: " H; read -p "Enter FTP port (default 21): " P
    read -p "Enter username: " U; read -sp "Enter password: " PW; echo ""
    if [[ -z "$H" || -z "$U" ]]; then log_error "Host dan username tidak boleh kosong!"; return 1; fi
    if [[ -z "$P" ]]; then P=21; fi; if ! command -v ftp &>/dev/null; then log_error "FTP client tidak ditemukan!"; return 1; fi
    echo ""; echo "FTP Client Commands:"; echo "  ls, cd, pwd, get, put, mkdir, rmdir, delete, rename"; echo "  binary, ascii, passive, exit"; echo "=============================="
    ftp -inv "$H" "$P" <<EOF
user $U $PW
passive
binary
prompt
!echo 'Koneksi berhasil. Ketik ''bye'' atau ''exit'' untuk keluar.'
EOF
    log_info "Sesi FTP ditutup."
}

# --- MODE INTERAKTIF (MENU TERPISAH) ---
menu_remote() {
    while true; do
        show_banner
        echo "┌──(${USER})-[KINFO]"
        echo "└─$ MODE: REMOTE SCANNER"
        echo ""
        echo " [1] Enhanced Subdomain Finder"
        echo " [2] Directory/File Enumeration"
        echo " [3] FTP Bruteforce"
        echo " [4] Judi Online Finder"
        echo " [5] Reverse IP Lookup"
        echo " [6] Extract Domain [Auto Add HTTPS]"
        echo " [7] Webshell Finder [DirScan]"
        echo " [8] ENV & Debug Method Scanner"
        echo " [9] WordPress Registration Finder"
        echo " [10] Grab Domain from Zone-H"
        echo " [11] Kembali ke Menu Utama"
        echo ""
        read -p "Pilih Opsi Remote (1-11): " pilihan

        TARGET=""; OUTPUT_FILE="$OUTPUT_DIR/kinfo_R${pilihan}_$(date +%s).txt"
        log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
        
        case $pilihan in
            1) read -p "Enter domain (e.g., target.com): " TARGET; run_module_subdomain ;;
            2) read -p "Enter target URL (e.g., https://target.com): " TARGET; run_module_direnum ;;
            3) read -p "Enter FTP host:port (e.g., 1.2.3.4:21): " TARGET; run_module_ftpbrute ;;
            4) read -p "Enter domain (e.g., target.com): " TARGET; run_module_judi ;;
            5) read -p "Enter IP Address: " TARGET; run_module_reverseip ;;
            6) read -p "Enter URL (e.g., http://www.target.com/path): " TARGET; run_module_extract ;;
            7) read -p "Enter target URL (e.g., https://target.com): " TARGET; run_module_webscan ;;
            8) read -p "Enter target URL (e.g., https://target.com): " TARGET; run_module_envscan ;;
            9) read -p "Enter domain (e.g., target.com): " TARGET; run_module_wpcheck ;;
            10) read -p "Enter Zone-H notifier name: " TARGET; run_module_zoneh ;;
            11) break ;;
            *) log_error "Opsi tidak valid. Silakan pilih 1-11"; sleep 2 ;;
        esac
        
        if [[ "$pilihan" -ne 11 ]]; then echo ""; read -p "Tekan Enter untuk melanjutkan..."; fi
    done
}

menu_local() {
    while true; do
        show_banner
        echo "┌──(${USER})-[KINFO]"
        echo "└─$ MODE: LOCAL INCIDENT RESPONSE"
        echo ""
        echo "--- Pemindaian Cepat ---"
        echo " [1] Webshell Finder [File Enumeration]"
        echo " [2] Pengecekan Proses Mencurigakan"
        echo " [3] Pengecekan Koneksi Jaringan"
        echo " [4] Pengecekan User & Login"
        echo " [5] Pengecekan Cron Mendalam"
        echo ""
        echo "--- Koleksi Penuh ---"
        echo " [6] Kumpulkan Artefak Sistem (Full) (Perlu Root & Target Path)"
        echo ""
        echo "--- Utilitas ---"
        echo " [7] Mini Shell FTP Client"
        echo " [8] Kembali ke Menu Utama"
        echo ""
        read -p "Pilih Opsi Lokal (1-8): " pilihan

        TARGET=""; OUTPUT_FILE="$OUTPUT_DIR/kinfo_L${pilihan}_$(date +%s).txt"
        
        case $pilihan in
            1) 
                log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
                read -p "Enter local directory path (default: .): " TARGET; if [[ -z "$TARGET" ]]; then TARGET="."; fi; run_module_filescan ;;
            2) 
                log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
                run_module_local_ps ;;
            3) 
                log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
                run_module_local_net ;;
            4) 
                log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
                run_module_local_users ;;
            5) 
                log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
                run_module_local_cron ;;
            6) 
                # Modul L6 (localcollect) TIDAK menggunakan $OUTPUT_FILE standar, ia punya folder sendiri
                read -p "Enter path direktori untuk dipindai (e.g., /var/www, /home): " TARGET
                run_module_local_collect ;;
            7) 
                # Modul FTP tidak menghasilkan file output
                log_info "Menjalankan FTP Client..."
                mini_ftp_client ;;
            8) break ;;
            *) log_error "Opsi tidak valid. Silakan pilih 1-8"; sleep 2 ;;
        esac
        
        if [[ "$pilihan" -ne 8 ]]; then echo ""; read -p "Tekan Enter untuk melanjutkan..."; fi
    done
}

main_interactive() {
    PARALLEL_JOBS=20; RATE_LIMIT=0; OUTPUT_FORMAT="text"
    WORDLIST="$SCRIPT_DIR/wordlist.txt"
    FTP_LIST="$SCRIPT_DIR/ftpbrute.txt"
    JUDI_LIST="$SCRIPT_DIR/judilist.txt"
    while true; do
        show_banner
        echo "--- MENU UTAMA ---"
        echo -e " [R] ${CYAN}Remote Scanner${NC} (Scan Target Eksternal)"
        echo -e " [L] ${YELLOW}Local IR${NC}       (Scan Mesin Ini)"
        echo -e " [Q] ${RED}Quit${NC}"
        echo ""
        read -p "Pilih Mode (R/L/Q): " mode
        
        case $mode in
            R|r) menu_remote ;;
            L|l) menu_local ;;
            Q|q) break ;;
            *) log_error "Pilihan tidak valid."; sleep 1 ;;
        esac
    done
}

# --- MAIN EXECUTION ---
main() {
    NON_INTERACTIVE=0; MODULE=""; TARGET=""; WORDLIST="$SCRIPT_DIR/wordlist.txt"
    FTP_LIST="$SCRIPT_DIR/ftpbrute.txt"; JUDI_LIST="$SCRIPT_DIR/judilist.txt"
    OUTPUT_FILE=""; OUTPUT_FORMAT="text"; PARALLEL_JOBS=20; RATE_LIMIT=0
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --module) MODULE="$2"; NON_INTERACTIVE=1; shift 2 ;;
            -t|--target) TARGET="$2"; NON_INTERACTIVE=1; shift 2 ;;
            -w|--wordlist) WORDLIST="$2"; shift 2 ;;
            --ftp-list) FTP_LIST="$2"; shift 2 ;;
            --judi-list) JUDI_LIST="$2"; shift 2 ;;
            -o|--output-file) OUTPUT_FILE="$2"; shift 2 ;;
            -f|--output-format) OUTPUT_FORMAT="$2"; shift 2 ;;
            -p|--parallel) PARALLEL_JOBS="$2"; shift 2 ;;
            -r|--rate-limit) RATE_LIMIT="$2"; shift 2 ;;
            -l|--logfile) LOG_FILE="$2"; shift 2 ;;
            -d|--debug) DEBUG_MODE=1; shift 1 ;;
            -h|--help) show_usage; exit 0 ;;
            *) shift 1 ;;
        esac
    done

    check_dependencies
    log_debug "Mode Debug Aktif."
    
    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        log_info "Menjalankan KINFO v$VERSION (Mode Non-Interaktif)"
        if [[ -z "$MODULE" ]]; then log_error "Mode non-interaktif membutuhkan --module"; show_usage; exit 1; fi
        
        case "$MODULE" in
            localps|localnet|localusers|localcron)
                # Modul lokal ini tidak membutuhkan --target
                ;;
            ftpclient)
                log_error "Modul 'ftpclient' (L7) hanya tersedia dalam mode Interaktif."; exit 1
                ;;
            *)
                # Semua modul lain membutuhkan --target
                if [[ -z "$TARGET" ]]; then log_error "Modul '$MODULE' membutuhkan --target <target>"; show_usage; exit 1; fi
                ;;
        esac

        # Tentukan file output, KECUALI untuk localcollect
        if [[ "$MODULE" != "localcollect" ]]; then
            if [[ -z "$OUTPUT_FILE" ]]; then
                if [[ "$OUTPUT_FORMAT" == "json" ]]; then
                    OUTPUT_FILE="/dev/stdout"
                else
                    OUTPUT_FILE="$OUTPUT_DIR/kinfo_${MODULE}_$(date +%s).txt"
                fi
            else
                OUTPUT_FILE="$OUTPUT_DIR/$OUTPUT_FILE"
            fi
            log_debug "Output File: $OUTPUT_FILE"
        fi

        export TARGET; export WORDLIST; export FTP_LIST; export JUDI_LIST; export OUTPUT_FILE
        export OUTPUT_FORMAT; export PARALLEL_JOBS; export RATE_LIMIT; export KINFO_USER_AGENT; export DORK_UA
        
        case "$MODULE" in
            # Remote
            subdomain) run_module_subdomain ;;
            direnum) run_module_direnum ;;
            ftpbrute) run_module_ftpbrute ;;
            judi) run_module_judi ;;
            reverseip) run_module_reverseip ;;
            extract) run_module_extract ;;
            webscan) run_module_webscan ;;
            envscan) run_module_envscan ;;
            wpcheck) run_module_wpcheck ;;
            zoneh) run_module_zoneh ;;
            # Lokal
            filescan) run_module_filescan ;;
            localps) run_module_local_ps ;;
            localnet) run_module_local_net ;;
            localusers) run_module_local_users ;;
            localcron) run_module_local_cron ;;
            localcollect) run_module_local_collect ;; # Modul koleksi penuh
            *) log_error "Modul tidak dikenal: '$MODULE'"; show_usage; exit 1 ;;
        esac
        
        if [[ "$MODULE" != "localcollect" ]]; then
            log_info "Eksekusi selesai. Output disimpan di: $OUTPUT_FILE"
        fi

    else
        main_interactive
    fi
}
main "$@"
