#!/bin/bash

# KINFO - Incident Response & Pentest Toolkit
# Versi: 1.3 (Integrasi Kolektor Artefak IR)
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
VERSION="1.3"
KINFO_USER_AGENT="Mozilla/5.0 KINFO/$VERSION"
DORK_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"

# --- LOKASI SCRIPT & FOLDER OUTPUT ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/outputkinfo"
# *** BARU v3.0: Folder untuk Koleksi IR Penuh ***
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

# --- [R1] ENHANCED SUBDOMAIN FINDER ---
resolve_subdomain() { local S="$1"; if nslookup "$S" >/dev/null 2>&1; then echo "$S"; fi; }
export -f resolve_subdomain
check_subdomain_http() {
    local S="$1"; local RF="$2"; local UA="$3"
    for P in "https" "http"; do
        local U="$P://$S"; local SC; SC=$(curl -sL -I -o /dev/null -w "%{http_code}" --max-time 5 "$U" -A "$UA")
        if [[ "$SC" =~ ^(2|3|401|403) ]]; then
            jq -n --arg url "$U" --arg status "$SC" '{"url": $url, "status": $status_code}' >> "$RF"; break
        fi
    done
}
export -f check_subdomain_http
run_module_subdomain() {
    log_info "Memulai Enhanced Subdomain Finder..."
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    local ST; ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    log_debug "Input asli '$TARGET' disanitasi menjadi '$ST'"
    if [[ -z "$ST" ]]; then log_error "Input target tidak valid."; return 1; fi
    if ! command -v jq &>/dev/null; then log_warn "Perintah 'jq' tidak ditemukan."; fi
    if ! command -v nslookup &>/dev/null; then log_warn "Perintah 'nslookup' tidak ditemukan."; fi
    local TFA; TFA=$(add_temp_file); log_debug "Temp file: $TFA"
    log_info "[*] Mengecek crt.sh..."
    curl -s "https://crt.sh/?q=%.${ST}&output=json" -A "$KINFO_USER_AGENT"|jq -r '.[].name_value' 2>/dev/null|grep -Po '(\S+\.)+\S+' >> "$TFA"
    log_info "[*] Mengecek bufferover.run..."
    curl -s "https://dns.bufferover.run/dns?q=.${ST}" -A "$KINFO_USER_AGENT" 2>/dev/null|jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null|cut -d',' -f2 >> "$TFA"
    log_info "[*] Mengecek alienvault.com..."
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${ST}/passive_dns" -A "$KINFO_USER_AGENT" 2>/dev/null|jq -r '.passive_dns[].hostname' 2>/dev/null|grep "\.${ST}$" >> "$TFA"
    log_info "[*] Mengecek threatcrowd.org..."
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${ST}" -A "$KINFO_USER_AGENT" 2>/dev/null|jq -r '.subdomains[]' 2>/dev/null >> "$TFA"
    sort -u "$TFA" -o "$TFA"; cp "$TFA" "/tmp/kinfo_last_subdomains_${ST}.txt"
    local total; total=$(wc -l < "$TFA"); log_info "[+] Ditemukan total $total subdomain unik (dari API)."
    log_info "[*] Melakukan DNS resolution paralel (Proses: $PARALLEL_JOBS)..."
    local TFD; TFD=$(add_temp_file)
    cat "$TFA" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "resolve_subdomain {}" >> "$TFD"
    local dlc; dlc=$(wc -l < "$TFD"); log_info "[+] Ditemukan $dlc subdomain yang DNS LIVE."
    log_info "[*] Melakukan HTTP check paralel pada subdomain DNS Live (Proses: $PARALLEL_JOBS)..."
    local TFH; TFH=$(add_temp_file); export KINFO_USER_AGENT; export TFH
    cat "$TFD" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "check_subdomain_http \"{}\" \"$TFH\" \"$KINFO_USER_AGENT\""
    local hlc; hlc=$(wc -l < "$TFH"); log_info "[+] Ditemukan $hlc subdomain yang HTTP LIVE."
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -n --arg target "$ST" --arg total_api "$total" --arg total_dns_live "$dlc" --arg total_http_live "$hlc" \
            --argjson all_api "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TFA")" \
            --argjson dns_live "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TFD")" \
            --argjson http_live "$(jq -s '.' "$TFH")" \
            '{target: $target, total_found_api: $total_api, total_dns_live: $total_dns_live, total_http_live: $total_http_live, all_subdomains_api: $all_api, dns_live_subdomains: $dns_live, http_live_subdomains: $http_live}'
    else
        cat <<EOF
KINFO Enhanced Subdomain Finder Results
Target: $ST
Scan Time: $(date)
Total Found (API): $total | DNS Live: $dlc | HTTP Live: $hlc
====================================
ALL SUBDOMAINS (Total: $total):
$(cat "$TFA")

DNS LIVE SUBDOMAINS (Total: $dlc):
$(cat "$TFD")

HTTP LIVE SUBDOMAINS (Total: $hlc):
$(cat "$TFH" | jq -r '"[\(.status)] \(.url)"')
EOF
    fi | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    log_info "Pencarian subdomain selesai."
}

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

# --- [R4] JUDI ONLINE FINDER ---
check_judi_homepage() {
    local U="$1"; local KLF="$2"; local RF="$3"
    local C; C=$(curl -sL "$U" --connect-timeout 5 --max-time 10 -H "User-Agent: $KINFO_USER_AGENT" 2>/dev/null)
    if [[ -z "$C" ]]; then return; fi
    while IFS= read -r K; do
        if [[ -z "$K" || "$K" == \#* ]]; then continue; fi
        if echo "$C" | grep -iq "$K"; then
            log_debug "Direct scan match: $K di $U"
            jq -n --arg method "direct_scan" --arg url "$U" --arg keyword "$K" \
                '{"method": $method, "url": $url, "keyword": $keyword}' >> "$RF"; break
        fi
    done < "$KLF"
}
export -f check_judi_homepage
check_judi_bing() {
    local TD="$1"; local K="$2"; local RF="$3"; local UA="$4"
    local Q; Q=$(printf "site:%s \"%s\"" "$TD" "$K" | jq -sRr @uri)
    local BU="https://www.bing.com/search?q=$Q"
    local R; R=$(curl -sL --max-time 10 -A "$UA" "$BU")
    if echo "$R" | grep -iq "$TD" && ! echo "$R" | grep -iqE "(Tidak ada hasil untuk|No results for)"; then
        log_debug "Bing dork match for keyword: $K"
        jq -n --arg method "bing_dork" --arg url "$BU" --arg keyword "$K" \
            '{"method": $method, "url": "https://www.bing.com/search?q=site:'$TD'+\"'${K}'\"", "keyword": $keyword}' >> "$RF"
    fi
}
export -f check_judi_bing
run_module_judi() {
    log_info "Memulai Judi Online Finder..."
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    local ST; ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    log_debug "Input asli '$TARGET' disanitasi menjadi '$ST'"
    if [[ -z "$ST" ]]; then log_error "Input target tidak valid."; return 1; fi
    if [[ ! -f "$JUDI_LIST" ]]; then log_error "Wordlist Judi tidak ditemukan di: $JUDI_LIST"; return 1; fi
    local kc; kc=$(grep -vE "^\s*#|^\s*$" "$JUDI_LIST" | wc -l)
    log_info "[*] Menggunakan $JUDI_LIST ($kc keywords)"
    local SF="/tmp/kinfo_last_subdomains_${ST}.txt"; local TS=("$ST")
    if [[ -f "$SF" ]]; then
        log_info "[*] Menggunakan daftar subdomain dari scan Modul 1 ($SF)"
        mapfile -t-O "${#TS[@]}" TS < <(grep -vE "^\s*#|^\s*$" "$SF")
    else log_warn "[*] Tidak ada daftar subdomain. Hanya memindai domain utama."; fi
    local tt; tt=${#TS[@]}; log_info "[*] Total $tt domain/subdomain akan diperiksa..."
    local TUC; TUC=$(add_temp_file); local TJL; TJL=$(add_temp_file)
    log_info "[*] Memulai Metode 1: Direct Scan (Homepage) (Paralel: $PARALLEL_JOBS)..."
    for T in "${TS[@]}"; do echo "https://$T" >> "$TUC"; echo "http://$T" >> "$TUC"; done
    export JUDI_LIST; export KINFO_USER_AGENT; export TJL
    cat "$TUC" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "check_judi_homepage \"{}\" \"$JUDI_LIST\" \"$TJL\""
    log_info "[*] Memulai Metode 2: Bing Dork Scan (Mencari di sub-halaman)..."
    export DORK_UA
    grep -vE "^\s*#|^\s*$" "$JUDI_LIST" | xargs -P 5 -I {} \
        bash -c "check_judi_bing \"$ST\" \"{}\" \"$TJL\" \"$DORK_UA\""
    local fc; fc=$(wc -l < "$TJL"); log_info "[+] Pemindaian selesai."
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada konten judi yang terdeteksi."; return 0; fi
    log_result "[FOUND] Ditemukan $fc indikasi konten judi!"
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then OD=$(jq -s '.' "$TJL"); else
        OD=$(cat <<EOF
Judi Online Finder Results
Domain: $ST
Scan Time: $(date)
==================================
$(cat "$TJL" | jq -r '"[+] (\(.method)) \(.url) (Keyword: \(.keyword))"')
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [R5] REVERSE IP LOOKUP ---
run_module_reverseip() {
    log_info "Memulai Reverse IP Lookup..."
    if [[ -z "$TARGET" ]]; then log_error "Target IP Address diperlukan."; return 1; fi
    local IP="$TARGET"
    if [[ ! $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then log_error "Format IP tidak valid: $IP"; return 1; fi
    log_info "[*] Melakukan reverse IP lookup untuk $IP..."
    local VDU="https://viewdns.info/reverseip/?host=$IP&t=1"
    local R; R=$(curl -s "$VDU" -H "User-Agent: $KINFO_USER_AGENT")
    local TD; TD=$(add_temp_file); echo "$R" | grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' | grep -v "$IP" | sort -u > "$TD"
    local D; mapfile -t D < "$TD"; local total=${#D[@]}
    if [[ $total -eq 0 ]]; then
        log_warn "[*] viewdns.info tidak mengembalikan hasil. Mencoba 'whois'..."
        if command -v whois &>/dev/null; then
            local WR; WR=$(whois "$IP" 2>/dev/null | grep -i "domain\|netname")
            if [[ -n "$WR" ]]; then log_warn "[!] Informasi terbatas dari WHOIS:"; echo "$WR" > "$TD";
            else log_error "[!] Tidak ada domain ditemukan untuk IP $IP"; return 1; fi
        else log_error "[!] 'whois' tidak terinstall."; return 1; fi
    fi
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg ip "$IP" --argjson domains "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TD")" '{"ip": $ip, "domains": $domains}')
    else
        OD=$(cat <<EOF
Reverse IP Lookup Results
Target IP: $IP
Scan Time: $(date)
==================================
Domains:
$(cat "$TD")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

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

# --- [R7] WEBSHELL FINDER [DIRSCAN] ---
run_module_webscan() {
    log_info "Memulai Webshell Finder [Directory Scan]..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    local WSP=("shell.php" "backdoor.php" "cmd.php" "wso.php" "up.php" "upload.php" "sh.php" "phpinfo.php" "info.php" "test.php" "1.php" "wordpress.php" "IndoXploit.php" "b374k.php" "adminer.php" "phpMyAdmin/index.php" "pma/index.php" "mysql.php" "wp-config.php" "configuration.php" "settings.php" "web.config" "shell.jsp" "cmd.asp" "shell.aspx" ".git/config" "composer.json" "package.json" "install.php" "admin.php" "login.php" "wp-login.php" "administrator/index.php" "user/login" "dashboard" "panel" "control" "manager" "adminpanel" "cpanel" "webmail" "upload" "uploads" "file" "files" "log" "logs" "temp" "tmp" "cache" "backup" "backups" "dev" "test" "api-docs" "swagger" "docs" "status" "health" "server-status" "server-info")
    local total=${#WSP[@]}
    log_info "[*] Memulai pemindaian pada $TARGET ($total path internal, Paralel: $PARALLEL_JOBS)..."
    local TJL; TJL=$(add_temp_file); local TPL; TPL=$(add_temp_file); printf "%s\n" "${WSP[@]}" > "$TPL"
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export TJL
    cat "$TPL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\""
    local fc; fc=$(wc -l < "$TJL"); log_info "[+] Pemindaian selesai. Ditemukan $fc item."
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada item yang ditemukan."; return 0; fi
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then OD=$(jq -s '.' "$TJL"); else
        OD=$(cat <<EOF
Webshell/Dir Scan Results
Target: $TARGET
Scan Time: $(date)
==================================
$(cat "$TJL" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort)
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [R8] ENV & DEBUG METHOD SCANNER ---
run_module_envscan() {
    log_info "Memulai ENV & Debug Method Scanner..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    local EF=(".env" ".env.backup" ".env.local" ".env.example" "config/.env" "configuration.php" "settings.php" "database.php" "db.php" "wp-config.php" "config.php" "config/database.yml" ".htpasswd" ".htaccess" "web.config" "debug.php" "phpinfo.php" "info.php" "test.php" "status" "health" "metrics" "actuator" "healthz" "readyz" "swagger" "api-docs" "v1/swagger" "docs" "robots.txt" "sitemap.xml" "server-status" "server-info" "composer.json" "package.json" "Dockerfile" "docker-compose.yml" "requirements.txt" "backup.sql" "db.sql" "database.sql" "data.sql" "dump.sql" "site.sql" "backup.tar.gz" "backup.zip" "backup.rar" "site.tar.gz" "site.zip" "database.zip" "database.tar.gz" "db.zip" "db.tar.gz" "www.zip" "www.tar.gz" "backup/backup.sql" "backup/db.sql" "backup/dump.sql" "backup/backup.zip" "backup/site.zip" "backup/db.zip" "backup/backup.tar.gz" "backups/backup.sql" "backups/db.sql" "backups/dump.sql" "backups/backup.zip" "backups/site.zip" "backups/db.zip" "backups/backup.tar.gz" "sql/backup.sql" "sql/db.sql" "sql/dump.sql" "sql/database.sql" "sql/backup.zip" "sql/db.zip" "files/backup.sql" "files/db.sql" "files/dump.sql" "files/backup.zip" "files/site.zip" "db/dump.sql" "db/db.sql" "db/database.sql" "db/backup.zip" "db/db.zip" "uploads/backup.sql" "uploads/db.sql" "uploads/dump.sql" "uploads/backup.zip" "uploads/site.zip" "_backup/backup.sql" "_backup/db.sql" "_backup/dump.sql" "_backup/backup.zip" "_backup/site.zip" "_db/dump.sql" "_db/db.sql")
    local total=${#EF[@]}
    log_info "[*] Memulai pemindaian pada $TARGET ($total path internal, Paralel: $PARALLEL_JOBS)..."
    local TJL; TJL=$(add_temp_file); local TPL; TPL=$(add_temp_file); printf "%s\n" "${EF[@]}" > "$TPL"
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export TJL
    cat "$TPL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\""
    local fc; fc=$(wc -l < "$TJL"); log_info "[+] Pemindaian selesai. Ditemukan $fc item."
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada item yang ditemukan."; return 0; fi
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then OD=$(jq -s '.' "$TJL"); else
        OD=$(cat <<EOF
ENV & Debug Scan Results
Target: $TARGET
Scan Time: $(date)
==================================
$(cat "$TJL" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort)
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [R9] WORDPRESS REGISTRATION FINDER ---
run_module_wpcheck() {
    log_info "Memulai WordPress Registration Finder..."
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    local ST; ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    local WU="https://$ST"; log_info "[*] Memeriksa situs WordPress di $WU"
    local R; R=$(curl -sIL "$WU" --connect-timeout 3 --max-time 5 -H "User-Agent: $KINFO_USER_AGENT" 2>/dev/null)
    if ! echo "$R" | grep -qi "wp-content\|wordpress"; then log_warn "[!] Ini tampaknya bukan situs WordPress."; fi
    local RP=("wp-login.php?action=register" "wp-signup.php" "register" "signup" "create-account" "registration")
    local TJL; TJL=$(add_temp_file); local TPL; TPL=$(add_temp_file); printf "%s\n" "${RP[@]}" > "$TPL"
    export TARGET="$WU"; export RATE_LIMIT=0; export KINFO_USER_AGENT; export TJL
    cat "$TPL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\""
    local FU=""; local FS=""
    while IFS= read -r L; do
        if [[ $(echo "$L" | jq -r '.status') == "200" ]]; then FU=$(echo "$L" | jq -r '.url'); FS="200"; break; fi
    done < "$TJL"
    local RD=""
    if [[ -n "$FU" ]]; then log_result "[+] Ditemukan halaman registrasi potensial: $FU"; RD="Halaman registrasi ditemukan di $FU";
    else log_warn "[-] Tidak ada halaman registrasi (200 OK) yang ditemukan."; RD="Tidak ada halaman registrasi (200 OK) yang ditemukan."; fi
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg domain "$ST" --arg found_url "$FU" --arg details "$RD" \
            '{"domain": $domain, "registration_page_found": (if $found_url != "" then true else false end), "url": $found_url, "details": $details}')
    else
        OD=$(cat <<EOF
WordPress Registration Finder Results
Target: $ST
Scan Time: $(date)
==================================
Status: $RD
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
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
