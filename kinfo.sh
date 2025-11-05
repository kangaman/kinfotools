#!/bin/bash

# KINFO - Incident Response & Pentest Toolkit
# Version: 2.6 (Refactored, Local IR Modules)
# Original: https://jejakintel.t.me/
# Refactor: Gemini (dengan paralelisasi, mode non-interaktif, JSON, logging)
# Updated: 5 November 2025

# --- KONFIGURASI GLOBAL ---
VERSION="2.6"
KINFO_USER_AGENT="Mozilla/5.0 KINFO/$VERSION"
DORK_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

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
    for cmd in jq nslookup nc ftp whois ps netstat ss; do
        if ! command -v "$cmd" &>/dev/null; then
            log_warn "Dependensi opsional tidak ditemukan: $cmd. Beberapa fitur mungkin tidak berfungsi."
        fi
    done
    if [[ $missing_deps -eq 1 ]]; then
        log_error "Harap install dependensi wajib dan coba lagi."
        exit 1
    fi
    log_debug "Semua dependensi wajib ditemukan."
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
    echo "  Version: $VERSION | Update: 5 November 2025 "
    echo "  Contact: https://jejakintel.t.me/      "
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
    echo "MODULES (REMOTE):"
    echo "  subdomain       : [1] Enhanced Subdomain Finder (membutuhkan --target)"
    echo "  direnum         : [2] Directory/File Enumeration (membutuhkan --target)"
    echo "  ftpbrute        : [3] FTP Bruteforce (membutuhkan --target)"
    echo "  judi            : [4] Judi Online Finder (membutuhkan --target)"
    echo "  reverseip       : [5] Reverse IP Lookup (membutuhkan --target)"
    echo "  extract         : [6] Extract Domain & Auto Add HTTPS (membutuhkan --target)"
    echo "  webscan         : [7] Webshell Finder [DirScan] (membutuhkan --target)"
    echo "  envscan         : [9] ENV & Debug Method Scanner (membutuhkan --target)"
    echo "  wpcheck         : [10] WordPress Registration Finder (membutuhkan --target)"
    echo "  zoneh           : [11] Grab Domain from Zone-H (membutuhkan --target)"
    echo ""
    echo "MODULES (LOKAL):"
    echo "  filescan        : [8] Webshell Finder [File Enumeration] (membutuhkan --target <path>)"
    echo "  ftpclient       : [12] Mini Shell FTP Client (Hanya Interaktif)"
    echo "  localps         : [13] Pengecekan Proses Mencurigakan (Lokal)"
    echo "  localnet        : [14] Pengecekan Koneksi Jaringan (Lokal)"
    echo "  localusers      : [15] Pengecekan User & Cron (Lokal)"
    echo ""
    echo "OPTIONS:"
    echo "  -t, --target <str>        : Target (domain, URL, IP, atau path lokal untuk 'filescan')"
    echo "  -w, --wordlist <file>     : Path ke wordlist (default: $SCRIPT_DIR/wordlist.txt)"
    echo "  --ftp-list <file>         : Path ke wordlist FTP (default: $SCRIPT_DIR/ftpbrute.txt)"
    echo "  --judi-list <file>        : Path ke wordlist Judi (default: $SCRIPT_DIR/judilist.txt)"
    echo "  -o, --output-file <file>  : Simpan output ke file"
    echo "  -f, --output-format <fmt> : Format output: text (default), json"
    echo "  -p, --parallel <num>      : Jumlah proses paralel (default: 20)"
    echo "  -r, --rate-limit <sec>    : Jeda (detik) antar request (default: 0)"
    echo "  -l, --logfile <file>      : Path ke file log"
    echo "  -d, --debug               : Aktifkan mode debug (verbose)"
    echo "  -h, --help                : Tampilkan pesan bantuan ini"
    echo ""
}

# --- [MODUL 1] ENHANCED SUBDOMAIN FINDER ---
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

# --- [MODUL 2] DIRECTORY/FILE ENUMERATION ---
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

# --- [MODUL 3] FTP BRUTEFORCE ---
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

# --- [MODUL 4] JUDI ONLINE FINDER ---
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

# --- [MODUL 5] REVERSE IP LOOKUP ---
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

# --- [MODUL 6] EXTRACT DOMAIN & CHECK HEADERS ---
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

# --- [MODUL 7] WEBSHELL FINDER [DIRSCAN] ---
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

# --- [MODUL 8] WEBSHELL FINDER [FILE ENUM] ---
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

# --- [MODUL 9] ENV & DEBUG METHOD SCANNER ---
run_module_envscan() {
    log_info "Memulai ENV & Debug Method Scanner..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    # v2.5: Daftar diperluas dengan .sql, .backup, dan subfolder umum
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

# --- [MODUL 10] WORDPRESS REGISTRATION FINDER ---
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

# --- [MODUL 11] GRAB DOMAIN DARI ZONE-H ---
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

# --- [MODUL 12] MINI SHELL FTP CLIENT (INTERAKTIF SAJA) ---
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

# --- *** BARU v2.6 *** [MODUL 13] CEK PROSES LOKAL ---
run_module_local_ps() {
    log_info "Memulai Pengecekan Proses Mencurigakan (Lokal)..."
    if ! command -v ps &>/dev/null; then log_error "Perintah 'ps' tidak ditemukan."; return 1; fi
    
    # User web server yang umum
    local web_users="www-data|apache|nginx|httpd|nobody"
    log_info "Mencari proses yang berjalan sebagai: $web_users"
    
    local temp_ps; temp_ps=$(add_temp_file)
    ps aux | grep -E "$web_users" | grep -v "grep" > "$temp_ps"
    
    local fc; fc=$(wc -l < "$temp_ps")
    log_info "[+] Ditemukan $fc proses yang cocok."
    
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --argjson processes "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$temp_ps")" \
            '{"module": "local_processes", "web_users_checked": $web_users, "processes": $processes}')
    else
        OD=$(cat <<EOF
Pengecekan Proses Lokal (Web Users)
Waktu: $(date)
User dicek: $web_users
==================================
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
$(cat "$temp_ps")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- *** BARU v2.6 *** [MODUL 14] CEK JARINGAN LOKAL ---
run_module_local_net() {
    log_info "Memulai Pengecekan Koneksi Jaringan (Lokal)..."
    local net_cmd=""
    if command -v ss &>/dev/null; then net_cmd="ss -antp";
    elif command -v netstat &>/dev/null; then net_cmd="netstat -antp";
    else log_error "Perintah 'netstat' atau 'ss' tidak ditemukan."; return 1; fi

    log_info "Menjalankan '$net_cmd'. Mencari koneksi ESTABLISHED atau LISTEN..."
    
    local temp_net; temp_net=$(add_temp_file)
    (echo "HEADER: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name"; \
     sudo $net_cmd 2>/dev/null | grep -E "(ESTABLISHED|LISTEN)") > "$temp_net"
    
    local fc; fc=$(( $(wc -l < "$temp_net") - 1 ))
    log_info "[+] Ditemukan $fc koneksi menarik."

    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg command_used "$net_cmd" --argjson connections "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$temp_net")" \
            '{"module": "local_network", "command": $command_used, "connections": $connections}')
    else
        OD=$(cat <<EOF
Pengecekan Jaringan Lokal (ESTABLISHED & LISTEN)
Waktu: $(date)
Perintah: $net_cmd (Mungkin perlu sudo untuk melihat nama program)
==================================
$(cat "$temp_net")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- *** BARU v2.6 *** [MODUL 15] CEK USER & CRON LOKAL ---
run_module_local_users() {
    log_info "Memulai Pengecekan User & Cron (Lokal)..."
    
    local temp_info; temp_info=$(add_temp_file)
    
    echo "--- /etc/passwd (User uid >= 1000 atau uid = 0) ---" >> "$temp_info"
    awk -F: '($3 >= 1000 || $3 == 0) {print}' /etc/passwd >> "$temp_info"
    
    echo "" >> "$temp_info"
    echo "--- Crontab (root) ---" >> "$temp_info"
    (crontab -l -u root 2>/dev/null || echo "Tidak ada crontab untuk root") >> "$temp_info"

    echo "" >> "$temp_info"
    echo "--- Crontab (current user: $USER) ---" >> "$temp_info"
    (crontab -l 2>/dev/null || echo "Tidak ada crontab untuk $USER") >> "$temp_info"

    log_info "[+] Pengecekan user dan cron selesai."
    
    local OD
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        OD=$(jq -n --arg info "$(cat "$temp_info")" '{"module": "local_users_cron", "info": $info}')
    else
        OD=$(cat <<EOF
Pengecekan User & Cron Lokal
Waktu: $(date)
==================================
$(cat "$temp_info")
EOF
)
    fi
    echo "$OD" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}


# --- MODE INTERAKTIF (FUNGSI ASLI) ---
main_interactive() {
    PARALLEL_JOBS=20; RATE_LIMIT=0; OUTPUT_FORMAT="text"
    WORDLIST="$SCRIPT_DIR/wordlist.txt"
    FTP_LIST="$SCRIPT_DIR/ftpbrute.txt"
    JUDI_LIST="$SCRIPT_DIR/judilist.txt"
    while true; do
        show_banner
        echo "┌──(${USER})-[KINFO]"; echo "└─$ INCIDENT RESPONSE MENU:"; echo ""
        echo "--- REMOTE SCANNER ---"
        echo " [1] Enhanced Subdomain Finder"; echo " [2] Directory/File Enumeration"
        echo " [3] FTP Bruteforce (FTP/FTPS)"; echo " [4] Judi Online Finder"
        echo " [5] Reverse IP Lookup"; echo " [6] Extract Domain [Auto Add HTTPS]"
        echo " [7] Webshell Finder [DirScan]"; echo " [9] ENV & Debug Method Scanner"
        echo " [10] WordPress Registration Finder"; echo " [11] Grab Domain from Zone-H"
        echo ""
        echo "--- LOCAL IR ---"
        echo " [8] Webshell Finder [File Enumeration]"
        echo " [12] Mini Shell FTP Client"
        echo " [13] Pengecekan Proses Mencurigakan (Lokal)"
        echo " [14] Pengecekan Koneksi Jaringan (Lokal)"
        echo " [15] Pengecekan User & Cron (Lokal)"
        echo " [16] Exit"
        echo ""
        read -p "Select Option (1-16): " pilihan
        TARGET=""; OUTPUT_FILE="/tmp/kinfo_interactive_$(date +%s).txt"
        log_info "Output (jika ada) akan disimpan ke: $OUTPUT_FILE"
        case $pilihan in
            1) read -p "Enter domain (e.g., target.com): " TARGET; run_module_subdomain ;;
            2) read -p "Enter target URL (e.g., https://target.com): " TARGET; run_module_direnum ;;
            3) read -p "Enter FTP host:port (e.g., 1.2.3.4:21): " TARGET; run_module_ftpbrute ;;
            4) read -p "Enter domain (e.g., target.com): " TARGET; run_module_judi ;;
            5) read -p "Enter IP Address: " TARGET; run_module_reverseip ;;
            6) read -p "Enter URL (e.g., http://www.target.com/path): " TARGET; run_module_extract ;;
            7) read -p "Enter target URL (e.g., https://target.com): " TARGET; run_module_webscan ;;
            8) read -p "Enter local directory path (default: .): " TARGET; if [[ -z "$TARGET" ]]; then TARGET="."; fi; run_module_filescan ;;
            9) read -p "Enter target URL (e.g., https://target.com): " TARGET; run_module_envscan ;;
            10) read -p "Enter domain (e.g., target.com): " TARGET; run_module_wpcheck ;;
            11) read -p "Enter Zone-H notifier name: " TARGET; run_module_zoneh ;;
            12) mini_ftp_client ;;
            13) run_module_local_ps ;;
            14) run_module_local_net ;;
            15) run_module_local_users ;;
            16) break ;;
            *) log_error "Opsi tidak valid. Silakan pilih 1-16"; sleep 2 ;;
        esac
        if [[ "$pilihan" -ne 16 ]]; then echo ""; read -p "Tekan Enter untuk melanjutkan..."; fi
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
        
        # Cek apakah modul membutuhkan target
        case "$MODULE" in
            localps|localnet|localusers)
                # Modul lokal ini tidak membutuhkan --target
                ;;
            ftpclient)
                log_error "Modul 'ftpclient' (12) hanya tersedia dalam mode Interaktif."; exit 1
                ;;
            *)
                # Semua modul lain membutuhkan --target
                if [[ -z "$TARGET" ]]; then log_error "Modul '$MODULE' membutuhkan --target <target>"; show_usage; exit 1; fi
                ;;
        esac

        if [[ -z "$OUTPUT_FILE" ]]; then
            if [[ "$OUTPUT_FORMAT" == "json" ]]; then OUTPUT_FILE="/dev/stdout"; else OUTPUT_FILE="kinfo_${MODULE}_$(date +%s).txt"; fi
        fi
        log_debug "Output File: $OUTPUT_FILE"
        export TARGET; export WORDLIST; export FTP_LIST; export JUDI_LIST; export OUTPUT_FILE
        export OUTPUT_FORMAT; export PARALLEL_JOBS; export RATE_LIMIT; export KINFO_USER_AGENT; export DORK_UA
        case "$MODULE" in
            subdomain) run_module_subdomain ;;
            direnum) run_module_direnum ;;
            ftpbrute) run_module_ftpbrute ;;
            judi) run_module_judi ;;
            reverseip) run_module_reverseip ;;
            extract) run_module_extract ;;
            webscan) run_module_webscan ;;
            filescan) run_module_filescan ;;
            envscan) run_module_envscan ;;
            wpcheck) run_module_wpcheck ;;
            zoneh) run_module_zoneh ;;
            localps) run_module_local_ps ;;
            localnet) run_module_local_net ;;
            localusers) run_module_local_users ;;
            *) log_error "Modul tidak dikenal: '$MODULE'"; show_usage; exit 1 ;;
        esac
        log_info "Eksekusi selesai."
    else
        main_interactive
    fi
}
main "$@"
