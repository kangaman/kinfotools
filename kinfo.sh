#!/bin/bash

# KINFO - Incident Response & Pentest Toolkit
# Version: 2.5 (Refactored, Expanded Module 9)
# Original: https://jejakintel.t.me/
# Refactor: Gemini (dengan paralelisasi, mode non-interaktif, JSON, logging)
# Updated: 5 November 2025

# --- KONFIGURASI GLOBAL ---
VERSION="2.5"
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
    for cmd in jq nslookup nc ftp whois; do
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
    echo "  Dibutuhkan: --module <nama_modul> --target <target>"
    echo ""
    echo "MODULES:"
    echo "  subdomain       : [1] Enhanced Subdomain Finder"
    echo "  direnum         : [2] Directory/File Enumeration"
    echo "  ftpbrute        : [3] FTP Bruteforce"
    echo "  judi            : [4] Judi Online Finder"
    echo "  reverseip       : [5] Reverse IP Lookup"
    echo "  extract         : [6] Extract Domain & Auto Add HTTPS"
    echo "  webscan         : [7] Webshell Finder [DirScan]"
    echo "  filescan        : [8] Webshell Finder [File Enumeration] (Target adalah path lokal)"
    echo "  envscan         : [9] ENV & Debug Method Scanner"
    echo "  wpcheck         : [10] WordPress Registration Finder"
    echo "  zoneh           : [11] Grab Domain from Zone-H (Target adalah nama notifier)"
    echo "  ftpclient       : [12] Mini Shell FTP Client (Hanya mode Interaktif)"
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

# Helper untuk nslookup
resolve_subdomain() {
    local subdomain="$1"
    if nslookup "$subdomain" >/dev/null 2>&1; then
        echo "$subdomain"
    fi
}
export -f resolve_subdomain

# Helper untuk cek HTTP/HTTPS
check_subdomain_http() {
    local subdomain="$1"
    local result_file="$2"
    local user_agent="$3"
    
    for proto in "https" "http"; do
        local url="$proto://$subdomain"
        local status_code
        status_code=$(curl -sL -I -o /dev/null -w "%{http_code}" --max-time 5 "$url" -A "$user_agent")
        
        # Cek 2xx, 3xx, 401, 403
        if [[ "$status_code" =~ ^(2|3|401|403) ]]; then
            jq -n --arg url "$url" --arg status "$status_code" \
                '{"url": $url, "status": $status_code}' >> "$result_file"
            break
        fi
    done
}
export -f check_subdomain_http

run_module_subdomain() {
    log_info "Memulai Enhanced Subdomain Finder..."
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan. Gunakan --target <domain>"; return 1; fi

    local sanitized_target
    sanitized_target=$(echo "$TARGET" | sed -E 's~^https?://~~' | sed -E 's/^www\.//' | cut -d'/' -f1)
    log_debug "Input asli '$TARGET' disanitasi menjadi '$sanitized_target'"
    if [[ -z "$sanitized_target" ]]; then log_error "Input target tidak valid setelah sanitasi."; return 1; fi

    if ! command -v jq &>/dev/null; then log_warn "Perintah 'jq' tidak ditemukan."; fi
    if ! command -v nslookup &>/dev/null; then log_warn "Perintah 'nslookup' tidak ditemukan."; fi

    local temp_file_all; temp_file_all=$(add_temp_file)
    log_debug "Menggunakan file temp: $temp_file_all"

    # --- Langkah 1: Kumpulkan dari API (Gunakan $sanitized_target) ---
    log_info "[*] Mengecek crt.sh..."
    curl -s "https://crt.sh/?q=%.${sanitized_target}&output=json" -A "$KINFO_USER_AGENT" | jq -r '.[].name_value' 2>/dev/null | grep -Po '(\S+\.)+\S+' >> "$temp_file_all"
    log_info "[*] Mengecek bufferover.run..."
    curl -s "https://dns.bufferover.run/dns?q=.${sanitized_target}" -A "$KINFO_USER_AGENT" 2>/dev/null | jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | cut -d',' -f2 >> "$temp_file_all"
    log_info "[*] Mengecek alienvault.com..."
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${sanitized_target}/passive_dns" -A "$KINFO_USER_AGENT" 2>/dev/null | jq -r '.passive_dns[].hostname' 2>/dev/null | grep "\.${sanitized_target}$" >> "$temp_file_all"
    log_info "[*] Mengecek threatcrowd.org..."
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${sanitized_target}" -A "$KINFO_USER_AGENT" 2>/dev/null | jq -r '.subdomains[]' 2>/dev/null >> "$temp_file_all"

    sort -u "$temp_file_all" -o "$temp_file_all"
    
    cp "$temp_file_all" "/tmp/kinfo_last_subdomains_${sanitized_target}.txt"
    log_debug "Menyimpan daftar subdomain mentah ke /tmp/kinfo_last_subdomains_${sanitized_target}.txt"
    
    local total; total=$(wc -l < "$temp_file_all")
    log_info "[+] Ditemukan total $total subdomain unik (dari API)."
    
    # --- Langkah 2: DNS Resolution (Cek DNS Live) ---
    log_info "[*] Melakukan DNS resolution paralel (Proses: $PARALLEL_JOBS)..."
    local temp_file_dns_live; temp_file_dns_live=$(add_temp_file)
    cat "$temp_file_all" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "resolve_subdomain {}" >> "$temp_file_dns_live"
    local dns_live_count; dns_live_count=$(wc -l < "$temp_file_dns_live")
    log_info "[+] Ditemukan $dns_live_count subdomain yang DNS LIVE."

    # --- Langkah 3: HTTP Check (Cek HTTP Live) ---
    log_info "[*] Melakukan HTTP check paralel pada subdomain DNS Live (Proses: $PARALLEL_JOBS)..."
    local temp_file_http_live; temp_file_http_live=$(add_temp_file)
    export KINFO_USER_AGENT
    export temp_file_http_live
    
    cat "$temp_file_dns_live" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_subdomain_http \"{}\" \"$temp_file_http_live\" \"$KINFO_USER_AGENT\""
    
    local http_live_count; http_live_count=$(wc -l < "$temp_file_http_live")
    log_info "[+] Ditemukan $http_live_count subdomain yang HTTP LIVE (merespon di port 80/443)."

    # --- Handle Output ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        local json_output
        json_output=$(jq -n \
            --arg target "$sanitized_target" \
            --arg total_api "$total" \
            --arg total_dns_live "$dns_live_count" \
            --arg total_http_live "$http_live_count" \
            --argjson all_api "$(jq -Rsc 'split("\n") | map(select(length > 0))' "$temp_file_all")" \
            --argjson dns_live "$(jq -Rsc 'split("\n") | map(select(length > 0))' "$temp_file_dns_live")" \
            --argjson http_live "$(jq -s '.' "$temp_file_http_live")" \
            '{target: $target, total_found_api: $total_api, total_dns_live: $total_dns_live, total_http_live: $total_http_live, all_subdomains_api: $all_api, dns_live_subdomains: $dns_live, http_live_subdomains: $http_live}')
        echo "$json_output"
    else
        local text_output
        text_output=$(cat <<EOF
KINFO Enhanced Subdomain Finder Results
Target: $sanitized_target
Scan Time: $(date)
Total Found (API): $total | DNS Live: $dns_live_count | HTTP Live: $http_live_count
====================================
ALL SUBDOMAINS (Total: $total):
$(cat "$temp_file_all")

DNS LIVE SUBDOMAINS (Total: $dns_live_count):
$(cat "$temp_file_dns_live")

HTTP LIVE SUBDOMAINS (Total: $http_live_count):
$(cat "$temp_file_http_live" | jq -r '"[\(.status)] \(.url)"')
EOF
)
        echo "$text_output"
    fi | tee "$OUTPUT_FILE" > /dev/null
    
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    log_info "Pencarian subdomain selesai."
}


# --- [MODUL 2] DIRECTORY/FILE ENUMERATION ---
check_url_path() {
    local base_url="$1"
    local path="$2"
    local rate_limit="$3"
    local user_agent="$4"
    local result_file="$5"
    local full_url="${base_url}/${path}"
    sleep "$rate_limit"
    local response; response=$(curl -sIL "$full_url" --connect-timeout 3 --max-time 5 -H "User-Agent: $user_agent" 2>/dev/null)
    local status_line; status_line=$(echo "$response" | head -n 1)
    local status_code; status_code=$(echo "$status_line" | grep -oE '[0-9]{3}' | head -1)
    if [[ "$status_code" =~ ^(200|301|302|401|403)$ ]]; then
        local size="N/A"
        if [[ "$status_code" == "200" ]]; then
            size=$(curl -s "$full_url" --connect-timeout 3 --max-time 5 -H "User-Agent: $user_agent" 2>/dev/null | wc -c)
        fi
        jq -n --arg url "$full_url" --arg status "$status_code" --arg size "$size" \
            '{"url": $url, "status": $status, "size": $size}' >> "$result_file"
    fi
}
export -f check_url_path
run_module_direnum() {
    log_info "Memulai Directory/File Enumeration..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan. Gunakan --target <url>"; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    if [[ ! -f "$WORDLIST" ]]; then log_error "Wordlist tidak ditemukan di: $WORDLIST"; return 1; fi
    local total_lines; total_lines=$(grep -vE "^\s*#|^\s*$" "$WORDLIST" | wc -l)
    log_info "[*] Memulai enumerasi pada $TARGET menggunakan $WORDLIST ($total_lines entri)"
    log_info "[*] Paralel: $PARALLEL_JOBS | Rate Limit: $RATE_LIMIT detik"
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export temp_json_lines
    grep -vE "^\s*#|^\s*$" "$WORDLIST" | \
    xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$temp_json_lines\""
    local found_count; found_count=$(wc -l < "$temp_json_lines")
    log_info "[+] Enumerasi selesai. Ditemukan $found_count item menarik."
    if [[ "$found_count" -eq 0 ]]; then log_warn "Tidak ada item yang ditemukan."; return 0; fi
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -s '.' "$temp_json_lines")
    else
        output_data=$(cat <<EOF
Directory/File Enumeration Results
Target: $TARGET
Wordlist: $WORDLIST
Scan Time: $(date)
==================================
$(cat "$temp_json_lines" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort)
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 3] FTP BRUTEFORCE ---
check_ftp_cred() {
    local ftp_host="$1"
    local ftp_port="$2"
    local username="$3"
    local password="$4"
    local result_file="$5"
    local login_result; login_result=$(echo -e "user $username $password\nquit" | ftp -n "$ftp_host" "$ftp_port" 2>&1)
    if echo "$login_result" | grep -qi "login successful\|230\|welcome"; then
        jq -n --arg host "$ftp_host" --arg port "$ftp_port" --arg user "$username" --arg pass "$password" \
            '{"host": $host, "port": $port, "username": $user, "password": $pass}' >> "$result_file"
    fi
}
export -f check_ftp_cred
run_module_ftpbrute() {
    log_info "Memulai FTP Bruteforce..."
    local ftp_host; ftp_host=$(echo "$TARGET" | cut -d':' -f1)
    local ftp_port; ftp_port=$(echo "$TARGET" | cut -d':' -f2)
    if [[ "$ftp_host" == "$ftp_port" ]]; then ftp_port=21; fi
    if [[ -z "$ftp_host" ]]; then log_error "Target host diperlukan."; return 1; fi
    if ! command -v ftp &>/dev/null; then log_error "Perintah 'ftp' tidak ditemukan."; return 1; fi
    if [[ ! -f "$FTP_LIST" ]]; then log_error "Wordlist FTP tidak ditemukan di: $FTP_LIST"; return 1; fi
    if ! nc -z "$ftp_host" "$ftp_port" 2>/dev/null; then log_error "Tidak dapat terhubung ke $ftp_host:$ftp_port"; return 1; fi
    log_info "[*] Terhubung ke $ftp_host:$ftp_port. Memulai brute force (Paralel: $PARALLEL_JOBS)..."
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    export ftp_host; export ftp_port; export temp_json_lines
    grep -vE "^\s*#|^\s*$" "$FTP_LIST" | grep ':' | \
    xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_ftp_cred \"$ftp_host\" \"$ftp_port\" \"$(echo {} | cut -d':' -f1)\" \"$(echo {} | cut -d':' -f2-)\" \"$temp_json_lines\""
    local found_count; found_count=$(wc -l < "$temp_json_lines")
    log_info "[+] Bruteforce selesai."
    if [[ "$found_count" -eq 0 ]]; then log_warn "Tidak ada kredensial valid yang ditemukan."; return 0; fi
    log_result "[SUCCESS] Ditemukan $found_count kredensial valid!"
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -s '.' "$temp_json_lines")
    else
        output_data=$(cat "$temp_json_lines" | jq -r '"[+] HOST: \(.host):\(.port) - USER: \(.username) - PASS: \(.password)"')
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 4] JUDI ONLINE FINDER ---
check_judi_homepage() {
    local url="$1"
    local keyword_list_file="$2"
    local result_file="$3"
    local content; content=$(curl -sL "$url" --connect-timeout 5 --max-time 10 -H "User-Agent: $KINFO_USER_AGENT" 2>/dev/null)
    if [[ -z "$content" ]]; then return; fi
    while IFS= read -r keyword; do
        if [[ -z "$keyword" || "$keyword" == \#* ]]; then continue; fi
        if echo "$content" | grep -iq "$keyword"; then
            log_debug "Direct scan match: $keyword di $url"
            jq -n --arg method "direct_scan" --arg url "$url" --arg keyword "$keyword" \
                '{"method": $method, "url": $url, "keyword": $keyword}' >> "$result_file"
            break
        fi
    done < "$keyword_list_file"
}
export -f check_judi_homepage
check_judi_bing() {
    local target_domain="$1"
    local keyword="$2"
    local result_file="$3"
    local dork_ua="$4"
    local query; query=$(printf "site:%s \"%s\"" "$target_domain" "$keyword" | jq -sRr @uri)
    local bing_url="https://www.bing.com/search?q=$query"
    local response; response=$(curl -sL --max-time 10 -A "$dork_ua" "$bing_url")
    if echo "$response" | grep -iq "$target_domain" && ! echo "$response" | grep -iqE "(Tidak ada hasil untuk|No results for)"; then
        log_debug "Bing dork match for keyword: $keyword"
        jq -n --arg method "bing_dork" --arg url "$bing_url" --arg keyword "$keyword" \
            '{"method": $method, "url": "https://www.bing.com/search?q=site:'$target_domain'+\"'${keyword}'\"", "keyword": $keyword}' >> "$result_file"
    fi
}
export -f check_judi_bing
run_module_judi() {
    log_info "Memulai Judi Online Finder..."
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan. Gunakan --target <domain>"; return 1; fi
    local sanitized_target
    sanitized_target=$(echo "$TARGET" | sed -E 's~^https?://~~' | sed -E 's/^www\.//' | cut -d'/' -f1)
    log_debug "Input asli '$TARGET' disanitasi menjadi '$sanitized_target'"
    if [[ -z "$sanitized_target" ]]; then log_error "Input target tidak valid setelah sanitasi."; return 1; fi
    if [[ ! -f "$JUDI_LIST" ]]; then log_error "Wordlist Judi tidak ditemukan di: $JUDI_LIST"; return 1; fi
    local keyword_count; keyword_count=$(grep -vE "^\s*#|^\s*$" "$JUDI_LIST" | wc -l)
    log_info "[*] Menggunakan $JUDI_LIST ($keyword_count keywords)"
    local subdomain_file="/tmp/kinfo_last_subdomains_${sanitized_target}.txt"
    local targets_to_scan=("$sanitized_target")
    if [[ -f "$subdomain_file" ]]; then
        log_info "[*] Menggunakan daftar subdomain dari scan Modul 1 ($subdomain_file)"
        mapfile -t-O "${#targets_to_scan[@]}" targets_to_scan < <(grep -vE "^\s*#|^\s*$" "$subdomain_file")
    else
        log_warn "[*] Tidak ada daftar subdomain. Hanya memindai domain utama."
    fi
    local total_targets=${#targets_to_scan[@]}
    log_info "[*] Total $total_targets domain/subdomain akan diperiksa..."
    local temp_urls_to_check; temp_urls_to_check=$(add_temp_file)
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    log_info "[*] Memulai Metode 1: Direct Scan (Homepage) (Paralel: $PARALLEL_JOBS)..."
    for target in "${targets_to_scan[@]}"; do
        echo "https://$target" >> "$temp_urls_to_check"
        echo "http://$target" >> "$temp_urls_to_check"
    done
    export JUDI_LIST; export KINFO_USER_AGENT; export temp_json_lines
    cat "$temp_urls_to_check" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_judi_homepage \"{}\" \"$JUDI_LIST\" \"$temp_json_lines\""
    log_info "[*] Memulai Metode 2: Bing Dork Scan (Mencari di sub-halaman)..."
    export DORK_UA
    grep -vE "^\s*#|^\s*$" "$JUDI_LIST" | \
    xargs -P 5 -I {} \
        bash -c "check_judi_bing \"$sanitized_target\" \"{}\" \"$temp_json_lines\" \"$DORK_UA\""
    local found_count; found_count=$(wc -l < "$temp_json_lines")
    log_info "[+] Pemindaian selesai."
    if [[ "$found_count" -eq 0 ]]; then log_warn "Tidak ada konten judi yang terdeteksi."; return 0; fi
    log_result "[FOUND] Ditemukan $found_count indikasi konten judi!"
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -s '.' "$temp_json_lines")
    else
        output_data=$(cat <<EOF
Judi Online Finder Results
Domain: $sanitized_target
Scan Time: $(date)
==================================
$(cat "$temp_json_lines" | jq -r '"[+] (\(.method)) \(.url) (Keyword: \(.keyword))"')
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 5] REVERSE IP LOOKUP ---
run_module_reverseip() {
    log_info "Memulai Reverse IP Lookup..."
    if [[ -z "$TARGET" ]]; then log_error "Target IP Address diperlukan."; return 1; fi
    local ipaddr="$TARGET"
    if [[ ! $ipaddr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then log_error "Format IP tidak valid: $ipaddr"; return 1; fi
    log_info "[*] Melakukan reverse IP lookup untuk $ipaddr..."
    local viewdns_url="https://viewdns.info/reverseip/?host=$ipaddr&t=1"
    local response; response=$(curl -s "$viewdns_url" -H "User-Agent: $KINFO_USER_AGENT")
    local temp_domains; temp_domains=$(add_temp_file)
    echo "$response" | grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' | grep -v "$ipaddr" | sort -u > "$temp_domains"
    local domains; mapfile -t domains < "$temp_domains"; local total=${#domains[@]}
    if [[ $total -eq 0 ]]; then
        log_warn "[*] viewdns.info tidak mengembalikan hasil. Mencoba 'whois'..."
        if command -v whois &>/dev/null; then
            local whois_result; whois_result=$(whois "$ipaddr" 2>/dev/null | grep -i "domain\|netname")
            if [[ -n "$whois_result" ]]; then
                log_warn "[!] Informasi terbatas dari WHOIS:"; echo "$whois_result" > "$temp_domains"
            else
                log_error "[!] Tidak ada domain ditemukan untuk IP $ipaddr"; return 1
            fi
        else
            log_error "[!] 'whois' tidak terinstall. Tidak dapat melanjutkan."; return 1
        fi
    fi
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -n --arg ip "$ipaddr" --argjson domains "$(jq -Rsc 'split("\n") | map(select(length > 0))' "$temp_domains")" \
            '{"ip": $ip, "domains": $domains}')
    else
        output_data=$(cat <<EOF
Reverse IP Lookup Results
Target IP: $ipaddr
Scan Time: $(date)
==================================
Domains:
$(cat "$temp_domains")
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 6] EXTRACT DOMAIN & CHECK HEADERS ---
run_module_extract() {
    log_info "Memulai Extract Domain & Auto Add HTTPS..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    local url="$TARGET"
    local extracted; extracted=$(echo "$url" | sed -E 's~^https?://~~' | sed -E 's/^www\.//' | cut -d'/' -f1)
    if [[ "$url" != *"//"* ]]; then extracted=$(echo "$url" | cut -d'/' -f1 | sed 's/^www\.//'); fi
    local full_url="https://$extracted"
    log_info "[*] URL Asli: $url"; log_info "[*] Ekstrak Domain: $extracted"; log_info "[*] HTTPS URL: $full_url"
    local temp_headers; temp_headers=$(add_temp_file)
    local status_code; status_code=$(curl -sI "$full_url" --max-time 5 -o "$temp_headers" -w "%{http_code}" -H "User-Agent: $KINFO_USER_AGENT")
    local sec_headers=(); mapfile -t sec_headers < <(grep -i "x-frame-options\|content-security-policy\|strict-transport-security" "$temp_headers")
    log_info "[*] Status Kode: $status_code"
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -n --arg original "$url" --arg domain "$extracted" --arg https_url "$full_url" --arg status "$status_code" \
            --argjson headers "$(printf "%s\n" "${sec_headers[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" \
            '{"original_url": $original, "extracted_domain": $domain, "https_url": $https_url, "status_code": $status, "security_headers": $headers}')
    else
        output_data=$(cat <<EOF
Extract Domain & Header Check
Original: $url
Extracted: $extracted
HTTPS URL: $full_url
==================================
Status Code: $status_code
Security Headers:
$(printf "%s\n" "${sec_headers[@]}" | sed 's/^/  /')
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 7] WEBSHELL FINDER [DIRSCAN] ---
run_module_webscan() {
    log_info "Memulai Webshell Finder [Directory Scan]..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')
    local webshell_paths=("shell.php" "backdoor.php" "cmd.php" "wso.php" "up.php" "upload.php" "sh.php" "phpinfo.php" "info.php" "test.php" "1.php" "wordpress.php" "IndoXploit.php" "b374k.php" "adminer.php" "phpMyAdmin/index.php" "pma/index.php" "mysql.php" "wp-config.php" "configuration.php" "settings.php" "web.config" "shell.jsp" "cmd.asp" "shell.aspx" ".git/config" "composer.json" "package.json" "install.php" "admin.php" "login.php" "wp-login.php" "administrator/index.php" "user/login" "dashboard" "panel" "control" "manager" "adminpanel" "cpanel" "webmail" "upload" "uploads" "file" "files" "log" "logs" "temp" "tmp" "cache" "backup" "backups" "dev" "test" "api-docs" "swagger" "docs" "status" "health" "server-status" "server-info")
    local total_lines=${#webshell_paths[@]}
    log_info "[*] Memulai pemindaian pada $TARGET ($total_lines path internal, Paralel: $PARALLEL_JOBS)..."
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    local temp_path_list; temp_path_list=$(add_temp_file)
    printf "%s\n" "${webshell_paths[@]}" > "$temp_path_list"
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export temp_json_lines
    cat "$temp_path_list" | \
    xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$temp_json_lines\""
    local found_count; found_count=$(wc -l < "$temp_json_lines")
    log_info "[+] Pemindaian selesai. Ditemukan $found_count item menarik."
    if [[ "$found_count" -eq 0 ]]; then log_warn "Tidak ada item yang ditemukan."; return 0; fi
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -s '.' "$temp_json_lines")
    else
        output_data=$(cat <<EOF
Webshell/Dir Scan Results
Target: $TARGET
Scan Time: $(date)
==================================
$(cat "$temp_json_lines" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort)
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 8] WEBSHELL FINDER [FILE ENUM] ---
check_file_suspicious() {
    local file="$1"
    local keyword_regex="$2"
    local result_file="$3"
    local file_size_b; file_size_b=$(stat -c%s "$file" 2>/dev/null || echo 0)
    if [[ "$file_size_b" -gt 1000000 ]]; then return; fi # Skip file > 1MB
    local matched_keyword; matched_keyword=$(grep -E -o "$keyword_regex" "$file" 2>/dev/null | head -1)
    if [[ -n "$matched_keyword" ]]; then
        local size; size=$(du -h "$file" 2>/dev/null | cut -f1)
        local modified; modified=$(stat -c %y "$file" 2>/dev/null | cut -d'.' -f1)
        jq -n --arg file "$file" --arg size "$size" --arg modified "$modified" --arg keyword "$matched_keyword" \
            '{"file": $file, "size": $size, "modified": $modified, "matched_keyword": $keyword}' >> "$result_file"
    fi
}
export -f check_file_suspicious
run_module_filescan() {
    log_info "Memulai Webshell Finder [File Enumeration]..."
    if [[ -z "$TARGET" ]]; then log_error "Target path direktori lokal diperlukan."; return 1; fi
    local scan_dir="$TARGET"
    if [[ ! -d "$scan_dir" ]]; then log_error "Direktori tidak ada: $scan_dir"; return 1; fi
    local suspicious_keywords=("eval" "base64_decode" "gzinflate" "exec" "system" "passthru" "shell_exec" "assert" "preg_replace.*\/e" "create_function" "call_user_func" "array_map" "ob_start" "error_reporting\(0\)" "\$_(POST|GET|REQUEST|COOKIE|SERVER)" "file_put_contents" "fwrite" "fopen" "curl_exec" "file_get_contents" "include" "require" "chr\(" "ord\(" "hex2bin" "str_rot13" "strrev" "GLOBALS" "FLAG" "password" "token" "key" "secret")
    local keyword_regex; keyword_regex=$(printf "%s|" "${suspicious_keywords[@]}"); keyword_regex="${keyword_regex%|}"
    log_info "[*] Memindai file mencurigakan di: $scan_dir (Paralel: $PARALLEL_JOBS)..."
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    export keyword_regex; export temp_json_lines
    find "$scan_dir" -type f \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php3" -o -iname "*.php4" -o -iname "*.php5" -o -iname "*.inc" -o -iname "*.asp" -o -iname "*.aspx" -o -iname "*.jsp" \) -print0 2>/dev/null | \
    xargs -0 -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_file_suspicious \"{}\" \"$keyword_regex\" \"$temp_json_lines\""
    local found_count; found_count=$(wc -l < "$temp_json_lines")
    log_info "[+] Pemindaian selesai. Ditemukan $found_count file mencurigakan."
    if [[ "$found_count" -eq 0 ]]; then log_warn "Tidak ada file mencurigakan yang ditemukan."; return 0; fi
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -s '.' "$temp_json_lines")
    else
        output_data=$(cat <<EOF
Webshell File Enumeration Results
Directory: $scan_dir
Scan Time: $(date)
==================================
$(cat "$temp_json_lines" | jq -r '"[!] \(.file) (Size: \(.size), Keyword: \(.keyword))"')
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 9] ENV & DEBUG METHOD SCANNER ---
run_module_envscan() {
    log_info "Memulai ENV & Debug Method Scanner..."
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::')

    # *** DIPERBARUI v2.5: Daftar diperluas dengan subfolder ***
    local env_files=(
        # ENV & Config
        ".env" ".env.backup" ".env.local" ".env.example" "config/.env"
        "configuration.php" "settings.php" "database.php" "db.php"
        "wp-config.php" "config.php" "config/database.yml" ".htpasswd" ".htaccess" "web.config"
        # Debug
        "debug.php" "phpinfo.php" "info.php" "test.php" "status" "health" "metrics"
        "actuator" "healthz" "readyz" "swagger" "api-docs" "v1/swagger" "docs"
        "robots.txt" "sitemap.xml" "server-status" "server-info"
        "composer.json" "package.json" "Dockerfile" "docker-compose.yml" "requirements.txt"

        # --- Penambahan .sql dan backup (Permintaan User) ---
        # Root level
        "backup.sql" "db.sql" "database.sql" "data.sql" "dump.sql" "site.sql"
        "backup.tar.gz" "backup.zip" "backup.rar" "site.tar.gz" "site.zip"
        "database.zip" "database.tar.gz" "db.zip" "db.tar.gz" "www.zip" "www.tar.gz"
        
        # --- Penambahan Subfolder (Permintaan User) ---
        # /backup/
        "backup/backup.sql" "backup/db.sql" "backup/dump.sql"
        "backup/backup.zip" "backup/site.zip" "backup/db.zip" "backup/backup.tar.gz"
        # /backups/
        "backups/backup.sql" "backups/db.sql" "backups/dump.sql"
        "backups/backup.zip" "backups/site.zip" "backups/db.zip" "backups/backup.tar.gz"
        # /sql/
        "sql/backup.sql" "sql/db.sql" "sql/dump.sql" "sql/database.sql"
        "sql/backup.zip" "sql/db.zip"
        # /files/
        "files/backup.sql" "files/db.sql" "files/dump.sql"
        "files/backup.zip" "files/site.zip"
        # /db/
        "db/dump.sql" "db/db.sql" "db/database.sql"
        "db/backup.zip" "db/db.zip"
        # /uploads/
        "uploads/backup.sql" "uploads/db.sql" "uploads/dump.sql"
        "uploads/backup.zip" "uploads/site.zip"
        # /_backup/
        "_backup/backup.sql" "_backup/db.sql" "_backup/dump.sql"
        "_backup/backup.zip" "_backup/site.zip"
        # /_db/
        "_db/dump.sql" "_db/db.sql"
    )

    local total_lines=${#env_files[@]}
    log_info "[*] Memulai pemindaian pada $TARGET ($total_lines path internal, Paralel: $PARALLEL_JOBS)..."
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    local temp_path_list; temp_path_list=$(add_temp_file)
    printf "%s\n" "${env_files[@]}" > "$temp_path_list"
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export temp_json_lines
    cat "$temp_path_list" | \
    xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$temp_json_lines\""
    local found_count; found_count=$(wc -l < "$temp_json_lines")
    log_info "[+] Pemindaian selesai. Ditemukan $found_count item menarik."
    if [[ "$found_count" -eq 0 ]]; then log_warn "Tidak ada item yang ditemukan."; return 0; fi
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -s '.' "$temp_json_lines")
    else
        output_data=$(cat <<EOF
ENV & Debug Scan Results
Target: $TARGET
Scan Time: $(date)
==================================
$(cat "$temp_json_lines" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort)
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 10] WORDPRESS REGISTRATION FINDER ---
run_module_wpcheck() {
    log_info "Memulai WordPress Registration Finder..."
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    local sanitized_target
    sanitized_target=$(echo "$TARGET" | sed -E 's~^https?://~~' | sed -E 's/^www\.//' | cut -d'/' -f1)
    
    local wp_url="https://$sanitized_target"
    log_info "[*] Memeriksa situs WordPress di $wp_url"
    local response; response=$(curl -sIL "$wp_url" --connect-timeout 3 --max-time 5 -H "User-Agent: $KINFO_USER_AGENT" 2>/dev/null)
    if ! echo "$response" | grep -qi "wp-content\|wordpress"; then
        log_warn "[!] Ini tampaknya bukan situs WordPress. Tetap melanjutkan..."
    fi
    local reg_paths=("wp-login.php?action=register" "wp-signup.php" "register" "signup" "create-account" "registration")
    local temp_json_lines; temp_json_lines=$(add_temp_file)
    local temp_path_list; temp_path_list=$(add_temp_file)
    printf "%s\n" "${reg_paths[@]}" > "$temp_path_list"
    export TARGET="$wp_url"; export RATE_LIMIT=0; export KINFO_USER_AGENT; export temp_json_lines
    cat "$temp_path_list" | \
    xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_url_path \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$temp_json_lines\""
    local found_url=""; local found_status=""
    while IFS= read -r line; do
        if [[ $(echo "$line" | jq -r '.status') == "200" ]]; then
            found_url=$(echo "$line" | jq -r '.url'); found_status="200"; break
        fi
    done < "$temp_json_lines"
    local result_details=""
    if [[ -n "$found_url" ]]; then
        log_result "[+] Ditemukan halaman registrasi potensial: $found_url"
        result_details="Halaman registrasi ditemukan di $found_url"
    else
        log_warn "[-] Tidak ada halaman registrasi (200 OK) yang ditemukan."
        result_details="Tidak ada halaman registrasi umum (200 OK) yang ditemukan."
    fi
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -n --arg domain "$sanitized_target" --arg found_url "$found_url" --arg details "$result_details" \
            '{"domain": $domain, "registration_page_found": (if $found_url != "" then true else false end), "url": $found_url, "details": $details}')
    else
        output_data=$(cat <<EOF
WordPress Registration Finder Results
Target: $sanitized_target
Scan Time: $(date)
==================================
Status: $result_details
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 11] GRAB DOMAIN DARI ZONE-H ---
run_module_zoneh() {
    log_info "Memulai Grab Domain dari Zone-H..."
    if [[ -z "$TARGET" ]]; then log_error "Nama Notifier diperlukan."; return 1; fi
    local notifier="$TARGET"; local zoneh_url="http://www.zone-h.org/archive/notifier=$notifier"
    log_info "[*] Mengambil data dari Zone-H untuk notifier: $notifier"
    local response; response=$(curl -s "$zoneh_url" --connect-timeout 10 -H "User-Agent: $KINFO_USER_AGENT" 2>/dev/null)
    if [[ -z "$response" ]]; then log_error "Gagal mengambil data dari Zone-H"; return 1; fi
    local temp_domains; temp_domains=$(add_temp_file)
    echo "$response" | grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' | grep -v "Domain" | sort -u > "$temp_domains"
    local domain_count; domain_count=$(wc -l < "$temp_domains")
    if [[ $domain_count -eq 0 ]]; then log_warn "Tidak ada domain ditemukan untuk notifier ini."; return 0; fi
    log_info "[+] Ditemukan $domain_count domain."
    local output_data
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        output_data=$(jq -n --arg notifier "$notifier" --argjson domains "$(jq -Rsc 'split("\n") | map(select(length > 0))' "$temp_domains")" \
            '{"notifier": $notifier, "domains": $domains}')
    else
        output_data=$(cat <<EOF
Zone-H Grabber Results
Notifier: $notifier
Scan Time: $(date)
======================
$(cat "$temp_domains")
EOF
)
    fi
    echo "$output_data" | tee "$OUTPUT_FILE" > /dev/null
    if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
}

# --- [MODUL 12] MINI SHELL FTP CLIENT (INTERAKTIF SAJA) ---
mini_ftp_client() {
    log_info "Memulai Mini Shell FTP Client..."
    local ftp_host ftp_port ftp_user ftp_pass
    read -p "Enter FTP host: " ftp_host
    read -p "Enter FTP port (default 21): " ftp_port
    read -p "Enter username: " ftp_user
    read -sp "Enter password: " ftp_pass; echo ""
    if [[ -z "$ftp_host" || -z "$ftp_user" ]]; then log_error "Host dan username tidak boleh kosong!"; return 1; fi
    if [[ -z "$ftp_port" ]]; then ftp_port=21; fi
    if ! command -v ftp &>/dev/null; then log_error "FTP client tidak ditemukan!"; return 1; fi
    echo ""; echo "FTP Client Commands:"; echo "  ls, cd, pwd, get, put, mkdir, rmdir, delete, rename"; echo "  binary, ascii, passive, exit"; echo "=============================="
    ftp -inv "$ftp_host" "$ftp_port" <<EOF
user $ftp_user $ftp_pass
passive
binary
prompt
!echo 'Koneksi berhasil. Ketik ''bye'' atau ''exit'' untuk keluar.'
EOF
    log_info "Sesi FTP ditutup."
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
        echo " [1] Enhanced Subdomain Finder"; echo " [2] Directory/File Enumeration (wordlist.txt)"
        echo " [3] FTP Bruteforce (FTP/FTPS) (ftpbrute.txt)"; echo " [4] Judi Online Finder (judilist.txt)"
        echo " [5] Reverse IP Lookup"; echo " [6] Extract Domain [Auto Add HTTPS]"
        echo " [7] Webshell Finder [DirScan]"; echo " [8] Webshell Finder [File Enumeration]"
        echo " [9] ENV & Debug Method Scanner"; echo " [10] WordPress Registration Finder"
        echo " [11] Grab Domain from Zone-H"; echo " [12] Mini Shell FTP Client"; echo " [13] Exit"; echo ""
        read -p "Select Option (1-13): " pilihan
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
            13) break ;;
            *) log_error "Opsi tidak valid. Silakan pilih 1-13"; sleep 2 ;;
        esac
        if [[ "$pilihan" -ne 13 ]]; then echo ""; read -p "Tekan Enter untuk melanjutkan..."; fi
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
        if [[ -z "$MODULE" || -z "$TARGET" ]]; then log_error "Mode non-interaktif membutuhkan --module dan --target"; show_usage; exit 1; fi
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
            ftpclient) log_error "Modul 'ftpclient' (12) hanya tersedia dalam mode Interaktif."; exit 1 ;;
            *) log_error "Modul tidak dikenal: '$MODULE'"; show_usage; exit 1 ;;
        esac
        log_info "Eksekusi selesai."
    else
        main_interactive
    fi
}
main "$@"
