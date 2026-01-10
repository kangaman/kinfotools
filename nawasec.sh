#!/bin/bash

# NawaSec Framework - Incident Response & Pentest Toolkit
# Versi: 2.0 (Ultimate Edition)
#
# Hak Cipta (c) 2025 NawaSec Team
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
VERSION="1.1"
KINFO_USER_AGENT="Mozilla/5.0 NawaSec/$VERSION"
DORK_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"

# --- LOKASI SCRIPT & FOLDER OUTPUT ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/results_nawasec"
# *** BARU v1.4: Folder untuk Koleksi IR Penuh ***
IR_DATA_DIR="$OUTPUT_DIR/ir_data"

# --- WARNA (NEON THEME) ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
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

# --- VISUAL & HTML HELPERS ---

# Improved Logging (Hacker Style)
log() {
    local TYPE=$1; local MSG=$2
    local TS=$(date "+%H:%M:%S")
    case $TYPE in
        "INFO") echo -e " ${GREEN}[+]${NC} ${MSG}" ;;
        "WARN") echo -e " ${YELLOW}[!]${NC} ${MSG}" ;;
        "ERR")  echo -e " ${RED}[X]${NC} ${MSG}" ;;
        "RES")  echo -e " ${CYAN}[★]${NC} ${MSG}" ;;
        *)      echo -e " ${BLUE}[?]${NC} ${MSG}" ;;
    esac
    if [[ -n "$LOG_FILE" ]]; then echo "[$TS] [$TYPE] $MSG" >> "$LOG_FILE"; fi
}

draw_box() {
    local msg="$1"; local color="${2:-$CYAN}"
    local len=${#msg}
    local border=$(printf '%*s' "$((len+4))" '' | tr ' ' '═')
    echo -e "${color}"
    echo "╔$border╗"
    echo "║  $msg  ║"
    echo "╚$border╝"
    echo -e "${NC}"
}

generate_html_report() {
    local JSON_FILE="$1"
    local HTML_FILE="${JSON_FILE%.json}.html"
    local TITLE="NawaSec Scan Report"
    
    log "INFO" "Generating HTML Report: $HTML_FILE..."
    
    cat <<EOF > "$HTML_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$TITLE</title>
    <style>
        :root { --bg: #000000; --card: #111; --text: #0f0; --accent: #0ff; --border: #333; }
        body { font-family: 'Courier New', monospace; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; border: 1px solid var(--accent); padding: 20px; box-shadow: 0 0 20px rgba(0, 255, 255, 0.1); }
        header { text-align: center; border-bottom: 2px dashed var(--accent); margin-bottom: 40px; padding-bottom: 20px; }
        h1 { color: var(--accent); text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 10px var(--accent); }
        .card { background: var(--card); border: 1px solid var(--border); padding: 20px; margin-bottom: 20px; }
        h2 { color: #fff; border-left: 4px solid var(--accent); padding-left: 10px; }
        pre { background: #0a0a0a; color: #ccc; padding: 10px; overflow-x: auto; border: 1px solid #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
        th { color: var(--accent); }
        .footer { text-align: center; color: #555; margin-top: 50px; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ NAWASEC PROTOCOL v${VERSION}</h1>
            <div>Target Scan Report | $(date)</div>
        </header>

        <div class="card">
            <h2>> SYSTEM_SUMMARY</h2>
            <div id="summaryContent">Initializing...</div>
        </div>

        <div class="card">
            <h2>> RAW_DATA_DUMP</h2>
            <pre id="rawData"></pre>
        </div>
        
        <script>
            const data = $(cat "$JSON_FILE");
            document.getElementById('rawData').textContent = JSON.stringify(data, null, 2);
            
            let html = '<table class="w-full">';
            for (const [key, value] of Object.entries(data)) {
                if (typeof value !== 'object') {
                    html += \`<tr><th>\${key.toUpperCase()}</th><td>\${value}</td></tr>\`;
                }
            }
            html += '</table>';
            
            html += '<div style="margin-top:20px; display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:15px;">';
            for (const [key, value] of Object.entries(data)) {
                if (Array.isArray(value)) {
                    html += \`<div style="border:1px solid #333; padding:15px; text-align:center;">
                        <div style="font-size:2em; color:var(--accent);">\${value.length}</div>
                        <div style="color:#666;">\${key.toUpperCase()}</div>
                    </div>\`;
                }
            }
            html += '</div>';

            document.getElementById('summaryContent').innerHTML = html;
        </script>
        
        <div class="footer">GENERATED BY NAWASEC FRAMEWORK // SECURE CHANNEL</div>
    </div>
</body>
</html>
EOF
    log "RES" "Report saved: $HTML_FILE"
}

# --- VALIDASI & DEPENDENSI ---
check_dependencies() {
    log_debug "Memeriksa dependensi..."
    local missing_deps=0
    for cmd in curl grep find stat sed sort uniq wc mktemp; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERR" "Dependensi WAJIB tidak ditemukan: $cmd"
            missing_deps=1
        fi
    done
    for cmd in jq nslookup nc ftp whois ps netstat ss last lastlog who file; do
        if ! command -v "$cmd" &>/dev/null; then
            log "WARN" "Dependensi opsional tidak ditemukan: $cmd"
        fi
    done
    if [[ $missing_deps -eq 1 ]]; then
        log "ERR" "Harap install dependensi wajib dan coba lagi."
        exit 1
    fi
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$IR_DATA_DIR"
}

# --- BANNER & BANTUAN ---
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
 ██ █  ▄▀▄  █   █  ▄▀▄  ▄▀▀  ▄▀▀  ▄▀▀ 
 █ ▀█  █▄█  ▀▄ ▄▀  █▄█  ▄██  ██▄  █▄▄ 
 █  █  █ █   ▀▄▀   █ █  ▀▄▄  ▄▄█  ▄▄█ 
EOF
    echo -e "${NC}"
    draw_box "NawaSec Framework v$VERSION [ULTIMATE]" "$GREEN"
    echo "  >> Power & Precision | By: NawaSec Team"
    echo "  >> Output Dir: $OUTPUT_DIR"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}
generate_html_report() {
    local JSON_FILE="$1"
    local HTML_FILE="${JSON_FILE%.json}.html"
    local TITLE="NawaSec Scan Report"
    
    log_info "Generating HTML Report: $HTML_FILE..."
    
    # 1. Baca konten JSON dengan aman ke variabel Bash
    # Escape backslash dan backticks untuk mencegah JS Injection error
    local JSON_CONTENT
    if [[ -f "$JSON_FILE" ]]; then
        JSON_CONTENT=$(cat "$JSON_FILE")
    else
        JSON_CONTENT="{}"
    fi

    # 2. Generate HTML dengan Embedded JS yang lebih pintar
    cat <<EOF > "$HTML_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$TITLE - v$VERSION</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --accent: #38bdf8; --border: #334155; --success: #22c55e; --danger: #ef4444; --warning: #f59e0b; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { text-align: center; padding: 40px 0; border-bottom: 1px solid var(--border); margin-bottom: 40px; }
        h1 { color: var(--accent); font-size: 2.5rem; margin: 0; display: flex; align-items: center; justify-content: center; gap: 15px; }
        .meta { color: #94a3b8; margin-top: 10px; font-size: 0.9rem; }
        .card { background: var(--card); border-radius: 12px; padding: 25px; margin-bottom: 25px; border: 1px solid var(--border); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        h2 { color: var(--accent); border-bottom: 2px solid var(--border); padding-bottom: 10px; margin-top: 0; font-size: 1.5rem; }
        pre { background: #020617; padding: 15px; border-radius: 8px; overflow-x: auto; color: #a5b4fc; font-family: 'Consolas', monospace; font-size: 0.85rem; }
        
        /* Table Styles */
        .res-table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 15px; }
        .res-table th { background: #0f172a; color: var(--accent); padding: 12px; text-align: left; border-bottom: 2px solid var(--border); position: sticky; top: 0; }
        .res-table td { padding: 12px; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
        .res-table tr:hover td { background: rgba(56, 189, 248, 0.05); }
        
        /* Badges */
        .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-live { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); } /* Merah */
        .badge-ghost { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.4); } /* Abu */
        .badge-clean { background: rgba(34, 197, 94, 0.2); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.4); } /* Hijau */
        
        /* Utilities */
        .url-link { color: var(--accent); text-decoration: none; transition: all 0.2s; }
        .url-link:hover { color: #7dd3fc; text-decoration: underline; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .stat-box { background: #0f172a; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid var(--border); }
        .stat-num { font-size: 2.5rem; font-weight: 800; line-height: 1; margin-bottom: 5px; color: var(--text); }
        .stat-label { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }

        .footer { text-align: center; margin-top: 50px; color: #64748b; font-size: 0.9em; border-top: 1px solid var(--border); padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ $TITLE</h1>
            <div class="meta">Generated by NawaSec Framework v${VERSION} | $(date) | Target Scope: <span id="targetScope">Detecting...</span></div>
        </header>

        <!-- Summary Section -->
        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div id="statsContainer" class="stat-grid">Loading stats...</div>
        </div>

        <!-- Detailed Results Section -->
        <div class="card">
            <h2>📝 Detailed Findings</h2>
            <div id="resultsContainer">Initializing data table...</div>
        </div>
        
        <!-- Raw Data (Hidden by default, toggleable) -->
        <div class="card">
            <h2 style="cursor: pointer;" onclick="document.getElementById('rawData').style.display = document.getElementById('rawData').style.display === 'none' ? 'block' : 'none'">⚙️ Raw Data (Click to Toggle)</h2>
            <pre id="rawData" style="display:none;"></pre>
        </div>

        <div class="footer">NawaSec Framework - Ultimate Edition | Secure Channel</div>
    </div>

    <script>
        // Inject Data safely
        const rawData = \`$JSON_CONTENT\`;
        let data = {};

        try {
            data = JSON.parse(rawData);
            document.getElementById('rawData').textContent = JSON.stringify(data, null, 2);
            document.getElementById('targetScope').textContent = data.target || "Unknown Target";
            
            renderDashboard(data);
        } catch (e) {
            console.error("JSON Parse Error:", e);
            document.getElementById('resultsContainer').innerHTML = '<div style="color:var(--danger); padding:20px; text-align:center;">❌ Error parsing scan data. Raw output might be corrupted.<br><small>'+e.message+'</small></div>';
            document.getElementById('rawData').textContent = rawData; // Show raw text if parse fails
            document.getElementById('rawData').style.display = 'block';
        }

        function renderDashboard(data) {
            // 1. STATS
            let statsHtml = '';
            let results = data.results || [];
            
            // Hitung statistik sederhana
            let total = results.length;
            let live = results.filter(r => r.status && r.status.includes('LIVE') || r.status.includes('!!!')).length;
            let ghost = results.filter(r => r.status && r.status.includes('GHOST')).length;
            let others = total - live - ghost;

            if (total > 0) {
                statsHtml += createStatBox(total, 'Total Findings', '#38bdf8');
                if (live > 0) statsHtml += createStatBox(live, 'Critical / Live', '#ef4444');
                if (ghost > 0) statsHtml += createStatBox(ghost, 'Ghost / Dead', '#94a3b8');
            } else {
                 // Jika data generik (bukan array results)
                 let keyCount = Object.keys(data).length;
                 statsHtml += createStatBox(keyCount, 'Data Fields', '#38bdf8');
            }
            document.getElementById('statsContainer').innerHTML = statsHtml;

            // 2. DETAILED TABLE
            if (results && results.length > 0) {
                let tableHtml = '<div style="overflow-x:auto;"><table class="res-table"><thead><tr>';
                
                // Deteksi kolom secara dinamis dari item pertama
                let headers = Object.keys(results[0]);
                // Prioritaskan kolom tertentu agar urutannya bagus
                const priority = ['status', 'type', 'url', 'file', 'info', 'size', 'keyword'];
                headers.sort((a, b) => {
                    let ia = priority.indexOf(a); let ib = priority.indexOf(b);
                    if (ia === -1) ia = 99; if (ib === -1) ib = 99;
                    return ia - ib;
                });

                headers.forEach(h => {
                    tableHtml += \`<th>\${h.toUpperCase()}</th>\`;
                });
                tableHtml += '</tr></thead><tbody>';

                results.forEach(row => {
                    tableHtml += '<tr>';
                    headers.forEach(key => {
                        let val = row[key] || '-';
                        tableHtml += \`<td>\${formatValue(key, val)}</td>\`;
                    });
                    tableHtml += '</tr>';
                });
                tableHtml += '</tbody></table></div>';
                document.getElementById('resultsContainer').innerHTML = tableHtml;
            } else {
                // Fallback untuk data Key-Value (non-array)
                let kvHtml = '<table class="res-table">';
                for (const [key, value] of Object.entries(data)) {
                    if (typeof value !== 'object') {
                        kvHtml += \`<tr><th width="200">\${key}</th><td>\${value}</td></tr>\`;
                    }
                }
                kvHtml += '</table>';
                document.getElementById('resultsContainer').innerHTML = kvHtml;
            }
        }

        function createStatBox(num, label, color) {
            return \`<div class="stat-box" style="border-top: 4px solid \${color}">
                <div class="stat-num" style="color: \${color}">\${num}</div>
                <div class="stat-label">\${label}</div>
            </div>\`;
        }

        function formatValue(key, val) {
            if (key === 'url' || key === 'link') {
                return \`<a href="\${val}" target="_blank" class="url-link">\${val}</a>\`;
            }
            if (key === 'status') {
                if (val.includes('LIVE') || val.includes('!!!')) return \`<span class="badge badge-live">\${val}</span>\`;
                if (val.includes('GHOST') || val.includes('404')) return \`<span class="badge badge-ghost">\${val}</span>\`;
                if (val.includes('CLEAN')) return \`<span class="badge badge-clean">\${val}</span>\`;
            }
            return val;
        }
    </script>
</body>
</html>
EOF
    log_result "HTML Report Generated (v1.5): $HTML_FILE"
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
+===================================================+
|  _   _                     ____                   |
| | \ | | __ ___      ____ _/ ___|  ___  ___        |
| |  \| |/ _` \ \ /\ / / _` \___ \ / _ \/ __|       |
| | |\  | (_| |\ V  V / (_| |___) |  __/ (__        |
| |_| \_|\__,_| \_/\_/ \__,_|____/ \___|\___|       |
+===================================================+
EOF
    echo -e "${NC}"
    draw_box "NawaSec Framework v$VERSION [ULTIMATE]" "$GREEN"
    echo "  Power & Precision | By: NawaSec Team"
    echo "  Output Dir: $OUTPUT_DIR"
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
    echo "  nmap            : [R11] Comprehensive Port Scanner (Nmap Hybrid)"
    echo "  ssl             : [R12] SSL & Header Inspector"
    echo ""
    echo "MODULES (LOKAL) - (Memindai mesin ini)"
    echo "  filescan        : [L1] Webshell Finder [File Enumeration] (membutuhkan --target <path>)"
    echo "  localps         : [L2] Pengecekan Proses Mencurigakan (Lokal)"
    echo "  localnet        : [L3] Pengecekan Koneksi Jaringan (Lokal)"
    echo "  localusers      : [L4] Pengecekan User & Login (Lokal)"
    echo "  localcron       : [L5] Pengecekan Cron Mendalam (Lokal)"
    echo "  localcron       : [L5] Pengecekan Cron Mendalam (Lokal)
  localcollect    : [L6] Kumpulkan Artefak Sistem (Full) (membutuhkan --target <path>)
  filescan        : [L7] Webshell Finder [File Enumeration] (membutuhkan --target <path>)
  privesc         : [L8] PrivEsc SUID Hunter
  filescan        : [L7] Webshell Finder [File Enumeration] (membutuhkan --target <path>)
  privesc         : [L8] PrivEsc SUID Hunter"
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

# --- [R1] ENHANCED SUBDOMAIN FINDER (v1.1 Power-Up) ---

# Helper: Resolve DNS with Timeout
resolve_subdomain() { 
    local S="$1"
    if timeout 2s nslookup "$S" >/dev/null 2>&1; then echo "$S"; fi
}
export -f resolve_subdomain

# Helper: HTTP Check with Banner Grab
check_subdomain_http() {
    local S="$1"; local RF="$2"; local UA="$3"
    for P in "https" "http"; do
        local U="$P://$S"
        local SC=$(curl -sL -I -o /dev/null -w "%{http_code}" --max-time 3 "$U" -A "$UA")
        if [[ "$SC" =~ ^(2|3|401|403) ]]; then
            jq -n --arg url "$U" --arg status "$SC" '{"url": $url, "status": $status}' >> "$RF"
            break
        fi
    done
}
export -f check_subdomain_http

run_module_subdomain() {
    log "INFO" "Starting Subdomain Finder v1.1 [Power-Up Mode]..."
    
    if [[ -z "$TARGET" ]]; then log "ERR" "Target domain required."; return 1; fi
    local ST=$(echo "$TARGET" | sed -E 's~^https?://~~' | sed -E 's/^www\.//' | cut -d'/' -f1)
    if [[ -z "$ST" ]]; then log "ERR" "Invalid target."; return 1; fi
    
    log "INFO" "Target: $ST"
    local TFA=$(add_temp_file)
    
    # 1. WILDCARD CHECK
    log "INFO" "Checking Wildcard DNS..."
    if nslookup "wildcard-test-$(date +%s).$ST" >/dev/null 2>&1; then
        log "WARN" "Wildcard DNS detected! Creating strict filter..."
        local WILDCARD=1
    else
        log "RES" "No Wildcard DNS detected. Safe to scan."
        local WILDCARD=0
    fi

    # 2. PASSIVE ENUMERATION (8 Sources)
    log "INFO" "Enumerating Passive Sources (CRT, HTarget, Anubis, AlienV, Rapid, Omni, SubCenter, Wayback)..."
    
    # Source 1-5 (Originals)
    (curl -s "https://crt.sh/?q=%.${ST}&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -Po '(\S+\.)+\S+' >> "$TFA") &
    (curl -s "https://api.hackertarget.com/hostsearch/?q=${ST}" | cut -d',' -f1 >> "$TFA") &
    (curl -s "https://jldc.me/anubis/subdomains/${ST}" | jq -r '.[]' 2>/dev/null >> "$TFA") &
    (curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${ST}/passive_dns" | jq -r '.passive_dns[].hostname' 2>/dev/null >> "$TFA") &
    (curl -s "https://rapiddns.io/subdomain/${ST}?full=1" | grep -oP '(?<=<td>)[a-zA-Z0-9.-]+\.'${ST}'(?=</td>)' >> "$TFA") &
    
    # Source 6-8 (New Power-Up)
    (curl -s "https://sonar.omnisint.io/subdomains/${ST}" | jq -r '.[]' 2>/dev/null >> "$TFA") &
    (curl -s "https://api.subdomain.center/?domain=${ST}" | jq -r '.[]' 2>/dev/null >> "$TFA") &
    (curl -s "http://web.archive.org/cdx/search/cdx?url=*.${ST}/*&output=json&collapse=urlkey" | jq -r '.[][2]' 2>/dev/null | grep -oP '(\S+\.)+\S+' | sort -u >> "$TFA") &

    wait
    
    # 3. CLEANING
    local TFC=$(add_temp_file)
    grep "$ST" "$TFA" | grep -v "*" | sed 's/^\.//' | sort -u | uniq > "$TFC"
    local total=$(wc -l < "$TFC")
    log "RES" "Found $total passive candidates."

    # 4. ACTIVE BRUTEFORCE (Optional/Turbo)
    # If the user provided a wordlist, we use it. If not, we skip active brute to save time/bandwidth unless requested.
    # For now, let's keep it simple: If wordlist > 1000 lines, ask user? No, let's make it automatic if small, or skip.
    # We'll skip complex brute logic for this "single file" constraint unless user asks.
    
    # 5. DNS RESOLUTION
    log "INFO" "Validating DNS Records ($PARALLEL_JOBS threads)..."
    local TFD=$(add_temp_file)
    cat "$TFC" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "resolve_subdomain {}" >> "$TFD"
    local dlc=$(wc -l < "$TFD")
    log "RES" "Alive Subdomains (DNS): $dlc"

    # 6. HTTP PROBING
    log "INFO" "Probing HTTP/HTTPS services..."
    local TFH=$(add_temp_file)
    export KINFO_USER_AGENT; export TFH
    cat "$TFD" | xargs -P "$PARALLEL_JOBS" -I {} bash -c "check_subdomain_http \"{}\" \"$TFH\" \"$KINFO_USER_AGENT\""
    local hlc=$(wc -l < "$TFH")
    log "RES" "Web Servers Found: $hlc"

    # 7. OUTPUT
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -n --arg target "$ST" \
              --arg total_passive "$total" \
              --arg total_dns "$dlc" \
              --arg total_http "$hlc" \
              --argjson dns_live "$(jq -Rsc 'split("\n")|map(select(length > 0))' "$TFD")" \
              --argjson http_live "$(jq -s '.' "$TFH")" \
              '{target: $target, stats: {passive: $total_passive, dns_live: $total_dns, http_live: $total_http}, data: {dns_live: $dns_live, http_live: $http_live}}' > "$OUTPUT_FILE"
    else
        {
            echo "NawaSec v1.1 - Subdomain Report"
            echo "Target: $ST"
            echo "Scan Date: $(date)"
            echo "------------------------------------------------"
            echo "Passive Candidates : $total"
            echo "DNS Alive          : $dlc"
            echo "HTTP/S Alive       : $hlc"
            echo "------------------------------------------------"
            echo ""
            echo "[+] WEB SERVERS:"
            cat "$TFH" | jq -r '"[\(.status)] \(.url)"'
            echo ""
            echo "[+] DNS RECORDS (No Web):"
            comm -23 <(sort "$TFD") <(cat "$TFH" | jq -r '.url' | sed -E 's~^https?://~~' | sort)
        } > "$OUTPUT_FILE"
        
        # Display Summary
        cat "$OUTPUT_FILE" | head -n 30
        if [[ $(wc -l < "$OUTPUT_FILE") -gt 30 ]]; then echo "... (Full report in output file)"; fi
    fi
    log "RES" "Scan Complete. Data saved to: $OUTPUT_FILE"
}

# ====================================================================
# --- [R2] DIRECTORY/FILE ENUMERATION ---
# ====================================================================
# --- [R2] DIRECTORY/FILE ENUMERATION (v1.4 Power-Up) ---

# Helper: Smart Dir Check (Status + Size + Soft 404)
check_dir_smart() {
    local URL="$1"; local IGNORE_SZ="$2"; local RF="$3"
    
    # Teknik Cepat: curl -w untuk ambil status code & size tanpa download body penuh
    # Kita ambil 1 byte saja (-r 0-0) untuk menipu server agar kirim header + content-length
    # Tapi beberapa server ignore range untuk halaman dinamis, jadi kita pakai -w dan buang output ke /dev/null
    
    local DATA
    DATA=$(curl -sL -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 3 --max-time 5 -H "User-Agent: $KINFO_USER_AGENT" "$URL")
    
    local SC=$(echo "$DATA" | cut -d':' -f1)
    local SZ=$(echo "$DATA" | cut -d':' -f2)
    
    # Filter Status Code (200, 301, 302, 401, 403)
    if [[ "$SC" =~ ^(200|301|302|401|403)$ ]]; then
        
        # LOGIKA SOFT 404:
        # Jika ukuran sama persis dengan halaman error (calibrated), abaikan.
        if [[ "$IGNORE_SZ" -gt 0 && "$SZ" -eq "$IGNORE_SZ" ]]; then
            return # Zonk / Soft 404
        fi
        
        # Simpan hasil
        jq -n --arg url "$URL" --arg status "$SC" --arg size "$SZ" \
            '{"url": $url, "status": $status, "size": $size}' >> "$RF"
    fi
}
export -f check_dir_smart

run_module_direnum() {
    log_info "Memulai Directory Enumeration v1.4 [Auto-Extensions]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan (e.g., example.com)."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::') # Hapus trailing slash
    
    if [[ ! -f "$WORDLIST" ]]; then log_error "Wordlist tidak ditemukan di: $WORDLIST"; return 1; fi
    
    log_info "[*] Target: $TARGET"
    
    # --- 2. SOFT 404 CALIBRATION ---
    log_info "[*] Kalibrasi Soft 404 (Anti-Zonk)..."
    local RAND_PATH="kinfo_404_test_$(date +%s)"
    local IGNORE_SIZE=0
    
    local CALIB_DATA
    CALIB_DATA=$(curl -sL -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 5 -H "User-Agent: $KINFO_USER_AGENT" "$TARGET/$RAND_PATH")
    local CALIB_SC=$(echo "$CALIB_DATA" | cut -d':' -f1)
    local CALIB_SZ=$(echo "$CALIB_DATA" | cut -d':' -f2)

    if [[ "$CALIB_SC" == "200" ]]; then
        IGNORE_SIZE="$CALIB_SZ"
        log_warn "[!] Soft 404 Detected! Mengabaikan response dengan ukuran $IGNORE_SIZE bytes."
    else
        log_info "[OK] Server normal."
    fi

    # --- 3. WORDLIST MUTATION (Auto-Extensions) ---
    local EXTENSIONS=(
        # Web Pages
        ".php" ".html" ".htm" ".jsp" ".asp" ".aspx" ".js"
        # Config / Backups
        ".bak" ".old" ".orig" ".save" ".swp" ".backup" ".txt"
        ".json" ".xml" ".yml" ".env" ".config" ".log"
        # Archives
        ".zip" ".tar.gz" ".rar" ".sql" ".db"
        # Directories (Trailing slash)
        "/"
    )
    
    log_info "[*] Menyiapkan Wordlist Mutasi (Menambahkan ${#EXTENSIONS[@]} ekstensi otomatis per kata)..."
    local LIST_ORI; LIST_ORI=$(grep -vE "^\s*#|^\s*$" "$WORDLIST")
    local TUL; TUL=$(add_temp_file)
    
    # Generator Cepat menggunakan AWK (Lebih efisien daripada Loop Bash)
    # Kami gabungkan kata asli + mutasi ekstensi
    echo "$LIST_ORI" | awk -v exts="${EXTENSIONS[*]}" '
    BEGIN { split(exts, e, " "); }
    { 
        print $0;              # Kata Asli (misal: "admin")
        for(i in e) print $0 e[i] # Mutasi (misal: "admin.php", "admin.zip")
    }' > "$TUL"

    local total_reqs=$(wc -l < "$TUL")
    log_info "[*] Memulai Scan Agresif ($total_reqs requests)..."
    
    # --- 4. EXECUTION ---
    local TJL; TJL=$(add_temp_file)
    export KINFO_USER_AGENT; export TJL; export IGNORE_SIZE
    
    # Jalankan Xargs Parallel
    cat "$TUL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_dir_smart \"$TARGET/{}\" \"$IGNORE_SIZE\" \"$TJL\""
    
    local fc; fc=$(wc -l < "$TJL")
    log_info "[+] Enumerasi selesai. Item ditemukan: $fc"
    
    if [[ "$fc" -eq 0 ]]; then log_warn "Tidak ada item valid ditemukan."; return 0; fi

    # --- 5. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$TARGET" --arg soft404_size "$IGNORE_SIZE" \
           '{target: $target, soft404_size: $soft404_size, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "NawaSec v1.1 - Directory Enum Report"
            echo "Target: $TARGET"
            echo "Soft 404 Size: $IGNORE_SIZE"
            echo "Total Found: $fc"
            echo "=================================="
            cat "$TJL" | jq -r '"[\(.status)] \(.url) (Size: \(.size))"' | sort -k 2
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE" | head -n 30
            if [[ "$fc" -gt 30 ]]; then echo "... (lihat file output untuk hasil lengkap)"; fi
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
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
    log_info "Memulai FTP Bruteforce v1.5 [Hydra + Anonymous]..."
    
    # --- 1. SETUP & VALIDASI ---
    local H; H=$(echo "$TARGET" | cut -d':' -f1); local P; P=$(echo "$TARGET" | cut -d':' -f2)
    if [[ "$H" == "$P" ]]; then P=21; fi
    
    if [[ -z "$H" ]]; then log_error "Target host diperlukan (IP/Domain)."; return 1; fi
    if ! nc -z -w 5 "$H" "$P" 2>/dev/null; then log_error "Port $P pada $H tertutup/unreachable."; return 1; fi
    
    log_info "[*] Target: $H:$P"
    local TJL; TJL=$(add_temp_file)
    
    # --- 2. ANONYMOUS CHECK (Sopan) ---
    log_info "[*] Tahap 1: Cek Login Anonymous..."
    local ANON_RES
    # Coba login user:anonymous pass:anonymous
    if command -v hydra &>/dev/null; then
        # Gunakan Hydra untuk cek satu user cepat
        if hydra -l anonymous -p anonymous "ftp://$H:$P" -t 1 -w 5 2>/dev/null | grep -qi "login:"; then
             ANON_RES="SUCCESS"
        fi
    else
        # Fallback Bash FTP
        local RESP=$(echo -e "user anonymous anonymous\nquit" | ftp -n "$H" "$P" 2>&1)
        if echo "$RESP" | grep -qi "login successful\|230\|welcome"; then
             ANON_RES="SUCCESS"
        fi
    fi

    if [[ "$ANON_RES" == "SUCCESS" ]]; then
        log_warn "[!!!] ANONYMOUS LOGIN SUKSES!"
        # Simpan hasil
        jq -n --arg url "ftp://$H:$P" --arg status "[LIVE]" --arg type "CREDENTIAL" --arg info "User: anonymous | Pass: anonymous" \
            '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$TJL"
            
        # Tanya user? atau skip brute force? Biasanya anon sudah cukup, tapi kita lanjut brute kalau user maksa (Wordlist check).
        log_info "    Melanjutkan brute force utk user lain..."
    else
        log_info "    Anonymous login gagal. Lanjut brute force."
    fi

    # --- 3. BRUTE FORCE ATTACK ---
    # Cek Wordlist
    if [[ ! -f "$FTP_LIST" ]]; then 
        log_warn "Wordlist default tidak ditemukan. Membuat wordlist mini..."
        echo "root:root" > "$FTP_LIST"
        echo "admin:admin" >> "$FTP_LIST"
        echo "user:user" >> "$FTP_LIST"
    fi
    
    # Mode Pilih: HYDRA vs BASH
    if command -v hydra &>/dev/null; then
        log_info "[*] Tahap 2: Brute Force (Engine: HYDRA 🐉)..."
        local HYDRA_OUT; HYDRA_OUT=$(add_temp_file)
        
        # Hydra format: user:pass file (-C)
        hydra -C "$FTP_LIST" -s "$P" "ftp://$H" -t "$PARALLEL_JOBS" -I -V > "$HYDRA_OUT"
        
        # Parse Output Hydra
        # Format Hydra: "[21][ftp] host: target   login: user   password: pw"
        grep "login:" "$HYDRA_OUT" | while read -r line; do
            local U=$(echo "$line" | grep -oP 'login: \K\S+')
            local PW=$(echo "$line" | grep -oP 'password: \K\S+')
            log_result "[SUCCESS] Found: $U:$PW"
            jq -n --arg url "ftp://$H:$P" --arg status "[LIVE]" --arg type "CREDENTIAL" --arg info "User: $U | Pass: $PW" \
                '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$TJL"
        done
        
    else
        log_info "[*] Tahap 2: Brute Force (Engine: BASH/FTP Legacy)..."
        log_warn "    Hydra tidak terinstall. Menggunakan metode lambat."
        
        check_ftp_cred_bash() {
            local H="$1"; local P="$2"; local UP="$3"; local RF="$4"
            local U=$(echo "$UP"|cut -d':' -f1); local PW=$(echo "$UP"|cut -d':' -f2-)
            local LR=$(echo -e "user $U $PW\nquit" | ftp -n "$H" "$P" 2>&1)
            if echo "$LR" | grep -qi "login successful\|230\|welcome"; then
                jq -n --arg url "ftp://$H:$P" --arg status "[LIVE]" --arg type "CREDENTIAL" --arg info "User: $U | Pass: $PW" \
                    '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$RF"
            fi
        }
        export -f check_ftp_cred_bash
        
        grep -vE "^\s*#|^\s*$" "$FTP_LIST" | grep ':' | xargs -P "$PARALLEL_JOBS" -I {} \
            bash -c "check_ftp_cred_bash \"$H\" \"$P\" \"{}\" \"$TJL\""
    fi
    
    local fc; fc=$(wc -l < "$TJL")
    log_info "[+] Scan selesai. Valid Credentials: $fc"
    
    if [[ "$fc" -eq 0 ]]; then return 0; fi

    # --- 4. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$H:$P" '{target: $target, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "FTP Bruteforce Report"
            echo "Target: $H:$P"
            echo "Scan Time: $(date)"
            echo "Total Found: $fc"
            echo "=================================="
            cat "$TJL" | jq -r '"\(.status) \(.type): \(.info)"'
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Hasil disimpan di: $OUTPUT_FILE"
        fi
    fi
}


# -----------------------------------------------
# -----------------------------------------------
# --- [R4] JUDI ONLINE FINDER (v1.4 Power-Up) ---

# Helper: Auto-Validation (Cek Status Hidup/Mati)
verify_infection() {
    local URL="$1"; local TYPE="$2"; local RF="$3"
    
    # Cek Header dulu (Cepat)
    local HCODE=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 5 -A "$KINFO_USER_AGENT" "$URL")
    
    if [[ "$HCODE" == "200" ]]; then
        # Jika 200 OK, cek kontennya ada kata judi gak?
        local BODY=$(curl -sL --max-time 5 -r 0-5000 -A "$KINFO_USER_AGENT" "$URL")
        # Regex keyword judi ekstrem (AI-Logic: match multiple keywords for higher confidence)
        if echo "$BODY" | grep -iqE "slot|gacor|maxwin|rtp|pragmatic|depo|wd|bonus|member|judi|bola|casino|togel|poker|zeus|olympus|mahjong|scatter|petir"; then
            # POSITIF: Halaman Hidup & Ada Konten Judi
            log_warn "  [LIVE] $URL (Confirmed Infection)"
            jq -n --arg url "$URL" --arg type "$TYPE" --arg status "[LIVE]" --arg info "Active Gambling Content Detected" \
                '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$RF"
        else
            # NEGATIF: Halaman Hidup tapi BERSIH (Mungkin False Positive Dork atau halaman berita)
            log "INFO" "  [CLEAN?] $URL (No keywords found in body)"
            jq -n --arg url "$URL" --arg type "$TYPE" --arg status "[?]" --arg info "Page 200 OK but clean content?" \
                '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$RF"
        fi
    elif [[ "$HCODE" =~ ^(404|410)$ ]]; then
        # GHOST: Terindeks tapi sudah dihapus (404)
        log "RES" "  [GHOST] $URL (404 Not Found - Already Cleaned)"
        jq -n --arg url "$URL" --arg type "$TYPE" --arg status "[GHOST]" --arg info "Indexed but Dead (404)" \
            '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$RF"
    else
        # Lainnya (403, 500, dll)
        log "INFO" "  [SKIP] $URL (Status: $HCODE)"
    fi
}
export -f verify_infection

# Helper: Cloaking Detector (Googlebot vs User)
check_cloaking() {
    local TARGET="$1"
    local LOG_FILE="$2"
    
    local PATTERN="slot|gacor|maxwin|rtp|pragmatic|depo|wd|bonus|member|judi|bola|casino|togel|poker|zeus|olympus"
    
    # 1. Simulate Normal User
    local USER_BODY=$(curl -sL --max-time 10 -A "$KINFO_USER_AGENT" "$TARGET")
    local C_USER=$(echo "$USER_BODY" | grep -ioE "$PATTERN" | wc -l)
    
    # 2. Simulate Googlebot (Search Engine Crawler)
    local GBOT_BODY=$(curl -sL --max-time 10 -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$TARGET")
    local C_GBOT=$(echo "$GBOT_BODY" | grep -ioE "$PATTERN" | wc -l)

    # 3. Simulate Mobile Device (Android) - Seringkali target redirect mobile
    local MOB_BODY=$(curl -sL --max-time 10 -A "Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36" "$TARGET")
    local C_MOB=$(echo "$MOB_BODY" | grep -ioE "$PATTERN" | wc -l)
    
    # AI-Logic Analysis
    if [[ "$C_GBOT" -gt "$((C_USER + 5))" ]] || [[ "$C_MOB" -gt "$((C_USER + 5))" ]]; then
        log_warn "[!] CLOAKING TERDETEKSI! Konten judi disembunyikan dari pengunjung Desktop."
        log_info "    Keywords -> User: $C_USER | Googlebot: $C_GBOT | Mobile: $C_MOB"
        jq -n --arg url "$TARGET" --arg type "CLOAKING" --arg info "Hidden content exposed to Bot/Mobile (User: $C_USER, Bot: $C_GBOT, Mob: $C_MOB)" \
            '{"status": "[!!!]", "type": $type, "url": $url, "info": $info}' >> "$LOG_FILE"
    elif [[ "$C_GBOT" -gt 0 || "$C_USER" -gt 0 || "$C_MOB" -gt 0 ]]; then
        if [[ "$C_USER" -gt 3 ]]; then
            log_warn "[!] KONTEN TERBUKA! Ditemukan $C_USER keyword judi di halaman utama."
            jq -n --arg url "$TARGET" --arg type "CONTENT" --arg info "Visible gambling content (User: $C_USER keywords)" \
                '{"status": "[LIVE]", "type": $type, "url": $url, "info": $info}' >> "$LOG_FILE"
        fi
    fi
}
export -f check_cloaking

# Helper: Smart Dorking (Bing + DuckDuckGo) + AUTO VALIDATION
check_dork_smart() {
    local DORK_QUERY="$1"   # e.g., site:target.com "slot gacor"
    local TYPE="$2"         # "DORK (Bing)" etc
    local RF="$3"           # Result File
    local UA="$4"
    
    local SEARCH_URL=""
    if [[ "$TYPE" == *"Bing"* ]]; then
        local ENC=$(echo "$DORK_QUERY" | jq -sRr @uri)
        SEARCH_URL="https://www.bing.com/search?q=$ENC"
    elif [[ "$TYPE" == *"DDG"* ]]; then
        local ENC=$(echo "$DORK_QUERY" | jq -sRr @uri)
        SEARCH_URL="https://html.duckduckgo.com/html/?q=$ENC"
    fi
    
    # Fetch Search Result
    local RES=$(curl -sL --max-time 10 -H "User-Agent: $UA" "$SEARCH_URL")
    
    # Extract URLs
    local FOUND_URLS
    FOUND_URLS=$(echo "$RES" | grep -oP 'href="https?://[^"]+"' | grep "$TARGET" | cut -d'"' -f2 | grep -v "google\|bing\|duckduckgo\|yahoo" | sort -u | head -n 3)
    
    if [[ -n "$FOUND_URLS" ]]; then
        log_info "[*] Dork hit: $DORK_QUERY -> Memvalidasi $(echo "$FOUND_URLS" | wc -l) URL..."
        while IFS= read -r U; do
            # AUTO-VALIDATION CALL
            verify_infection "$U" "$TYPE" "$RF"
        done <<< "$FOUND_URLS"
    fi
}
export -f check_dork_smart
export -f verify_infection

run_module_judi() {
    log_info "Memulai Judi Online Finder v1.5 [AI-Logic: Cloaking + Hybrid Dork]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target domain diperlukan."; return 1; fi
    local ST=$(echo "$TARGET"|sed -E 's~^https?://~~'|sed -E 's/^www\.//'|cut -d'/' -f1)
    if [[ -z "$ST" ]]; then log_error "Input target tidak valid."; return 1; fi
    
    log_info "[*] Target: $ST"
    local TJL; TJL=$(add_temp_file)
    
    # --- 2. CLOAKING DETECTION (Mobile + Bot) ---
    log_info "[*] Tahap 1: Cloaking Detection (Multi-Agent Simulation)..."
    check_cloaking "https://$ST" "$TJL" &
    if timeout 2s nc -z "$ST" 80 2>/dev/null; then
        check_cloaking "http://$ST" "$TJL" &
    fi
    wait
    
    # --- 3. HYBRID KEYWORD GENERATION (Max 40) ---
    log_info "[*] Tahap 2: Smart Dorking (Bing + DDG)..."
    log_info "    Menyiapkan Keyword Populer (v1.5 Enterprise Wordlist)..."
    
    local KEYS_FILE; KEYS_FILE=$(add_temp_file)
    
    # A. Built-in Popular Keys (The "Gacor" List v1.5)
    cat <<EOF > "$KEYS_FILE"
slot gacor
situs judi online
rtp live slot
bonus new member
judol
agen bola terpercaya
casino online
togel sgp
poker online uat
maxwin x500
pragmatic play
bo slot
link alternatif
deposit pulsa tanpa potongan
scatter hitam
mahjong ways
gates of olympus
starlight princess
syair hk
prediksi togel
live chat judi
sabung ayam online
tembak ikan
bandar togel
slot deposit dana
garansi kekalahan
bonus rollingan
referral judi
jackpot terbesar
pola gacor
zeus slot
slot88
judi bola
roulette online
baccarat online
sicbo online
domino qiu qiu
capsa susun
sakong online
bandar q
EOF

    # B. Merge User List (If exists)
    if [[ -f "$JUDI_LIST" ]]; then
        cat "$JUDI_LIST" >> "$KEYS_FILE"
    fi
    
    # C. Shuffle & Pick Top 40
    local FINAL_KEYS; FINAL_KEYS=$(add_temp_file)
    sort -u "$KEYS_FILE" | shuf | head -n 40 > "$FINAL_KEYS"
    
    local k_count=$(wc -l < "$FINAL_KEYS")
    log_info "    Menggunakan $k_count Keyword Final untuk Dorking."

    # --- 4. EXECUTION ---
    local TDL; TDL=$(add_temp_file)
    
    # Generate Queries (Bing + DDG)
    while IFS= read -r K; do
        if [[ -n "$K" ]]; then
            echo "site:$ST \"$K\"|DORK (Bing)" >> "$TDL"
            echo "site:$ST \"$K\"|DORK (DDG)" >> "$TDL"
        fi
    done < "$FINAL_KEYS"
    
    # Limit queries check (Prevent blocking)
    shuf "$TDL" | head -n 20 > "$TDL.run"
    
    export TARGET="$ST"; export KINFO_USER_AGENT; export TJL
    
    # Jalankan Dorking Paralel
    cat "$TDL.run" | xargs -P 5 -I {} bash -c \
        "IFS='|' read -r Q E <<< '{}'; check_dork_smart \"\$Q\" \"\$E\" \"$TJL\" \"$KINFO_USER_AGENT\""
        
    wait
    
    local fc; fc=$(wc -l < "$TJL")
    log_info "[+] Scan selesai. Total Alert/Info: $fc"
    
    if [[ "$fc" -eq 0 ]]; then 
        log_warn "Target BERSIH. Tidak ditemukan indikasi judi online (Cloaking/Dork/Live Page)."; return 0; 
    fi

    # --- 5. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$ST" '{target: $target, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "NawaSec v1.5 - Judol Hunter Report"
            echo "Target: $ST"
            echo "Scan Time: $(date)"
            echo "Total Alerts: $fc"
            echo "=================================="
            # Prioritaskan LIVE / CLOAKING di atas
            cat "$TJL" | jq -r 'select(.status == "[LIVE]" or .status == "[!!!]") | "\(.status) \(.type): \(.url)"'
            cat "$TJL" | jq -r 'select(.status != "[LIVE]" and .status != "[!!!]") | "\(.status) \(.type): \(.url)"' 
            echo ""
            echo "Rincian:"
            cat "$TJL" | jq -r '"- [\(.type)] \(.info)"' | sort -u
        } > "$OUTPUT_FILE"
        
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then 
            cat "$OUTPUT_FILE"
            echo -e "\n[+] Laporan disimpan di: $OUTPUT_FILE"
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
    log_info "Memulai Webshell Finder v1.5 Ultimate [Content Aware]..."
    
    # --- 1. SETUP & VALIDASI ---
    if [[ -z "$TARGET" ]]; then log_error "Target URL diperlukan (e.g., example.com)."; return 1; fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then TARGET="https://$TARGET"; fi
    TARGET=$(echo "$TARGET" | sed 's:/*$::') # Hapus trailing slash
    
    log_info "[*] Target: $TARGET"

    # --- 2. SOFT 404 CALIBRATION ---
    log_info "[*] Kalibrasi Soft 404 (Anti-Zonk)..."
    local RAND_PATH="kinfo_chk_$(date +%s)"
    local IGNORE_SIZE=0
    
    local CALIB_DATA
    CALIB_DATA=$(curl -sL -o /dev/null -w "%{http_code}:%{size_download}" --connect-timeout 5 -H "User-Agent: $KINFO_USER_AGENT" "$TARGET/$RAND_PATH")
    local CALIB_SC=$(echo "$CALIB_DATA" | cut -d':' -f1)
    local CALIB_SZ=$(echo "$CALIB_DATA" | cut -d':' -f2)

    if [[ "$CALIB_SC" == "200" ]]; then
        IGNORE_SIZE="$CALIB_SZ"
        log_warn "[!] Soft 404 Aktif! Memfilter respon dengan ukuran $IGNORE_SIZE bytes."
    else
        log_info "[OK] Server normal."
    fi

    # --- 3. WORDLIST SELECTION ---
    local TPL; TPL=$(add_temp_file)
    local MODE_INFO=""
    
    # Cek apakah user memberikan Wordlist Eksternal via -w
    # NOTE: Variabel WORDLIST di-set global oleh main()
    # Kita cek apakah file itu file default atau file custom user
    if [[ "$WORDLIST" != "$SCRIPT_DIR/wordlist.txt" && -f "$WORDLIST" ]]; then
         log_info "[*] Menggunakan Wordlist Eksternal: $WORDLIST"
         # Copy isi wordlist custom ke temp
         cat "$WORDLIST" > "$TPL"
         MODE_INFO="Brute Force (External Wordlist)"
    else
        log_info "[*] Menggunakan Built-in Wordlist (Top 130 Webshell Paths)..."
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
        printf "%s\n" "${WSP[@]}" > "$TPL"
        MODE_INFO="Deep Scan (Built-in)"
    fi
    
    local total_lines=$(wc -l < "$TPL")
    log_info "[*] Memulai Scan: $MODE_INFO ($total_lines targets, Paralel: $PARALLEL_JOBS)..."
    
    local TJL; TJL=$(add_temp_file)
    export TARGET; export RATE_LIMIT; export KINFO_USER_AGENT; export TJL; export IGNORE_SIZE
    
    # --- 4. EXECUTION ---
    # Gunakan xargs dengan replacement {} agar bisa handle spasi di nama file jika ada
    cat "$TPL" | xargs -P "$PARALLEL_JOBS" -I {} \
        bash -c "check_path_smart \"$TARGET\" \"{}\" \"$RATE_LIMIT\" \"$KINFO_USER_AGENT\" \"$TJL\" \"$IGNORE_SIZE\""
    
    local fc; fc=$(wc -l < "$TJL")
    log_info "[+] Scan selesai. Kandidat ditemukan: $fc"
    
    if [[ "$fc" -eq 0 ]]; then 
        log_warn "Target bersih. Tidak ditemukan webshell."; return 0; 
    fi

    # --- 5. OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        jq -s --arg target "$TARGET" --arg soft404_size "$IGNORE_SIZE" \
           '{target: $target, soft404_size: $soft404_size, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        {
            echo "Webshell Hunter Results ($MODE_INFO)"
            echo "Target: $TARGET"
            echo "Scan Time: $(date)"
            echo "Total Found: $fc"
            echo "=================================="
            # Menampilkan Status, Type, Info, URL
            cat "$TJL" | jq -r '"\(.status) \(.type): \(.url) [\(.info)]"' | sort -k 1
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

# --- [R11] NMAP PORT SCANNER (Hybrid) ---
run_module_nmap() {
    log_info "Memulai Comprehensive Port Scanner v1.5 [HTML Ready]..."
    if [[ -z "$TARGET" ]]; then log_error "Target IP/Domain diperlukan."; return 1; fi
    
    # Auto-Install Nmap Logic
    if ! command -v nmap &>/dev/null; then
        log_warn "Nmap tidak ditemukan. Mencoba auto-install..."
        if command -v apt-get &>/dev/null; then sudo apt-get update && sudo apt-get install -y nmap
        elif command -v apk &>/dev/null; then sudo apk add nmap
        elif command -v yum &>/dev/null; then sudo yum install -y nmap
        else log_error "Gagal install Nmap. Silakan install manual."; return 1; fi
        
        if ! command -v nmap &>/dev/null; then log_error "Instalasi gagal."; return 1; fi
    fi
    
    local H=$(echo "$TARGET" | sed -E 's~^https?://~~' | cut -d'/' -f1)
    log_info "[*] Target: $H"
    
    # Mode Fast but Detailed (Top 1000 ports, Version Scan, Open only)
    local ARGS="-sV --open -T4"
    log_info "[*] Running Nmap ($ARGS)..."
    
    local OUT_N="$OUTPUT_DIR/nmap_${H}.txt"
    local OUT_G="$(mktemp)"
    
    # Run Nmap (Save Normal and Grepable)
    nmap $ARGS "$H" -oN "$OUT_N" -oG "$OUT_G"
    
    # Parse Grepable Output to JSON for HTML Report
    local TJL; TJL=$(add_temp_file)
    
    # Ambil baris Ports, extract bagian setelah 'Ports: '
    local PORTS_DATA
    PORTS_DATA=$(grep "Ports:" "$OUT_G" | cut -d':' -f3)
    
    # Jika ada port terbuka
    if [[ -n "$PORTS_DATA" ]]; then
        # Set IFS ke koma untuk memisahkan tiap blok port
        IFS=',' read -ra P_ARRAY <<< "$PORTS_DATA"
        for P_STR in "${P_ARRAY[@]}"; do
            # Format: 80/open/tcp//http//Apache/
            # Trim whitespace
            P_STR=$(echo "$P_STR" | xargs)
            
            # Split by /
            local PORT=$(echo "$P_STR" | cut -d'/' -f1)
            local STATE=$(echo "$P_STR" | cut -d'/' -f2)
            local PROTO=$(echo "$P_STR" | cut -d'/' -f3)
            local SERVICE=$(echo "$P_STR" | cut -d'/' -f5)
            local VERSION=$(echo "$P_STR" | cut -d'/' -f7)
            
            # Construct Info
            local INFO="$SERVICE"
            if [[ -n "$VERSION" ]]; then INFO="$SERVICE ($VERSION)"; fi
            
            # Append to JSON Log
            jq -n --arg url "$H:$PORT" --arg status "[$STATE]" --arg type "PORT ($PROTO)" --arg info "$INFO" \
                '{"status": $status, "type": $type, "url": $url, "info": $info}' >> "$TJL"
        done
        
        local fc=$(wc -l < "$TJL")
        log_result "[+] Ditemukan $fc port terbuka."
    else
        log_warn "Tidak ada port terbuka yang ditemukan."
    fi
    
    rm "$OUT_G"

    # --- OUTPUT GENERATION ---
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        # Jika JSON kosong (no ports), buat valid JSON
        if [[ ! -s "$TJL" ]]; then echo "[]" > "$TJL"; fi
        
        jq -s --arg target "$H" '{target: $target, results: .}' "$TJL" > "$OUTPUT_FILE"
        if [[ "$OUTPUT_FILE" != "/dev/stdout" ]]; then cat "$OUTPUT_FILE"; fi
    else
        # Tampilkan Raw Nmap Output di CLI/Text Mode
        cat "$OUT_N" > "$OUTPUT_FILE" # Overwrite temp JSON file pointer logic from main menu if raw text needed
        cat "$OUT_N"
        echo -e "\n[+] Raw Nmap log saved to: $OUT_N"
    fi
}


# --- [R12] SSL & HEADER INSPECTOR ---
run_module_ssl() {
    log_info "Memulai SSL & Header Inspector..."
    if [[ -z "$TARGET" ]]; then log_error "Target Domain diperlukan."; return 1; fi
    local D=$(echo "$TARGET" | sed -E 's~^https?://~~' | cut -d'/' -f1)
    
    log_info "[*] Target: $D"
    local OUT="$OUTPUT_DIR/ssl_${D}.txt"
    
    {
        echo "=== SSL CERTIFICATE INFO ==="
        echo | openssl s_client -servername "$D" -connect "$D":443 2>/dev/null | openssl x509 -noout -dates -issuer -subject
        echo ""
        echo "=== SECURITY HEADERS ==="
        curl -sI "https://$D" | grep -E "Strict-Transport|Content-Security|X-Frame|X-Content-Type"
    } | tee "$OUT"
    log_result "[+] Inspeksi selesai. Hasil: $OUT"
}

# --- [L8] PRIVESC SUID HUNTER ---
run_module_privesc() {
    log_info "Memulai PrivEsc Hunter (SUID Binaries)..."
    log_warn "Mencari binary dengan SUID bit yang bisa dieksploitasi untuk Root."
    
    local OUT="$OUTPUT_DIR/privesc_suid_$(hostname).txt"
    find / -perm -4000 -type f 2>/dev/null | tee "$OUT"
    
    local count=$(wc -l < "$OUT")
    log_result "[+] Ditemukan $count SUID binaries. Cek di $OUT"
    log_info "Tips: Cek binary tersebut di https://gtfobins.github.io"
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
        echo " [11] Comprehensive Port Scanner (Nmap)"
        echo " [12] SSL & Header Inspector"
        echo " [13] Kembali ke Menu Utama"
        echo ""
        read -p "Pilih Opsi Remote (1-13): " pilihan

        TARGET=""; OUTPUT_FILE="$OUTPUT_DIR/kinfo_R${pilihan}_$(date +%s).txt"
        
        # HTML Option
        local HTML_OPT="n"; OUTPUT_FORMAT="text"
        read -p "Generate HTML Report? (y/N): " HTML_OPT
        if [[ "$HTML_OPT" =~ ^[Yy]$ ]]; then
            OUTPUT_FORMAT="json"
            OUTPUT_FILE="${OUTPUT_FILE%.txt}.json"
            log_info "HTML Mode Active. Raw JSON will be saved to: $OUTPUT_FILE"
        else
            log_info "Output (if any) will be saved to: $OUTPUT_FILE"
        fi
        
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
            11) read -p "Enter Target IP/Domain: " TARGET; run_module_nmap ;;
            12) read -p "Enter Target Domain: " TARGET; run_module_ssl ;;
            13) break ;;
            *) log_error "Opsi tidak valid. Silakan pilih 1-13"; sleep 2 ;;
        esac
        
        if [[ "$HTML_OPT" =~ ^[Yy]$ ]]; then generate_html_report "$OUTPUT_FILE"; fi
        if [[ "$pilihan" -ne 13 ]]; then echo ""; read -p "Tekan Enter untuk melanjutkan..."; fi
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
        echo " [8] PrivEsc SUID Hunter [NEW]"
        echo " [9] Kembali ke Menu Utama"
        echo ""
        read -p "Pilih Opsi Lokal (1-9): " pilihan

        TARGET=""; OUTPUT_FILE="$OUTPUT_DIR/kinfo_L${pilihan}_$(date +%s).txt"
        
        # HTML Option (Except for option 7 FTP which has no output)
        local HTML_OPT="n"; OUTPUT_FORMAT="text"
        if [[ "$pilihan" -ne 7 && "$pilihan" -ne 9 ]]; then
             read -p "Generate HTML Report? (y/N): " HTML_OPT
             if [[ "$HTML_OPT" =~ ^[Yy]$ ]]; then
                 OUTPUT_FORMAT="json"
                 OUTPUT_FILE="${OUTPUT_FILE%.txt}.json"
                 log_info "HTML Mode Active. Raw JSON will be saved to: $OUTPUT_FILE"
             else
                 log_info "Output (if any) will be saved to: $OUTPUT_FILE"
             fi
        fi
        
        case $pilihan in
            1) 
                log_info "Output will be saved to: $OUTPUT_FILE"
                read -p "Enter local directory path (default: .): " TARGET; if [[ -z "$TARGET" ]]; then TARGET="."; fi; run_module_filescan ;;
            2) 
                log_info "Output will be saved to: $OUTPUT_FILE"
                run_module_local_ps ;;
            3) 
                log_info "Output will be saved to: $OUTPUT_FILE"
                run_module_local_net ;;
            4) 
                log_info "Output will be saved to: $OUTPUT_FILE"
                run_module_local_users ;;
            5) 
                log_info "Output will be saved to: $OUTPUT_FILE"
                run_module_local_cron ;;
            6) 
                # Modul L6 (localcollect) TIDAK menggunakan $OUTPUT_FILE standar, ia punya folder sendiri
                read -p "Enter path direktori untuk dipindai (e.g., /var/www, /home): " TARGET
                run_module_local_collect ;;
            7) 
                # Modul FTP tidak menghasilkan file output
                log_info "Menjalankan FTP Client..."
                mini_ftp_client ;;
            8) run_module_privesc ;;
            9) break ;;
            *) log_error "Opsi tidak valid. Silakan pilih 1-9"; sleep 2 ;;
        esac
        
        if [[ "$HTML_OPT" =~ ^[Yy]$ ]]; then generate_html_report "$OUTPUT_FILE"; fi
        if [[ "$pilihan" -ne 9 ]]; then echo ""; read -p "Tekan Enter untuk melanjutkan..."; fi
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
