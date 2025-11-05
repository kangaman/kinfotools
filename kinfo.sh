#!/bin/bash

# KINFO - Incident Response & Pentest Toolkit
# Version: 1.3
# Updated: 5 November 2025
# Contact: https://jejakintel.t.me/

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
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
    echo "  Version: 1.3 | Update: 5 November 2025 "
    echo "  Contact: https://jejakintel.t.me/      "
    echo "========================================="
    echo ""
}

# Menu Utama
show_menu() {
    echo "┌──(${USER})-[KINFO]"
    echo "└─$ INCIDENT RESPONSE MENU:"
    echo ""
    echo " [1] Enhanced Subdomain Finder"
    echo " [2] Directory/File Enumeration (wordlist.txt)"
    echo " [3] FTP Bruteforce (FTP/FTPS) (ftpbrute.txt)"
    echo " [4] Judi Online Finder (judilist.txt)"
    echo " [5] Reverse IP Lookup"
    echo " [6] Extract Domain [Auto Add HTTPS]"
    echo " [7] Webshell Finder [DirScan]"
    echo " [8] Webshell Finder [File Enumeration]"
    echo " [9] ENV & Debug Method Scanner"
    echo " [10] WordPress Registration Finder"
    echo " [11] Grab Domain from Zone-H"
    echo " [12] Mini Shell FTP Client"
    echo " [13] Back to Main Menu"
    echo ""
    read -p "Select Option (1-13): " pilihan
}

# 1. Enhanced Subdomain Finder
enhanced_subdomain_finder() {
    echo ""
    echo "[+] Enhanced Subdomain Finder"
    echo "============================="
    read -p "Enter domain (without http/https): " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}[!] Domain cannot be empty!${NC}"
        return 1
    fi
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] cURL not found!${NC}"
        return 1
    fi
    
    echo "[*] Finding subdomains for $domain..."
    
    # Create temporary files
    temp_file="/tmp/subdomains_$domain.txt"
    resolved_file="/tmp/resolved_$domain.txt"
    > "$temp_file"
    > "$resolved_file"
    
    # Source 1: crt.sh
    echo "[*] Checking crt.sh..."
    curl -s "https://crt.sh/?q=%.$domain&output=json" | \
    grep -Po '"name_value":\s*"\K[^"]*' >> "$temp_file"
    
    # Source 2: Bufferover.run
    echo "[*] Checking bufferover.run..."
    bufferover_result=$(curl -s "https://dns.bufferover.run/dns?q=.$domain" 2>/dev/null)
    if [ -n "$bufferover_result" ]; then
        echo "$bufferover_result" | jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | \
        cut -d',' -f2 >> "$temp_file"
    fi
    
    # Source 3: AlienVault OTX
    echo "[*] Checking alienvault.com..."
    otx_result=$(curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" 2>/dev/null)
    if [ -n "$otx_result" ]; then
        echo "$otx_result" | jq -r '.passive_dns[].hostname' 2>/dev/null | \
        grep "\.$domain$" >> "$temp_file"
    fi
    
    # Source 4: ThreatCrowd
    echo "[*] Checking threatcrowd.org..."
    tc_result=$(curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" 2>/dev/null)
    if [ -n "$tc_result" ]; then
        echo "$tc_result" | jq -r '.subdomains[]' 2>/dev/null >> "$temp_file"
    fi
    
    # Source 5: SecurityTrails
    echo "[*] Checking securitytrails.com..."
    st_result=$(curl -s "https://securitytrails.com/list/apex_domain/$domain" 2>/dev/null)
    if [ -n "$st_result" ]; then
        echo "$st_result" | grep -oE '[a-zA-Z0-9\-\.]*\.$domain' | \
        grep -v "^$domain$" >> "$temp_file"
    fi
    
    # Remove duplicates and empty lines
    sort -u "$temp_file" | grep -v "^$" > "${temp_file}.tmp"
    mv "${temp_file}.tmp" "$temp_file"
    
    # DNS Resolution for live checking
    echo "[*] Resolving subdomains..."
    while read -r subdomain; do
        if nslookup "$subdomain" >/dev/null 2>&1; then
            echo "$subdomain" >> "$resolved_file"
            echo -e "${GREEN}[LIVE] $subdomain${NC}"
        fi
    done < "$temp_file"
    
    total=$(wc -l < "$temp_file")
    live_count=$(wc -l < "$resolved_file")
    
    echo -e "${GREEN}[✓] Found $total subdomains ($live_count live)${NC}"
    
    if [ $total -gt 0 ]; then
        # Save results
        output_file="kinfo_subdomains_${domain}_$(date +%s).txt"
        {
            echo "KINFO Enhanced Subdomain Finder Results"
            echo "Target: $domain"
            echo "Scan Time: $(date)"
            echo "Total Found: $total | Live: $live_count"
            echo "===================================="
            echo "ALL SUBDOMAINS:"
            cat "$temp_file"
            echo ""
            echo "LIVE SUBDOMAINS:"
            cat "$resolved_file"
        } > "$output_file"
        
        echo "[*] Results saved to: $output_file"
        
        # Show summary
        if [ $total -le 30 ]; then
            echo "[*] All subdomains:"
            cat "$temp_file"
        else
            echo "[*] First 30 subdomains:"
            head -30 "$temp_file"
            echo "[*] Full list in the output file"
        fi
    else
        echo -e "${YELLOW}[-] No subdomains found${NC}"
    fi
    
    # Store subdomains in a global variable for later use
    echo "$temp_file" > "/tmp/kinfo_last_subdomains.txt"
    
    # Cleanup
    # rm -f "$temp_file" "$resolved_file"
    
    echo ""
    read -p "Press Enter to continue..."
}

# 2. Directory/File Enumeration with wordlist.txt
dir_file_enum() {
    echo ""
    echo "[+] Directory/File Enumeration"
    echo "=============================="
    read -p "Enter target URL (e.g., https://target.com): " target_url
    
    if [ -z "$target_url" ]; then
        echo -e "${RED}[!] Target URL cannot be empty!${NC}"
        return 1
    fi
    
    # Validate and format URL
    if [[ ! "$target_url" =~ ^https?:// ]]; then
        target_url="https://$target_url"
    fi
    
    # Remove trailing slash
    target_url=$(echo "$target_url" | sed 's:/*$::')
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] cURL not found!${NC}"
        return 1
    fi

    # Check for wordlist.txt in current directory
    wordlist="wordlist.txt"
    if [ ! -f "$wordlist" ]; then
        echo -e "${RED}[!] wordlist.txt not found in current directory!${NC}"
        echo "Please create a wordlist.txt file with directory/file names"
        return 1
    fi
    
    echo "[*] Starting enumeration on $target_url"
    echo "[*] Using wordlist: $wordlist"
    
    # Read wordlist and start enumeration
    total_lines=$(wc -l < "$wordlist")
    found_items=()
    checked=0
    
    while IFS= read -r path; do
        # Skip empty lines and comments
        if [ -z "$path" ] || [[ "$path" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        checked=$((checked + 1))
        full_url="$target_url/$path"
        printf "${CYAN}[*] Checking %s (%d/%d)\r${NC}" "$path" "$checked" "$total_lines"
        
        # Check with different methods
        response=$(curl -sIL "$full_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
        status_line=$(echo "$response" | head -n 1)
        status_code=$(echo "$status_line" | grep -oE '[0-9]{3}' | head -1)
        
        # Check for interesting responses
        if [[ "$status_code" =~ ^(200|301|302|401|403)$ ]]; then
            size=$(curl -s "$full_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null | wc -c)
            content_type=$(echo "$response" | grep -i "content-type:" | head -1 | cut -d' ' -f2)
            
            # Highlight findings
            if [[ "$status_code" == "200" ]]; then
                echo -e "\n${GREEN}[FOUND] $full_url (Status: $status_code, Size: $size bytes)${NC}"
                found_items+=("$full_url|$status_code|$size")
            elif [[ "$status_code" == "403" ]]; then
                echo -e "\n${YELLOW}[FORBIDDEN] $full_url (Status: $status_code)${NC}"
                found_items+=("$full_url|$status_code|N/A")
            else
                echo -e "\n${BLUE}[REDIRECT] $full_url (Status: $status_code)${NC}"
                found_items+=("$full_url|$status_code|N/A")
            fi
        fi
    done < "$wordlist"
    
    echo "" # New line after progress
    
    # Save results
    if [ ${#found_items[@]} -gt 0 ]; then
        enum_file="kinfo_enum_$(date +%s).txt"
        {
            echo "Directory/File Enumeration Results"
            echo "Target: $target_url"
            echo "Wordlist: $wordlist"
            echo "Scan Time: $(date)"
            echo "=================================="
            echo "URL|STATUS|SIZE"
        } > "$enum_file"
        
        for item in "${found_items[@]}"; do
            echo "$item" >> "$enum_file"
        done
        
        echo -e "${GREEN}[✓] Enumeration completed. Found ${#found_items[@]} items.${NC}"
        echo "[*] Results saved to: $enum_file"
        
        # Show first 10 results
        echo "[*] First 10 results:"
        head -n 11 "$enum_file" | tail -n 10
        if [ ${#found_items[@]} -gt 10 ]; then
            echo "... and $((${#found_items[@]} - 10)) more items"
        fi
    else
        echo -e "${YELLOW}[-] No directories/files found during enumeration.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 3. FTP Bruteforce (FTP/FTPS) with ftpbrute.txt
ftp_bruteforce() {
    echo ""
    echo "[+] FTP Bruteforce (FTP/FTPS)"
    echo "============================="
    read -p "Enter FTP host: " ftp_host
    read -p "Enter FTP port (default 21): " ftp_port
    
    if [ -z "$ftp_port" ]; then
        ftp_port=21
    fi
    
    # Check if host is reachable
    if ! nc -z "$ftp_host" "$ftp_port" 2>/dev/null; then
        echo -e "${RED}[!] Cannot connect to $ftp_host:$ftp_port${NC}"
        return 1
    fi
    
    echo "[*] Connected to FTP server: $ftp_host:$ftp_port"
    
    # Check for ftpbrute.txt in current directory
    wordlist="ftpbrute.txt"
    if [ ! -f "$wordlist" ]; then
        echo -e "${RED}[!] ftpbrute.txt not found in current directory!${NC}"
        echo "Please create a ftpbrute.txt file with username:password combinations"
        echo "Format: username:password (one per line)"
        return 1
    fi
    
    echo "[*] Using wordlist: $wordlist"
    
    # Detect FTP or FTPS
    echo "[*] Detecting FTP service type..."
    banner=$(echo -e "quit" | ftp -n "$ftp_host" "$ftp_port" 2>/dev/null | head -3)
    
    if echo "$banner" | grep -qi "ftps\|tls\|ssl"; then
        protocol="FTPS"
        echo -e "${YELLOW}[INFO] Detected FTPS server${NC}"
    else
        protocol="FTP"
        echo -e "${BLUE}[INFO] Standard FTP server${NC}"
    fi
    
    # Start bruteforce
    echo "[*] Starting bruteforce attack..."
    total_attempts=$(grep -v "^#" "$wordlist" | grep -v "^$" | wc -l)
    attempt=0
    success=false
    
    while IFS=: read -r username password; do
        # Skip empty lines and comments
        if [ -z "$username" ] || [[ "$username" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        attempt=$((attempt + 1))
        printf "${CYAN}[*] Trying %s:%s (%d/%d)\r${NC}" "$username" "$password" "$attempt" "$total_attempts"
        
        # Attempt login
        if [ "$protocol" = "FTPS" ]; then
            # For FTPS, we'll use a more basic check since ftp command doesn't easily support FTPS
            # This is a simplified approach - in practice you'd use lftp or similar
            login_result=$(echo -e "user $username $password\nquit" | ftp -n "$ftp_host" "$ftp_port" 2>&1)
        else
            login_result=$(echo -e "user $username $password\nquit" | ftp -n "$ftp_host" "$ftp_port" 2>&1)
        fi
        
        # Check for successful login
        if echo "$login_result" | grep -qi "login successful\|230\|welcome"; then
            echo -e "\n${GREEN}[SUCCESS] Credentials found: $username:$password${NC}"
            
            # Save successful credentials
            brute_result="kinfo_ftp_success_${ftp_host}_$(date +%s).txt"
            {
                echo "FTP Bruteforce Success Report"
                echo "Host: $ftp_host:$ftp_port"
                echo "Protocol: $protocol"
                echo "Time: $(date)"
                echo "=================================="
                echo "Username: $username"
                echo "Password: $password"
            } > "$brute_result"
            
            echo "[*] Credentials saved to: $brute_result"
            success=true
            break
        fi
    done < <(grep -v "^#" "$wordlist" | grep -v "^$")
    
    echo "" # New line after progress
    
    if [ "$success" = false ]; then
        echo -e "${YELLOW}[-] Bruteforce completed. No valid credentials found.${NC}"
        echo "[*] Tried $attempt credential combinations"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 4. Judi Online Finder with judilist.txt
judi_online_finder() {
    echo ""
    echo "[+] Judi Online Finder"
    echo "======================"
    read -p "Enter domain (without http/https): " domain
    
    if [ -z "$domain" ]; then
        echo -e "${RED}[!] Domain cannot be empty!${NC}"
        return 1
    fi
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] cURL not found!${NC}"
        return 1
    fi

    # Check for judilist.txt in current directory
    judilist="judilist.txt"
    if [ ! -f "$judilist" ]; then
        echo -e "${RED}[!] judilist.txt not found in current directory!${NC}"
        echo "Please create a judilist.txt file with gambling keywords"
        return 1
    fi
    
    echo "[*] Using judilist: $judilist"
    
    # Get subdomains if available
    subdomains_file="/tmp/subdomains_$domain.txt"
    if [ ! -f "$subdomains_file" ]; then
        echo "[*] No subdomains found locally, using only the main domain"
        targets=("$domain")
    else
        echo "[*] Loading subdomains from previous scan"
        # Read subdomains into array
        mapfile -t subdomain_list < "$subdomains_file"
        # Add main domain to the beginning
        targets=("$domain" "${subdomain_list[@]}")
    fi
    
    echo "[*] Scanning ${#targets[@]} targets for gambling content..."
    
    # Load keywords
    mapfile -t keywords < "$judilist"
    echo "[*] Loaded ${#keywords[@]} gambling keywords"
    
    found_pages=()
    
    # Scan each target
    for target in "${targets[@]}"; do
        echo "[*] Scanning $target..."
        
        # Try both http and https
        for proto in "https" "http"; do
            url="$proto://$target"
            echo "  Checking $url..."
            
            # Get main page content
            content=$(curl -s "$url" --connect-timeout 5 --max-time 10 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
            if [ -z "$content" ]; then
                continue
            fi
            
            # Check for gambling keywords in main page
            for keyword in "${keywords[@]}"; do
                keyword=$(echo "$keyword" | xargs)  # Trim whitespace
                if [ -z "$keyword" ] || [[ "$keyword" =~ ^[[:space:]]*# ]]; then
                    continue
                fi
                
                if echo "$content" | grep -iq "$keyword"; then
                    echo -e "${RED}[!] Gambling content detected at $url (keyword: $keyword)${NC}"
                    found_pages+=("$url|$keyword")
                    break
                fi
            done
            
            # If main page has gambling content, don't scan further paths
            if echo "${found_pages[@]}" | grep -q "$url|"; then
                continue
            fi
            
            # Check common paths that might contain gambling content
            gambling_paths=(
                "" "index.html" "index.php" "home" "home.php" "main" "welcome"
                "play" "game" "games" "slot" "slots" "casino" "live-casino"
                "sports" "sport" "bet" "betting" "login" "register" "signup"
                "promo" "promotion" "bonus" "jackpot" "winner" "win"
            )
            
            for path in "${gambling_paths[@]}"; do
                if [ -n "$path" ]; then
                    check_url="$url/$path"
                else
                    check_url="$url"
                fi
                
                path_content=$(curl -s "$check_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
                if [ -z "$path_content" ]; then
                    continue
                fi
                
                # Check for keywords in path content
                for keyword in "${keywords[@]}"; do
                    keyword=$(echo "$keyword" | xargs)  # Trim whitespace
                    if [ -z "$keyword" ] || [[ "$keyword" =~ ^[[:space:]]*# ]]; then
                        continue
                    fi
                    
                    if echo "$path_content" | grep -iq "$keyword"; then
                        echo -e "${RED}[!] Gambling content detected at $check_url (keyword: $keyword)${NC}"
                        found_pages+=("$check_url|$keyword")
                        break
                    fi
                done
                
                # Break if we found gambling content on this target
                if echo "${found_pages[@]}" | grep -q "$url|"; then
                    break
                fi
            done
        done
    done
    
    # Save results
    if [ ${#found_pages[@]} -gt 0 ]; then
        judi_file="kinfo_judi_${domain}_$(date +%s).txt"
        {
            echo "Judi Online Finder Results"
            echo "Domain: $domain"
            echo "Scan Time: $(date)"
            echo "Targets Scanned: ${#targets[@]}"
            echo "Keywords Used: ${#keywords[@]}"
            echo "=================================="
            echo "URL|KEYWORD"
        } > "$judi_file"
        
        for item in "${found_pages[@]}"; do
            echo "$item" >> "$judi_file"
        done
        
        echo -e "${RED}[✓] Scan completed. Found ${#found_pages[@]} pages with gambling content.${NC}"
        echo "[*] Detailed results saved to: $judi_file"
        
        # Show results
        echo "[*] Found pages:"
        cat "$judi_file" | tail -n +6
    else
        echo -e "${GREEN}[✓] Scan completed. No gambling content found.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 5. Reverse IP Lookup (unchanged from previous version)
reverse_ip() {
    echo ""
    echo "[+] Reverse IP Lookup"
    echo "====================="
    read -p "Enter IP Address: " ipaddr

    if [[ ! $ipaddr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${RED}[!] Invalid IP format!${NC}"
        return 1
    fi
    
    echo "[*] Performing reverse IP lookup for $ipaddr..."
    
    # Method 1: Using viewdns.info API
    viewdns_url="https://viewdns.info/reverseip/?host=$ipaddr&t=1"
    response=$(curl -s "$viewdns_url" -H "User-Agent: Mozilla/5.0 KINFO/1.3")
    
    # Parse domains from table
    domains=$(echo "$response" | grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' | grep -v "$ipaddr" | sort -u)
    
    if [ -n "$domains" ]; then
        echo "$domains" > "/tmp/reverse_$ipaddr.txt"
        total=$(echo "$domains" | wc -l)
        echo -e "${GREEN}[✓] Found $total domains on $ipaddr${NC}"
        
        if [ $total -le 20 ]; then
            echo "[*] Domains:"
            echo "$domains"
        else
            echo "[*] First 20 domains:"
            echo "$domains" | head -20
            echo "[*] Full results saved to: /tmp/reverse_$ipaddr.txt"
        fi
    else
        # Method 2: Using whois as fallback
        echo "[*] Trying alternative method..."
        whois_result=$(whois "$ipaddr" 2>/dev/null | grep -i "domain\|netname")
        if [ -n "$whois_result" ]; then
            echo -e "${YELLOW}[!] Limited information from WHOIS:${NC}"
            echo "$whois_result"
        else
            echo -e "${RED}[!] No domains found for this IP${NC}"
        fi
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 6. Extract Domain [Auto Add HTTPS] (unchanged)
extract_domain() {
    echo ""
    echo "[+] Extract Domain & Auto Add HTTPS"
    echo "==================================="
    echo "Examples:"
    echo "  http://example.com/path"
    echo "  www.example.net/test/"
    echo "  test.google.co.id"
    echo ""
    read -p "Enter URL: " url
    
    if [ -z "$url" ]; then
        echo -e "${RED}[!] URL cannot be empty!${NC}"
        return 1
    fi
    
    # Extract domain using multiple methods
    extracted=$(echo "$url" | sed -E 's/^[^/]*\/\///' | cut -d'/' -f1 | sed 's/^www\.//')
    
    # Handle cases where protocol is missing
    if [[ "$url" != *"//"* ]]; then
        extracted=$(echo "$url" | cut -d'/' -f1 | sed 's/^www\.//')
    fi
    
    echo -e "Extracted domain: ${GREEN}$extracted${NC}"
    
    # Auto-add HTTPS
    full_url="https://$extracted"
    echo -e "Full HTTPS URL: ${BLUE}$full_url${NC}"
    
    # Test connectivity
    if command -v curl &> /dev/null; then
        echo "[*] Testing connection..."
        status_code=$(curl -sI "$full_url" --max-time 5 -o /tmp/curl_headers.txt -w "%{http_code}" -H "User-Agent: Mozilla/5.0 KINFO/1.3")
        
        if [[ "$status_code" =~ ^[23][0-9][0-9]$ ]]; then
            echo -e "${GREEN}[✓] Server responded with HTTP $status_code${NC}"
            
            # Check for security headers
            echo "[*] Security Headers Check:"
            grep -i "x-frame-options\|content-security-policy\|strict-transport-security" /tmp/curl_headers.txt || echo -e "${YELLOW}[!] No major security headers found${NC}"
        else
            echo -e "${RED}[!] Connection failed with HTTP $status_code${NC}"
        fi
        rm -f /tmp/curl_headers.txt
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 7. Webshell Finder [Dir Scan] (unchanged)
dir_scan_webshell() {
    echo ""
    echo "[+] Webshell Finder [Directory Scan]"
    echo "==================================="
    read -p "Enter target URL (e.g., https://target.com): " target_url
    
    if [ -z "$target_url" ]; then
        echo -e "${RED}[!] Target URL cannot be empty!${NC}"
        return 1
    fi
    
    # Validate and format URL
    if [[ ! "$target_url" =~ ^https?:// ]]; then
        target_url="https://$target_url"
    fi
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] cURL not found!${NC}"
        return 1
    fi

    echo "[*] Starting directory scan..."
    
    # Comprehensive webshell paths list (common ones)
    webshell_paths=(
        "shell.php" "backdoor.php" "cmd.php" "wso.php" "up.php" "upload.php"
        "sh.php" "phpinfo.php" "info.php" "test.php" "1.php" "wordpress.php"
        "IndoXploit.php" "b374k.php" "andela.php" "gaza.php" "marju.php"
        "pasir.php" "tai.php" "jembud.php" "404.php" "403.php" "index.php~"
        "config.php" ".env" ".htaccess" ".htpasswd" "backup.zip" "db.sql"
        "adminer.php" "phpMyAdmin/index.php" "pma/index.php" "mysql.php"
        "wp-config.php" "configuration.php" "settings.php" "web.config"
        "shell.jsp" "cmd.asp" "shell.aspx" "shell.jsp" ".git/config"
        "composer.json" "package.json" "yarn.lock" "README.md" "readme.html"
        "license.txt" "install.php" "upgrade.php" "update.php" "setup.php"
        "admin.php" "login.php" "wp-login.php" "administrator/index.php"
        "user/login" "users/login" "signin" "auth/login" "api/admin"
        "api/v1/admin" "api/v2/admin" "dashboard" "panel" "control"
        "manager" "adminpanel" "cpanel" "webmail" "mail" "email"
        "forum" "forums" "blog" "wiki" "shop" "store" "cart" "checkout"
        "payment" "pay" "secure" "ssl" "vpn" "api" "graphql" "soap"
        "rest" "v1" "v2" "mobile" "app" "application" "download" "downloads"
        "upload" "uploads" "file" "files" "image" "images" "img" "media"
        "video" "audio" "document" "documents" "pdf" "xls" "xlsx" "doc"
        "docx" "ppt" "pptx" "txt" "log" "logs" "temp" "tmp" "cache"
        "backup" "backups" "old" "new" "dev" "development" "test" "testing"
        "stage" "staging" "prod" "production" "api-docs" "swagger" "docs"
        "documentation" "help" "support" "contact" "about" "privacy" "terms"
        "legal" "status" "health" "metrics" "monitor" "monitoring" "stats"
        "statistics" "report" "reports" "analytics" "search" "find" "lookup"
        "query" "data" "database" "db" "mysql" "postgresql" "mongo" "redis"
        "elasticsearch" "kibana" "grafana" "prometheus" "jaeger" "zipkin"
        "jenkins" "gitlab" "github" "bitbucket" "docker" "kubernetes" "k8s"
        "aws" "azure" "gcp" "cloud" "storage" "s3" "bucket" "cdn" "edge"
        "node_modules" "vendor" "lib" "libs" "library" "libraries"
    )
    
    found_items=()
    checked=0
    total_paths=${#webshell_paths[@]}
    
    for path in "${webshell_paths[@]}"; do
        checked=$((checked + 1))
        full_scan_url="$target_url/$path"
        printf "${CYAN}[*] Checking %s (%d/%d)\r${NC}" "$path" "$checked" "$total_paths"
        
        # Check with different methods
        response=$(curl -sIL "$full_scan_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
        status_line=$(echo "$response" | head -n 1)
        status_code=$(echo "$status_line" | grep -oE '[0-9]{3}' | head -1)
        
        # Check for interesting responses
        if [[ "$status_code" =~ ^(200|301|302|401|403)$ ]]; then
            size=$(curl -s "$full_scan_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null | wc -c)
            content_type=$(echo "$response" | grep -i "content-type:" | head -1 | cut -d' ' -f2)
            
            # Highlight suspicious findings
            if [[ "$status_code" == "200" ]]; then
                echo -e "\n${GREEN}[!] FOUND: $full_scan_url (Status: $status_code, Size: $size bytes, Type: $content_type)${NC}"
                found_items+=("$full_scan_url|$status_code|$size|$content_type")
            elif [[ "$status_code" == "403" ]]; then
                echo -e "\n${YELLOW}[!] PROTECTED: $full_scan_url (Status: $status_code)${NC}"
                found_items+=("$full_scan_url|$status_code|N/A|N/A")
            else
                echo -e "\n${BLUE}[!] OTHER: $full_scan_url (Status: $status_code)${NC}"
                found_items+=("$full_scan_url|$status_code|N/A|N/A")
            fi
        fi
    done
    
    echo "" # New line after progress
    
    # Save results
    if [ ${#found_items[@]} -gt 0 ]; then
        scan_file="/tmp/webscan_$(date +%s).txt"
        {
            echo "Webshell/Dir Scan Results for: $target_url"
            echo "Scan performed on: $(date)"
            echo "=================================="
            echo "URL|STATUS|SIZE|CONTENT_TYPE"
        } > "$scan_file"
        
        for item in "${found_items[@]}"; do
            echo "$item" >> "$scan_file"
        done
        
        echo -e "${GREEN}[✓] Scan completed. Found ${#found_items[@]} items.${NC}"
        echo "[*] Detailed results saved to: $scan_file"
        
        # Show summary
        echo "[*] Summary:"
        cat "$scan_file" | tail -n +5 | head -10
        if [ ${#found_items[@]} -gt 10 ]; then
            echo "... and $((${#found_items[@]} - 10)) more items"
        fi
    else
        echo -e "${YELLOW}[-] No items found during scan.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 8. Webshell Finder [File Enumeration] (unchanged)
file_enum_webshell() {
    echo ""
    echo "[+] Webshell Finder [File Enumeration]"
    echo "====================================="
    read -p "Enter local directory path for scanning (or press Enter for current dir): " scan_dir
    
    if [ -z "$scan_dir" ]; then
        scan_dir="."
    fi
    
    if [ ! -d "$scan_dir" ]; then
        echo -e "${RED}[!] Directory does not exist: $scan_dir${NC}"
        return 1
    fi
    
    echo "[*] Scanning for suspicious PHP files in: $scan_dir"
    
    # Suspicious keywords commonly found in webshells
    suspicious_keywords=(
        "eval" "base64_decode" "gzinflate" "exec" "system" "passthru" 
        "shell_exec" "assert" "preg_replace.*\/e" "create_function" 
        "call_user_func" "call_user_func_array" "array_map" "ob_start" 
        "error_reporting\(0\)" "set_time_limit\(0\)" "ignore_user_abort"
        "\$_(POST|GET|REQUEST|COOKIE|SERVER)" "file_put_contents" 
        "fwrite" "fopen" "curl_exec" "file_get_contents" "include\|require"
        "chr\(" "ord\(" "hex2bin" "str_rot13" "strrev" "\\x[0-9a-fA-F]{2}"
        "GLOBALS" "FLAG" "password" "token" "key" "secret" "auth" "login"
    )
    
    detected_files=()
    php_files_count=0
    
    # Find all PHP files
    while IFS= read -r -d '' file; do
        php_files_count=$((php_files_count + 1))
        basename_file=$(basename "$file")
        printf "${CYAN}[*] Checking: %s\r${NC}" "$basename_file"
        
        # Check file size (skip very large files)
        file_size=$(stat -c%s "$file" 2>/dev/null || echo 0)
        if [ "$file_size" -gt 1000000 ]; then  # 1MB limit
            continue
        fi
        
        # Check for suspicious keywords
        for keyword in "${suspicious_keywords[@]}"; do
            if grep -qE "$keyword" "$file" 2>/dev/null; then
                # Get file info
                size=$(du -h "$file" 2>/dev/null | cut -f1)
                modified=$(stat -c %y "$file" 2>/dev/null | cut -d'.' -f1)
                detected_info="$file|$size|$modified|$keyword"
                
                # Avoid duplicates
                is_duplicate=false
                for df in "${detected_files[@]}"; do
                    df_path=$(echo "$df" | cut -d'|' -f1)
                    if [ "$df_path" == "$file" ]; then
                        is_duplicate=true
                        break
                    fi
                done
                
                if [ "$is_duplicate" = false ]; then
                    detected_files+=("$detected_info")
                    echo -e "\n${RED}[!] SUSPICIOUS FILE: $file${NC}"
                    echo "    Size: $size | Modified: $modified"
                    echo "    Keyword matched: $keyword"
                fi
                break
            fi
        done
    done < <(find "$scan_dir" -type f \( -iname "*.php" -o -iname "*.phtml" -o -iname "*.php3" -o -iname "*.php4" -o -iname "*.php5" -o -iname "*.inc" -o -iname "*.asp" -o -iname "*.aspx" -o -iname "*.jsp" \) -print0 2>/dev/null)
    
    echo "" # New line after progress
    
    # Report results
    if [ ${#detected_files[@]} -gt 0 ]; then
        enum_file="/tmp/webshell_enum_$(date +%s).txt"
        {
            echo "Webshell File Enumeration Results"
            echo "Directory: $scan_dir"
            echo "Scan Time: $(date)"
            echo "PHP Files Scanned: $php_files_count"
            echo "Suspicious Files Detected: ${#detected_files[@]}"
            echo "=================================="
            echo "FILE|SIZE|MODIFIED|KEYWORD"
        } > "$enum_file"
        
        for item in "${detected_files[@]}"; do
            echo "$item" >> "$enum_file"
        done
        
        echo -e "${RED}[✓] File enumeration completed. Found ${#detected_files[@]} suspicious files.${NC}"
        echo "[*] Detailed results saved to: $enum_file"
        
        # Show first 5 results
        echo "[*] First 5 suspicious files:"
        head -n 6 "$enum_file" | tail -n 5
        if [ ${#detected_files[@]} -gt 5 ]; then
            echo "... and $((${#detected_files[@]} - 5)) more files"
        fi
    else
        echo -e "${GREEN}[✓] File enumeration completed. No suspicious files detected.${NC}"
        echo "[*] Scanned $php_files_count PHP files"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}
# 9. ENV & Debug Method Scanner (unchanged)
env_debug_scan() {
    echo ""
    echo "[+] ENV & Debug Method Scanner"
    echo "=============================="
    read -p "Enter domain (without http/https): " env_domain
    
    if [ -z "$env_domain" ]; then
        echo -e "${RED}[!] Domain cannot be empty!${NC}"
        return 1
    fi
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] cURL not found!${NC}"
        return 1
    fi
    
    echo "[*] Scanning for ENV files and debug modes on $env_domain"
    
    # Common ENV and debug files
    env_files=(
        ".env" ".env.backup" ".env.local" ".env.example" "config/.env"
        "configuration.php" "settings.php" "database.php" "db.php"
        "wp-config.php" "config.php" "app/config/parameters.yml"
        "config/database.yml" ".htpasswd" ".htaccess" "web.config"
        "debug.php" "phpinfo.php" "info.php" "test.php" "test.html"
        "status" "health" "metrics" "actuator" "healthz" "readyz"
        "swagger" "api-docs" "v1/swagger" "v2/swagger" "docs"
        "backup.sql" "db.sql" "database.sql" "data.sql"
        "backup.tar.gz" "backup.zip" "backup.rar" "site.tar.gz"
        "composer.json" "package.json" "yarn.lock" "Gemfile"
        "Dockerfile" "docker-compose.yml" "Procfile" "requirements.txt"
        "robots.txt" "sitemap.xml" "crossdomain.xml" "clientaccesspolicy.xml"
        "server-status" "server-info" "jkstatus" "jkmanager"
        "CFIDE/administrator/index.cfm" "CFIDE/adminapi/base.cfc"
    )
    
    found_env=()
    checked=0
    total=${#env_files[@]}
    
    for path in "${env_files[@]}"; do
        checked=$((checked + 1))
        full_env_url="https://$env_domain/$path"
        printf "${CYAN}[*] Checking %s (%d/%d)\r${NC}" "$path" "$checked" "$total"
        
        # Special case for phpinfo
        if [[ "$path" == "phpinfo.php" ]]; then
            response=$(curl -sIL "$full_env_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
            status_line=$(echo "$response" | head -n 1)
            status_code=$(echo "$status_line" | grep -oE '[0-9]{3}' | head -1)
            
            if [[ "$status_code" == "200" ]]; then
                phpinfo_content=$(curl -s "$full_env_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
                if echo "$phpinfo_content" | grep -q "phpinfo()"; then
                    size=$(echo "$phpinfo_content" | wc -c)
                    echo -e "\n${RED}[!] PHPINFO EXPOSED: $full_env_url (Size: $size bytes)${NC}"
                    found_env+=("$full_env_url|PHPINFO|$size")
                fi
            fi
            continue
        fi
        
        # Regular file check
        response=$(curl -sIL "$full_env_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
        status_line=$(echo "$response" | head -n 1)
        status_code=$(echo "$status_line" | grep -oE '[0-9]{3}' | head -1)
        
        if [[ "$status_code" == "200" ]]; then
            size=$(curl -s "$full_env_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null | wc -c)
            content_type=$(echo "$response" | grep -i "content-type:" | head -1 | cut -d' ' -f2)
            
            # Check for sensitive files
            if echo "$path" | grep -qE "\.(env|sql|backup|tar\.gz|zip|rar)$"; then
                echo -e "\n${RED}[!] SENSITIVE FILE EXPOSED: $full_env_url (Size: $size bytes)${NC}"
                found_env+=("$full_env_url|SENSITIVE|$size")
            elif echo "$path" | grep -qE "\.(php|html|cfm)$"; then
                # Check for debug info
                debug_content=$(curl -s "$full_env_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
                if echo "$debug_content" | grep -qE "debug|stack trace|exception|error|environment"; then
                    echo -e "\n${RED}[!] DEBUG INFO EXPOSED: $full_env_url (Size: $size bytes)${NC}"
                    found_env+=("$full_env_url|DEBUG|$size")
                fi
            elif [[ "$content_type" =~ (text|json|xml) ]]; then
                # Check for configuration files
                echo -e "\n${YELLOW}[!] CONFIG FILE: $full_env_url (Size: $size bytes)${NC}"
                found_env+=("$full_env_url|CONFIG|$size")
            else
                echo -e "\n${BLUE}[!] FOUND: $full_env_url (Size: $size bytes, Type: $content_type)${NC}"
                found_env+=("$full_env_url|UNKNOWN|$size")
            fi
        fi
    done
    
    echo "" # New line after progress
    
    # Save results
    if [ ${#found_env[@]} -gt 0 ]; then
        env_file="/tmp/env_scan_$(date +%s).txt"
        {
            echo "ENV & Debug Scanner Results"
            echo "Domain: $env_domain"
            echo "Scan Time: $(date)"
            echo "=================================="
            echo "URL|TYPE|SIZE"
        } > "$env_file"
        
        for item in "${found_env[@]}"; do
            echo "$item" >> "$env_file"
        done
        
        echo -e "${RED}[✓] Scan completed. Found ${#found_env[@]} items.${NC}"
        echo "[*] Detailed results saved to: $env_file"
        
        # Show results
        echo "[*] Found items:"
        cat "$env_file" | tail -n +5
    else
        echo -e "${GREEN}[✓] Scan completed. No sensitive files or debug info found.${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 10. WordPress Registration Finder (unchanged)
wp_registrar_finder() {
    echo ""
    echo "[+] WordPress Registration Finder"
    echo "================================="
    read -p "Enter domain (without http/https): " wp_domain
    
    if [ -z "$wp_domain" ]; then
        echo -e "${RED}[!] Domain cannot be empty!${NC}"
        return 1
    fi
    
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}[!] cURL not found!${NC}"
        return 1
    fi
    
    echo "[*] Checking WordPress registration for $wp_domain"
    
    # Check if it's a WordPress site
    wp_url="https://$wp_domain"
    response=$(curl -sIL "$wp_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
    
    if ! echo "$response" | grep -qi "wp-content\|wordpress"; then
        echo -e "${YELLOW}[!] This doesn't appear to be a WordPress site${NC}"
        read -p "Continue anyway? (y/N): " continue_anyway
        if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Common registration URLs
    reg_paths=(
        "wp-login.php?action=register"
        "wp-signup.php"
        "register"
        "signup"
        "create-account"
        "join"
        "registration"
        "register.html"
        "signup.html"
        "auth/register"
        "user/register"
        "users/register"
        "account/register"
        "new-user"
        "wp-admin/user-new.php"
    )
    
    found_reg=()
    for path in "${reg_paths[@]}"; do
        full_reg_url="$wp_url/$path"
        response=$(curl -sIL "$full_reg_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
        status_code=$(echo "$response" | head -1 | grep -oE '[0-9]{3}' | head -1)
        
        if [[ "$status_code" == "200" ]]; then
            reg_content=$(curl -s "$full_reg_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
            # Check for registration form
            if echo "$reg_content" | grep -qi "register\|signup\|username\|password\|email"; then
                echo -e "${GREEN}[✓] Registration page found: $full_reg_url${NC}"
                found_reg+=("$full_reg_url")
                break
            fi
        fi
    done
    
    if [ ${#found_reg[@]} -eq 0 ]; then
        echo -e "${YELLOW}[-] No registration page found${NC}"
        
        # Check if registration is disabled
        default_reg_url="$wp_url/wp-login.php"
        default_content=$(curl -s "$default_reg_url" --connect-timeout 3 --max-time 5 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
        if echo "$default_content" | grep -qi "registration is disabled\|not allowed"; then
            echo -e "${BLUE}[i] Registration appears to be disabled on this site${NC}"
        fi
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 11. Grab Domain from Zone-H (unchanged)
grab_zoneh_domains() {
    echo ""
    echo "[+] Grab Domain from Zone-H"
    echo "==========================="
    read -p "Enter Zone-H notifier name: " notifier
    
    if [ -z "$notifier" ]; then
        echo -e "${RED}[!] Notifier name cannot be empty!${NC}"
        return 1
    fi
    
    zoneh_url="http://www.zone-h.org/archive/notifier=$notifier"
    
    echo "[*] Fetching domains from Zone-H for notifier: $notifier"
    
    # Fetch content
    response=$(curl -s "$zoneh_url" --connect-timeout 10 --max-time 15 -H "User-Agent: Mozilla/5.0 KINFO/1.3" 2>/dev/null)
    
    if [ -z "$response" ]; then
        echo -e "${RED}[!] Failed to fetch data from Zone-H${NC}"
        return 1
    fi
    
    # Parse domains
    domains=$(echo "$response" | grep -oP '(?<=<td>)[a-zA-Z0-9\-\.]+(?=</td>)' | grep -v "Domain" | sort -u)
    
    if [ -n "$domains" ]; then
        domain_count=$(echo "$domains" | wc -l)
        echo -e "${GREEN}[✓] Found $domain_count domains${NC}"
        
        # Save to file
        zoneh_file="/tmp/zoneh_domains_${notifier}_$(date +%s).txt"
        echo "$domains" > "$zoneh_file"
        echo "[*] Domains saved to: $zoneh_file"
        
        # Show first 20 domains
        if [ $domain_count -le 20 ]; then
            echo "[*] Domains:"
            echo "$domains"
        else
            echo "[*] First 20 domains:"
            echo "$domains" | head -20
            echo "... and $((domain_count - 20)) more domains"
        fi
    else
        echo -e "${YELLOW}[-] No domains found for this notifier${NC}"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# 12. Mini Shell FTP Client (unchanged)
mini_ftp_client() {
    echo ""
    echo "[+] Mini Shell FTP Client"
    echo "========================="
    read -p "Enter FTP host: " ftp_host
    read -p "Enter FTP port (default 21): " ftp_port
    read -p "Enter username: " ftp_user
    read -sp "Enter password: " ftp_pass
    echo ""
    
    if [ -z "$ftp_host" ] || [ -z "$ftp_user" ]; then
        echo -e "${RED}[!] Host and username cannot be empty!${NC}"
        return 1
    fi
    
    if [ -z "$ftp_port" ]; then
        ftp_port=21
    fi
    
    if ! command -v ftp &> /dev/null; then
        echo -e "${RED}[!] FTP client not found!${NC}"
        return 1
    fi
    
    echo ""
    echo "FTP Client Commands:"
    echo "ls                 - List files"
    echo "cd <dir>           - Change directory"
    echo "pwd                - Print working directory"
    echo "get <file>         - Download file"
    echo "put <file>         - Upload file"
    echo "mkdir <dir>        - Create directory"
    echo "rmdir <dir>        - Remove directory"
    echo "delete <file>      - Delete file"
    echo "rename <old> <new> - Rename file"
    echo "binary             - Set binary mode"
    echo "ascii              - Set ASCII mode"
    echo "passive            - Set passive mode"
    echo "exit               - Exit FTP client"
    echo "=============================="
    
    # Create a temporary script for FTP session
    ftp_script="/tmp/ftp_session_$$.txt"
    ftp_output="/tmp/ftp_output_$$.txt"
    
    # Initial connection commands
    {
        echo "open $ftp_host $ftp_port"
        echo "user $ftp_user $ftp_pass"
        echo "passive"
        echo "binary"
    } > "$ftp_script"
    
    while true; do
        echo ""
        read -p "ftp> " ftp_command
        
        # Exit condition
        if [[ "$ftp_command" == "exit" ]]; then
            # Append quit command to script
            echo "quit" >> "$ftp_script"
            break
        fi
        
        # Handle special commands
        if [[ "$ftp_command" == "get "* ]]; then
            # For download commands, we'll execute immediately
            echo "$ftp_command" >> "$ftp_script"
            echo "quit" >> "$ftp_script"
            
            # Execute and capture output
            ftp -n < "$ftp_script" > "$ftp_output" 2>&1
            
            # Check for success
            if grep -q "226 Transfer complete\|150 Opening" "$ftp_output"; then
                filename=$(echo "$ftp_command" | cut -d' ' -f2)
                echo -e "${GREEN}[✓] Downloaded: $filename${NC}"
            else
                echo -e "${RED}[!] Download failed${NC}"
                cat "$ftp_output"
            fi
            
            # Reset script file for next command
            {
                echo "open $ftp_host $ftp_port"
                echo "user $ftp_user $ftp_pass"
                echo "passive"
                echo "binary"
            } > "$ftp_script"
        elif [[ "$ftp_command" == "put "* ]]; then
            filename=$(echo "$ftp_command" | cut -d' ' -f2)
            if [ ! -f "$filename" ]; then
                echo -e "${RED}[!] File not found: $filename${NC}"
                continue
            fi
            
            # Append command and quit
            echo "$ftp_command" >> "$ftp_script"
            echo "quit" >> "$ftp_script"
            
            # Execute
            ftp -n < "$ftp_script" > "$ftp_output" 2>&1
            
            if grep -q "226 Transfer complete\|150 Opening" "$ftp_output"; then
                echo -e "${GREEN}[✓] Uploaded: $filename${NC}"
            else
                echo -e "${RED}[!] Upload failed${NC}"
                cat "$ftp_output"
            fi
            
            # Reset script
            {
                echo "open $ftp_host $ftp_port"
                echo "user $ftp_user $ftp_pass"
                echo "passive"
                echo "binary"
            } > "$ftp_script"
        else
            # For other commands, append to script
            echo "$ftp_command" >> "$ftp_script"
        fi
    done
    
    # If we have additional commands besides just the initial connection, execute them
    if [ $(wc -l < "$ftp_script") -gt 4 ]; then
        # Add quit command if not already there
        if ! tail -1 "$ftp_script" | grep -q "quit"; then
            echo "quit" >> "$ftp_script"
        fi
        
        echo "[*] Executing FTP commands..."
        ftp -n < "$ftp_script" > "$ftp_output" 2>&1
        
        # Show output for non-download/upload commands
        if ! grep -q "get\|put" "$ftp_script"; then
            cat "$ftp_output"
        fi
    fi
    
    # Clean up temporary files
    rm -f "$ftp_script" "$ftp_output"
    
    echo ""
    read -p "Press Enter to continue..."
}

# 13. Back to Main Menu (updated)
back_to_menu() {
    echo ""
    echo -e "${YELLOW}[i] Returning to main menu...${NC}"
    sleep 1
    return 0
}

# Main execution loop
main() {
    while true; do
        show_banner
        show_menu
        
        case $pilihan in
            1)
                enhanced_subdomain_finder
                ;;
            2)
                dir_file_enum
                ;;
            3)
                ftp_bruteforce
                ;;
            4)
                judi_online_finder
                ;;
            5)
                reverse_ip
                ;;
            6)
                extract_domain
                ;;
            7)
                dir_scan_webshell
                ;;
            8)
                file_enum_webshell
                ;;
            9)
                env_debug_scan
                ;;
            10)
                wp_registrar_finder
                ;;
            11)
                grab_zoneh_domains
                ;;
            12)
                mini_ftp_client
                ;;
            13)
                back_to_menu
                break
                ;;
            *)
                echo -e "${RED}[!] Invalid option. Please select 1-13${NC}"
                sleep 2
                ;;
        esac
    done
}

# Run the script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Check for dependencies
    dependencies=(curl grep find stat)
    missing_deps=()
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing dependencies: ${missing_deps[*]}${NC}"
        echo "Please install them to use this tool."
        exit 1
    fi
    
    main "$@"
fi
