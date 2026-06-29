#!/bin/bash

# Color codes for visual output
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <domain.com>${RESET}"
    exit 1
fi

DOMAIN=$1
TARGET_NAME=$(echo "$DOMAIN" | cut -d'.' -f1)
OUTPUT_DIR="infoleak_advanced_$DOMAIN"

echo -e "${CYAN}[+] Starting Advanced Information Disclosure Recon for: $DOMAIN${RESET}"
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit

# Prerequisites Check
for cmd in subfinder httpx gau katana nuclei; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}[!] Error: $cmd is not installed. Please install it first.${RESET}"
        exit 1
    fi
done

# -------------------------------------------------------------------------
# Step 1: Gathering Live Hosts & Endpoints (Patched for Apex Domains)
# -------------------------------------------------------------------------
echo -e "${GREEN}[*] Step 1: Enumerating subdomains and passive assets...${RESET}"
subfinder -d "$DOMAIN" -silent > subdomains.txt

# CRITICAL FIX: Agar subdomains file khali hai, toh apex domain ko khud dynamic resource list mein add karo
if [ ! -s subdomains.txt ]; then
    echo "$DOMAIN" > subdomains.txt
else
    # Agar subdomains mile hain, toh bhi fallback safety ke liye main domain list mein hamesha rakho
    echo "$DOMAIN" >> subdomains.txt
fi

# Filter out live interfaces
httpx -l subdomains.txt -silent -threads 50 -o live_hosts.txt

echo -e "${GREEN}[*] Step 2: Extracting historic & dynamic URLs (GAU + Katana)...${RESET}"

# FIX: Gau run without broken --silent, output formatting directly managed
if [ -s live_hosts.txt ]; then
    cat live_hosts.txt | gau --threads 30 > gau_urls.txt
    # FIX: Naming convention synced (Purani script me katana_urls.txt create hone me discrepancy thi)
    katana -list live_hosts.txt -jc -kf all -silent -concurrency 20 -o katana_urls.txt
else
    touch gau_urls.txt katana_urls.txt
fi

# Merge and unique sort (Removing static media to reduce parsing loads)
cat gau_urls.txt katana_urls.txt 2>/dev/null | grep -E -v -i "\.(png|jpg|jpeg|gif|svg|woff|woff2|ttf|css|ico)$" | sort -u > all_endpoints.txt
echo -e "${CYAN}[✓] Total Unique Clean Endpoints Collected: $(wc -l < all_endpoints.txt)${RESET}"

# -------------------------------------------------------------------------
# Step 2: Information Disclosure - Smart Filtering & Isolation
# -------------------------------------------------------------------------
echo -e "${GREEN}[*] Step 3: Classifying Assets & Filtering Noise...${RESET}"

# 1. API Endpoints
grep -E -i "api/v[0-9]|/api/|graphql|/rest/v[0-9]|wp-json" all_endpoints.txt > api_endpoints.txt

# 2. Third-Party Leaks
grep -E -i "s3\.amazonaws\.com|firebaseio\.com|blob\.core\.windows\.net|github\.com|jira\." all_endpoints.txt > third_party_leaks.txt

# 3. High-Risk Files
grep -E -i "\.(env|git|bak|conf|log|sql|ini|old|zip|tar\.gz|db|configuration|properties)$" all_endpoints.txt > sensitive_files.txt

# 4. Standard/Low-Risk JSON/Manifests
grep -E -i "\.(json|manifest|yml|yaml)$" all_endpoints.txt | grep -E -v -i "(config|credential|secret|auth|admin)" > public_json_files.txt

# 5. JavaScript Files
grep -E -i "\.js(\?|$)" all_endpoints.txt | sort -u > javascript_files.txt

# -------------------------------------------------------------------------
# NEW: IDOR, Access Control & Auth Target Isolation
# -------------------------------------------------------------------------
echo -e "${GREEN}[*] Isolate Targets for IDOR, Access Control & Authentication...${RESET}"

# 1. Potential IDOR Parameters & Resource Tracking (Isolating query parameters with numeric or generic IDs)
grep -E -i "(\?|&)(id|uid|user|account|profile|doc|order|invoice|file|uuid|number|key|invoice_id|customer|cust_id)=" all_endpoints.txt | sort -u > idor_parameter_targets.txt

# 2. Access Control & Identity Dashboard Endpoints (Paths handling account contexts or privilege settings)
grep -E -i "/(account|settings|profile|dashboard|admin|manage|update|edit|delete|remove|invoice|billing|download|checkout)/" all_endpoints.txt | sort -u > access_control_paths.txt

# 3. Authentication & Session Management Endpoints (Paths checking tokens, sessions, or logins)
grep -E -i "/(auth|login|signin|signup|register|token|session|logout|forgot-password|reset-password|verify)/" all_endpoints.txt | sort -u > authentication_targets.txt

touch idor_parameter_targets.txt access_control_paths.txt authentication_targets.txt
# -------------------------------------------------------------------------
# Step 3: Active Vulnerability Verification & Secrets Scanning
# -------------------------------------------------------------------------
echo -e "${GREEN}[*] Step 4: Validating live exposures and active scanning...${RESET}"

# Validate sensitive files via httpx
if [ -s sensitive_files.txt ]; then
    httpx -l sensitive_files.txt -status-code -mc 200 -silent -title -o verified_high_leaks.txt
else
    touch verified_high_leaks.txt
fi

# FIX: Nuclei command optimized with correct synchronization to avoid max-host errors
echo -e "${GREEN}[*] Step 5: Running Nuclei for Hardcoded Tokens & Exposed Panels...${RESET}"
if [ -s javascript_files.txt ]; then
    nuclei -l javascript_files.txt -tags token,exposure,secrets -silent -c 50 -max-host-error 50 -o js_leaked_secrets.txt
fi

if [ -s live_hosts.txt ]; then
    nuclei -l live_hosts.txt -tags config,exposure,git,env -severity low,medium,high,critical -silent -c 50 -max-host-error 50 -o nuclei_infrastructure_leaks.txt
fi

# -------------------------------------------------------------------------
# Summary Report
# -------------------------------------------------------------------------
echo -e "\n${CYAN}==================== ADVANCED SCAN SUMMARY ====================${RESET}"
echo -e "${GREEN}[✓] API Endpoints Found: $(wc -l < api_endpoints.txt)${RESET}"
echo -e "${GREEN}[✓] Third-Party Links Leaked: $(wc -l < third_party_leaks.txt)${RESET}"
echo -e "${GREEN}[✓] Raw JavaScript Files: $(wc -l < javascript_files.txt)${RESET}"
echo -e "${YELLOW}[✓] Filtered Public JSON Assets: $(wc -l < public_json_files.txt)${RESET}"
echo -e "${YELLOW}[✓] Potential IDOR Targets Found: $(wc -l < idor_parameter_targets.txt)${RESET}"
echo -e "${YELLOW}[✓] Access Control Paths Isolated: $(wc -l < access_control_paths.txt)${RESET}"
echo -e "${YELLOW}[✓] Auth/Session Management Endpoints: $(wc -l < authentication_targets.txt)${RESET}"
echo -e "--------------------------------------------------------------"
if [ -s verified_high_leaks.txt ]; then
    echo -e "${RED}[⚠️ CRITICAL] Verified High-Risk File Exposures: $(wc -l < verified_high_leaks.txt)${RESET} -> check verified_high_leaks.txt"
fi
if [ -s js_leaked_secrets.txt ]; then
    echo -e "${RED}[⚠️ CRITICAL] Hardcoded Secrets Found in JS: $(wc -l < js_leaked_secrets.txt)${RESET} -> check js_leaked_secrets.txt"
fi
if [ -s nuclei_infrastructure_leaks.txt ]; then
    echo -e "${RED}[⚠️ CRITICAL] Nuclei Infrastructure Leaks Detected: $(wc -l < nuclei_infrastructure_leaks.txt)${RESET} -> check nuclei_infrastructure_leaks.txt"
fi
echo -e "${CYAN}==============================================================${RESET}"
