#!/bin/bash

# ============================================================
#  AXIOS COMPROMISE CHECKER - March 31, 2026
#  Supply Chain Attack Detection Script
#  
#  Detects: axios@1.14.1 & axios@0.30.4 (malicious versions)
#  Malicious dependency: plain-crypto-js@4.2.1
#  Payload: Cross-platform RAT (macOS, Windows, Linux)
#  C2 Server: sfrclak[.]com / 142.11.206.73:8000
#
#  Reference: https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
#  Advisory:  SNYK-JS-AXIOS-15850650
#
#  Usage: sudo bash check_axios_compromise.sh
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

COMPROMISED=0
WARNINGS=0

echo ""
echo "============================================================"
echo -e "${BOLD}  AXIOS COMPROMISE CHECKER - March 31, 2026${NC}"
echo -e "  Supply Chain Attack Detection Script"
echo "============================================================"
echo ""
echo -e "${BLUE}[INFO]${NC} Starting full system scan..."
echo -e "${BLUE}[INFO]${NC} Scan date  : $(date)"
echo -e "${BLUE}[INFO]${NC} Hostname   : $(hostname)"
echo -e "${BLUE}[INFO]${NC} OS         : $(uname -s) $(uname -r)"
echo -e "${BLUE}[INFO]${NC} User       : $(whoami)"
echo ""

# ============================================================
# 1. CHECK FOR MALWARE FILES ON DISK
# ============================================================
echo "------------------------------------------------------------"
echo -e "${BOLD}1/6 - CHECKING FOR KNOWN MALWARE FILES${NC}"
echo "------------------------------------------------------------"

# Linux RAT payload
if [ -f "/tmp/ld.py" ]; then
    echo -e "  ${RED}[CRITICAL]${NC} Malicious file found: /tmp/ld.py"
    echo -e "  ${RED}           >>> SYSTEM IS COMPROMISED <<<${NC}"
    COMPROMISED=1
else
    echo -e "  ${GREEN}[OK]${NC} No /tmp/ld.py found"
fi

# macOS RAT payload
if [ -f "/Library/Caches/com.apple.act.mond" ]; then
    echo -e "  ${RED}[CRITICAL]${NC} Malicious macOS binary found: /Library/Caches/com.apple.act.mond"
    COMPROMISED=1
else
    echo -e "  ${GREEN}[OK]${NC} No macOS malware binary found"
fi

# Windows payload (WSL environments)
if [ -f "/mnt/c/ProgramData/wt.exe" ]; then
    echo -e "  ${RED}[CRITICAL]${NC} Malicious Windows binary found: %PROGRAMDATA%\\wt.exe"
    COMPROMISED=1
else
    echo -e "  ${GREEN}[OK]${NC} No Windows malware binary found"
fi

# Active ld.py process
if ps aux 2>/dev/null | grep -v grep | grep -q "ld.py"; then
    echo -e "  ${RED}[CRITICAL]${NC} Malicious process ld.py is RUNNING:"
    ps aux | grep -v grep | grep "ld.py" | sed 's/^/           /'
    COMPROMISED=1
else
    echo -e "  ${GREEN}[OK]${NC} No ld.py process running"
fi

# Suspicious python processes in /tmp
if ps aux 2>/dev/null | grep -v grep | grep -q "python.*/tmp/"; then
    echo -e "  ${YELLOW}[WARNING]${NC} Suspicious Python process running from /tmp:"
    ps aux | grep -v grep | grep "python.*/tmp/" | sed 's/^/           /'
    WARNINGS=$((WARNINGS+1))
else
    echo -e "  ${GREEN}[OK]${NC} No suspicious Python processes in /tmp"
fi

echo ""

# ============================================================
# 2. CHECK NETWORK CONNECTIONS TO C2 SERVER
# ============================================================
echo "------------------------------------------------------------"
echo -e "${BOLD}2/6 - CHECKING NETWORK CONNECTIONS TO C2 SERVER${NC}"
echo "------------------------------------------------------------"

C2_IP="142.11.206.73"
C2_DOMAIN="sfrclak"

if command -v ss &>/dev/null; then
    if ss -tp 2>/dev/null | grep -q "$C2_IP"; then
        echo -e "  ${RED}[CRITICAL]${NC} Active connection to attacker IP ($C2_IP) detected!"
        ss -tp 2>/dev/null | grep "$C2_IP" | sed 's/^/           /'
        COMPROMISED=1
    else
        echo -e "  ${GREEN}[OK]${NC} No active connection to $C2_IP"
    fi

    if ss -tp 2>/dev/null | grep -q "$C2_DOMAIN"; then
        echo -e "  ${RED}[CRITICAL]${NC} Active connection to ${C2_DOMAIN}.com detected!"
        COMPROMISED=1
    else
        echo -e "  ${GREEN}[OK]${NC} No active connection to ${C2_DOMAIN}.com"
    fi
elif command -v netstat &>/dev/null; then
    if netstat -an 2>/dev/null | grep -q "$C2_IP"; then
        echo -e "  ${RED}[CRITICAL]${NC} Connection to attacker IP ($C2_IP) detected!"
        COMPROMISED=1
    else
        echo -e "  ${GREEN}[OK]${NC} No connection to $C2_IP"
    fi
else
    echo -e "  ${YELLOW}[WARNING]${NC} Neither 'ss' nor 'netstat' available — cannot check connections"
    WARNINGS=$((WARNINGS+1))
fi

# Check system logs
if grep -rq "$C2_DOMAIN" /var/log/ 2>/dev/null; then
    echo -e "  ${RED}[CRITICAL]${NC} Traces of ${C2_DOMAIN}.com found in system logs!"
    grep -rl "$C2_DOMAIN" /var/log/ 2>/dev/null | sed 's/^/           /'
    COMPROMISED=1
else
    echo -e "  ${GREEN}[OK]${NC} No traces in system logs"
fi

echo ""

# ============================================================
# 3. SCAN ALL LOCKFILES FOR COMPROMISED AXIOS VERSIONS
# ============================================================
echo "------------------------------------------------------------"
echo -e "${BOLD}3/6 - SCANNING ALL LOCKFILES FOR COMPROMISED AXIOS${NC}"
echo "------------------------------------------------------------"
echo -e "  ${BLUE}[INFO]${NC} Scanning filesystem (this may take a few minutes)..."

FOUND_BAD_AXIOS=0

# package-lock.json
while IFS= read -r lockfile; do
    if grep -q "axios" "$lockfile" 2>/dev/null; then
        if grep -E '"axios"' "$lockfile" 2>/dev/null | grep -qE '1\.14\.1|0\.30\.4'; then
            echo -e "  ${RED}[CRITICAL]${NC} Compromised axios version in:"
            echo -e "           ${RED}$lockfile${NC}"
            grep -E '"axios"' "$lockfile" 2>/dev/null | grep -E '1\.14\.1|0\.30\.4' | head -3 | sed 's/^/           /'
            FOUND_BAD_AXIOS=1
            COMPROMISED=1
        fi
    fi
done < <(find / -name "package-lock.json" -not -path "*/\.git/*" 2>/dev/null)

# yarn.lock
while IFS= read -r lockfile; do
    if grep -q "axios" "$lockfile" 2>/dev/null; then
        if grep -E 'axios@' "$lockfile" 2>/dev/null | grep -qE '1\.14\.1|0\.30\.4'; then
            echo -e "  ${RED}[CRITICAL]${NC} Compromised axios version in:"
            echo -e "           ${RED}$lockfile${NC}"
            FOUND_BAD_AXIOS=1
            COMPROMISED=1
        fi
    fi
done < <(find / -name "yarn.lock" -not -path "*/\.git/*" 2>/dev/null)

# bun.lock
while IFS= read -r lockfile; do
    if grep -q "axios" "$lockfile" 2>/dev/null; then
        if grep -E 'axios' "$lockfile" 2>/dev/null | grep -qE '1\.14\.1|0\.30\.4'; then
            echo -e "  ${RED}[CRITICAL]${NC} Compromised axios version in:"
            echo -e "           ${RED}$lockfile${NC}"
            FOUND_BAD_AXIOS=1
            COMPROMISED=1
        fi
    fi
done < <(find / -name "bun.lock" -not -path "*/\.git/*" 2>/dev/null)

if [ "$FOUND_BAD_AXIOS" -eq 0 ]; then
    echo -e "  ${GREEN}[OK]${NC} No lockfile contains axios@1.14.1 or axios@0.30.4"
fi

echo ""

# ============================================================
# 4. SEARCH FOR MALICIOUS DEPENDENCY: plain-crypto-js
# ============================================================
echo "------------------------------------------------------------"
echo -e "${BOLD}4/6 - SEARCHING FOR MALICIOUS DEPENDENCY (plain-crypto-js)${NC}"
echo "------------------------------------------------------------"

FOUND_PLAIN_CRYPTO=0

# In node_modules
while IFS= read -r dir; do
    echo -e "  ${RED}[CRITICAL]${NC} Malicious dependency installed:"
    echo -e "           ${RED}$dir${NC}"
    FOUND_PLAIN_CRYPTO=1
    COMPROMISED=1
done < <(find / -type d -name "plain-crypto-js" -not -path "*/\.git/*" 2>/dev/null)

# In lockfiles and package.json
while IFS= read -r file; do
    if grep -q "plain-crypto-js" "$file" 2>/dev/null; then
        echo -e "  ${RED}[CRITICAL]${NC} plain-crypto-js referenced in:"
        echo -e "           ${RED}$file${NC}"
        FOUND_PLAIN_CRYPTO=1
        COMPROMISED=1
    fi
done < <(find / \( -name "package-lock.json" -o -name "yarn.lock" -o -name "bun.lock" -o -name "package.json" \) -not -path "*/\.git/*" 2>/dev/null)

if [ "$FOUND_PLAIN_CRYPTO" -eq 0 ]; then
    echo -e "  ${GREEN}[OK]${NC} No trace of plain-crypto-js anywhere"
fi

echo ""

# ============================================================
# 5. CHECK FOR OTHER COMPROMISED PACKAGES
# ============================================================
echo "------------------------------------------------------------"
echo -e "${BOLD}5/6 - CHECKING FOR RELATED COMPROMISED PACKAGES${NC}"
echo "------------------------------------------------------------"

FOUND_OTHER=0

while IFS= read -r file; do
    if grep -qE "openclaw-qbot|shadanai/openclaw" "$file" 2>/dev/null; then
        echo -e "  ${RED}[CRITICAL]${NC} Related compromised package found in:"
        echo -e "           ${RED}$file${NC}"
        FOUND_OTHER=1
        COMPROMISED=1
    fi
done < <(find / \( -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" \) -not -path "*/\.git/*" 2>/dev/null | head -1000)

if [ "$FOUND_OTHER" -eq 0 ]; then
    echo -e "  ${GREEN}[OK]${NC} No trace of @qqbrowser/openclaw-qbot or @shadanai/openclaw"
fi

echo ""

# ============================================================
# 6. INVENTORY OF ALL INSTALLED AXIOS VERSIONS
# ============================================================
echo "------------------------------------------------------------"
echo -e "${BOLD}6/6 - INVENTORY OF ALL INSTALLED AXIOS VERSIONS${NC}"
echo "------------------------------------------------------------"

FOUND_AXIOS=0
while IFS= read -r pkg; do
    VERSION=$(grep -o '"version": *"[^"]*"' "$pkg" 2>/dev/null | head -1 | grep -o '"[^"]*"$' | tr -d '"')
    DIR=$(dirname "$pkg")
    if [ -n "$VERSION" ]; then
        if echo "$VERSION" | grep -qE '^1\.14\.1$|^0\.30\.4$'; then
            echo -e "  ${RED}[DANGER]${NC} axios@${VERSION} → ${DIR}"
            COMPROMISED=1
        else
            echo -e "  ${GREEN}[SAFE]${NC}   axios@${VERSION} → ${DIR}"
        fi
        FOUND_AXIOS=1
    fi
done < <(find / -path "*/node_modules/axios/package.json" -not -path "*/\.git/*" 2>/dev/null)

if [ "$FOUND_AXIOS" -eq 0 ]; then
    echo -e "  ${BLUE}[INFO]${NC} No axios installations found in node_modules"
fi

echo ""

# ============================================================
# FINAL REPORT
# ============================================================
echo "============================================================"
if [ "$COMPROMISED" -eq 1 ]; then
    echo ""
    echo -e "  ${RED}${BOLD}  !!! ALERT: COMPROMISE DETECTED !!!${NC}"
    echo ""
    echo -e "  ${RED}${BOLD}  IMMEDIATE ACTIONS REQUIRED:${NC}"
    echo ""
    echo -e "  ${RED}  1. CRYPTO WALLETS: Move all funds IMMEDIATELY${NC}"
    echo -e "  ${RED}     to a wallet on a CLEAN device${NC}"
    echo ""
    echo -e "  ${RED}  2. ROTATE ALL SECRETS: API keys, SSH keys,${NC}"
    echo -e "  ${RED}     tokens, passwords, cloud credentials —${NC}"
    echo -e "  ${RED}     revoke and reissue EVERYTHING${NC}"
    echo ""
    echo -e "  ${RED}  3. ISOLATE: Disconnect this machine from${NC}"
    echo -e "  ${RED}     the network if possible${NC}"
    echo ""
    echo -e "  ${RED}  4. REBUILD: Do NOT attempt to clean the${NC}"
    echo -e "  ${RED}     system — rebuild from a clean image${NC}"
    echo ""
    echo -e "  ${RED}  5. EMERGENCY KILL (buys time, not a fix):${NC}"
    echo -e "  ${RED}     pkill -f ld.py${NC}"
    echo -e "  ${RED}     rm -f /tmp/ld.py${NC}"
    echo ""
    echo -e "  ${RED}  6. AUDIT: Review CI/CD build logs for the${NC}"
    echo -e "  ${RED}     March 31, 2026 00:21–03:29 UTC window${NC}"
    echo ""
elif [ "$WARNINGS" -gt 0 ]; then
    echo ""
    echo -e "  ${YELLOW}${BOLD}  RESULT: NO CONFIRMED COMPROMISE${NC}"
    echo -e "  ${YELLOW}  But $WARNINGS warning(s) need manual review${NC}"
    echo ""
else
    echo ""
    echo -e "  ${GREEN}${BOLD}  ✓ RESULT: NO COMPROMISE DETECTED${NC}"
    echo ""
    echo -e "  ${GREEN}  Your system appears clean.${NC}"
    echo ""
    echo -e "  ${BLUE}  RECOMMENDED PRECAUTIONS:${NC}"
    echo -e "  ${BLUE}  - Pin axios to a safe version in package.json${NC}"
    echo -e "  ${BLUE}  - Always commit your lockfile${NC}"
    echo -e "  ${BLUE}  - Use 'npm ci' instead of 'npm install' in CI/CD${NC}"
    echo -e "  ${BLUE}  - Consider 'npm ci --ignore-scripts' in pipelines${NC}"
    echo ""
fi
echo "============================================================"
echo ""
echo -e "${BLUE}[INFO]${NC} Scan complete."
echo -e "${BLUE}[INFO]${NC} Reference: https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/"
echo -e "${BLUE}[INFO]${NC} Advisory:  SNYK-JS-AXIOS-15850650"
echo ""
