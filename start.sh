#!/bin/bash

# ============================================================================
# REDHAVEN 1.0.3 — Offensive Bug Bounty Framework
# Elite Red Team Edition • by darkne55
# ============================================================================

# ----------------- COLORES & ESTILO (RED TEAM) -----------------
PRIMARY='\033[1;31m'     # Rojo profundo
ACCENT='\033[1;91m'      # Rojo brillante
WARN='\033[1;33m'
ERROR='\033[1;31m'
TITLE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ----------------- LAYOUT -----------------
BANNER_WIDTH=79
MENU_WIDTH=70

# ----------------- BUILD / SIGNATURE -----------------
BUILD_ID="$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo local)"
OPERATOR="$(whoami)"
HOSTNAME="$(hostname)"


# ----------------- UTILIDADES UI -----------------
sep() {
  printf '%*s\n' "$BANNER_WIDTH" '' | tr ' ' '─'
}

center_ascii() {
  local term_width
  term_width=$(tput cols 2>/dev/null || echo 80)

  while IFS= read -r line; do
    local clean
    clean=$(echo -e "$line" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
    local line_length=${#clean}

    if (( line_length < term_width )); then
      local padding=$(( (term_width - line_length) / 2 ))
      printf "%*s%s\n" "$padding" "" "$line"
    else
      echo "$line"
    fi
  done
}


center_banner() {
  local text="$1"
  local padding=$(( (BANNER_WIDTH - ${#text}) / 2 ))
  printf "%*s%s\n" "$padding" "" "$text"
}

error_exit() {
  echo -e "${ERROR}[✘] ERROR:${RESET} $1"
  exit 1
}

strip_ansi() {
  sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'
}

menu_block() {
  local title="$1"
  shift

  echo -e "${DIM}┌─────────────────────────────────────────────────────────────────────────┐${RESET}"
  printf "${PRIMARY}│ %-${MENU_WIDTH}s │${RESET}\n" "$title"
  echo -e "${DIM}├─────────────────────────────────────────────────────────────────────────┤${RESET}"

  for line in "$@"; do
    clean=$(echo -e "$line" | strip_ansi)
    visible_len=${#clean}
    padding=$((70 - visible_len))
    [ $padding -lt 0 ] && padding=0
    printf "│  %b%*s │\n" "$line" "$padding" ""
  done

  echo -e "${DIM}└─────────────────────────────────────────────────────────────────────────┘${RESET}"
  echo ""
}

# ----------------- FX & ANIMACIONES -----------------

fake_loader() {
  local msg="$1"
  local delay="${2:-0.017}"
  local bar="████████████████████████████████████████"
  echo -e "${ACCENT}${msg}${RESET}"
  for i in $(seq 1 ${#bar}); do
    printf "\r${DIM}[%-40s] %3d%%${RESET}" "${bar:0:i}" $(( i * 100 / ${#bar} ))
    sleep "$delay"
  done
  echo -e "\n"
}

spinner() {
  local pid=$1
  local spin='-\|/'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\r${PRIMARY}[${spin:$i:1}]${RESET} Executing..."
    sleep 0.3
  done
  printf "\r${ACCENT}[✓]${RESET} Completed.          \n"
}

transition() {
  clear
  echo -e "${DIM}"
  for _ in {1..3}; do
    echo "   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░"
    sleep 0.20
  done
  echo -e "${RESET}"
}

# ----------------- BOOT SEQUENCE -----------------
transition
fake_loader "Bootstrapping REDHAVEN core..."
fake_loader "Loading offensive modules..."
fake_loader "Verifying operational integrity..."

# ----------------- LOGO REDHAVEN -----------------
clear
echo -e "${PRIMARY}${BOLD}"
cat <<'EOF' | center_ascii

██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ██╗   ██╗███████╗███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██║   ██║██╔════╝████╗  ██║
██████╔╝█████╗  ██║  ██║███████║███████║██║   ██║█████╗  ██╔██╗ ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██║  ██║███████╗██████╔╝██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝

EOF
echo -e "${RESET}"

sep
line=$(center_banner "REDHAVEN 1.0.3"); echo -e "${TITLE}${line}${RESET}"
line=$(center_banner "OFFENSIVE BUG BOUNTY HUNTER"); echo -e "${TITLE}${line}${RESET}"
line=$(center_banner "Elite Red Team Edition • by darkne55"); echo -e "${TITLE}${line}${RESET}"
line=$(center_banner "Build: $BUILD_ID | Operator: $OPERATOR@$HOSTNAME")
echo -e "${DIM}${line}${RESET}"
sep
echo ""
sleep 4

# ----------------- CHECKS -----------------
( command -v docker &>/dev/null ) & spinner $!
if ! command -v docker &>/dev/null; then error_exit "Docker is not installed."; fi

# ----------------- MENU -----------------
transition

menu_block "SYSTEM OPERATIONS" \
  "[0] Update Toolchain & Templates   :: Sync nuclei, configs & payloads"

menu_block "PHASE 1 — RECONNAISSANCE" \
  "[1] Passive Recon      :: Subdomains, DNS, HTTP fingerprinting" \
  "[2] Active Recon       :: Ports, crawling, endpoint discovery" \
  "[3] Visual Recon       :: Automated screenshots & surface mapping" \
  "[4] Parameter Mining   :: Hidden params & attack vectors" \
  "[5] Port Scanning      :: Naabu top 1000 ports"

menu_block "PHASE 2 — METADATA & FILES" \
  "[6] Metadata Hunter    :: PDF / DOCX intelligence leakage" \
  "[7] Backup Discovery   :: .bak, .old, .swp file detection" \
  "[8] Secrets Hunter     :: Tokens, keys & credentials"

menu_block "PHASE 3 — VULNERABILITIES" \
  "[9] IDOR Hunter        :: Authorization logic abuse" \
  "[10] XSS Engine        :: Advanced reflection & DOM vectors" \
  "[11] SSRF Storm        :: Focused internal access" \
  "[12] CRLF Injection    :: Optimized with URO" \
  "[13] 403 Bypass        :: Access control evasion" \
  "[14] Client-Side       :: Redirects, proto & JS abuse" \
  "[15] JWT Attacks       :: Token manipulation & bypass" \
  "[16] Logic Flaws       :: Business logic abuse" \
  "[17] Unified Fuzzing   :: Context-aware STRATEGIC Fuzzing" \
  "[18] Supply Chain      :: CDN & third-party takeover"

menu_block "PHASE 4 — INFRASTRUCTURE & CLOUD" \
  "[19] Cloud Scan        :: S3, Azure, GCP misconfigs" \
  "[20] Subdomain Takeover:: Dangling CNAME detection" \
  "[21] GraphQL Deep Test :: Schema abuse & introspection" \
  "[22] Rate Limit Bypass :: API exhaustion attacks"

menu_block "PHASE 5 — ELITE UPGRADES (PHASE 2B)" \
  "[25] Race Conditions   :: Async logic abuse testing" \
  "[26] WebSocket Hunter  :: WS/WSS discovery & fuzzing" \
  "[27] Swagger Discovery :: API documentation recon" \
  "[28] BOLA/BFLA Testing :: API authorization bypass"

menu_block "PHASE 5B — ADVANCED ANALYSIS (PHASE 2B)" \
  "[29] PostMessage Scan  :: DOM XSS & origin validation" \
  "[30] Blind XSS Hunter  :: Out-of-band XSS (requires callback)" \
  "[31] 2FA Bypass Test   :: MFA security testing"

menu_block "PHASE 5C — ELITE SECURITY (PHASE 2C - 10/10)" \
  "[32] HTTP Smuggling    :: CL.TE/TE.CL/TE.TE attacks" \
  "[33] CORS Testing      :: Origin misconfiguration" \
  "[34] Cache Poisoning   :: Web cache & CPDoS" \
  "[39] Hunter Toolkit    :: Unicode, Email, Clickjacking"

menu_block "PHASE 6 — ADVANCED OAUTH & AI" \
  "[23] OAuth / OIDC      :: Auth flow compromise" \
  "[24] AI Hunter         :: Gemini-powered analysis"

menu_block "PHASE 7 — MOBILE SECURITY" \
  "[50] APK Analysis      :: Android app static analysis" \
  "[51] iOS Analysis      :: iOS .ipa security audit"

menu_block "PHASE 7 — AUTOMATION" \
  "[40] STANDARD MODE    :: Fast recon + top vulns" \
  "[41] ELITE MODE       :: Full chained workflow" \
  "${ACCENT}${BOLD}[42] RED TEAM ELITE   :: ALL-IN OFFENSIVE PIPELINE${RESET}" \
  "[99] Generate Report  :: Consolidated findings"

echo -e "${BLUE}          REDHAVEN v1.0.3 - Public Release          ${RESET}"
echo -e "${DIM}Enter the numeric code and press ENTER${RESET}"
echo ""
echo -ne "${PRIMARY}➜ ${BOLD}MODE${RESET} ❯ "
read MODO
case "$MODO" in
  30) MODE_NAME="STANDARD MODE" ;;
  31) MODE_NAME="ELITE MODE" ;;
  32) MODE_NAME="RED TEAM ELITE" ;;
  *)  MODE_NAME="CUSTOM MODE" ;;
esac

[ -z "$MODO" ] && error_exit "Invalid mode."

# ----------------- TARGET CONFIG -----------------
fake_loader "Preparing operational workspace..."

echo -e "${PRIMARY}[•] TARGET CONFIGURATION:${RESET}"
read -p " > Domain (e.g. uber.com): " TARGET
[ -z "$TARGET" ] && error_exit "Required domain."

PARENT_DIR="$(pwd)/results"
TARGET_DIR="$PARENT_DIR/$TARGET"

if [ -d "$TARGET_DIR" ]; then
  ( sleep 1 ) & spinner $!
  sep
  echo -e "${WARN}[!] Previous engagement detected for: $TARGET${RESET}"
  echo -e "  [C] Continue   |   [R] Reset"
  read -p " > Option [C/R]: " RESUME_CHOICE
  RESUME_CHOICE=${RESUME_CHOICE:-r}
  case "${RESUME_CHOICE,,}" in
    c) ;;
    *)
      mv "$TARGET_DIR" "$PARENT_DIR/${TARGET}_backup_$(date +%Y%m%d_%H%M%S)"
      mkdir -p "$TARGET_DIR"
      ;;
  esac
else
  mkdir -p "$TARGET_DIR"
fi

read -p " > Threads [Default: 25]: " THREADS
THREADS=${THREADS:-25}

# Mobile analysis files (optional)
read -p " > APK file path (Mode 50) [e.g. /home/user/app.apk | ENTER to skip]: " APK_FILE
read -p " > IPA file path (Mode 51) [e.g. /home/user/app.ipa | ENTER to skip]: " IPA_FILE

sep
line=$(center_banner "OPERATION MODE: $MODE_NAME")
echo -e "${ACCENT}${BOLD}${line}${RESET}"
echo -e "${DIM}Target: $TARGET | Threads: $THREADS${RESET}"
sep


fake_loader "Spawning container..."
fake_loader "Allocating resources..."
fake_loader "Mounting result volumes..."

CMD_ARGS=(run --rm -it --shm-size=2g -v "$PARENT_DIR":/results)

# Mount APK/IPA if provided
if [ -n "$APK_FILE" ] && [ -f "$APK_FILE" ]; then
  CMD_ARGS+=(-v "$(realpath "$APK_FILE"):/app.apk")
  CMD_ARGS+=(darkne55-redhaven -d "$TARGET" -m "$MODO" -t "$THREADS" -a /app.apk)
elif [ -n "$IPA_FILE" ] && [ -f "$IPA_FILE" ]; then
  CMD_ARGS+=(-v "$(realpath "$IPA_FILE"):/app.ipa")
  CMD_ARGS+=(darkne55-redhaven -d "$TARGET" -m "$MODO" -t "$THREADS" -i /app.ipa)
else
  CMD_ARGS+=(darkne55-redhaven -d "$TARGET" -m "$MODO" -t "$THREADS")
fi

if groups | grep -q docker; then
  docker "${CMD_ARGS[@]}"
else
  sudo docker "${CMD_ARGS[@]}"
fi

( sleep 1 ) & spinner $!
echo -e "${ACCENT}[OPERATION COMPLETE] Review results/$TARGET${RESET}"

