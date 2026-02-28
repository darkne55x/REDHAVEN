#!/bin/bash

# ============================================================================
# REDHAVEN v1.2.4 — Offensive Bug Bounty Framework
# Elite Red Team Edition • by darkne55
# ============================================================================

# ─────────────────── COLORES ───────────────────
R='\033[0;31m'       # Red
BR='\033[1;31m'      # Bold Red
LR='\033[1;91m'      # Light Red
O='\033[38;5;208m'   # Orange
Y='\033[1;33m'       # Yellow
G='\033[1;32m'       # Green
C='\033[1;36m'       # Cyan
B='\033[1;34m'       # Blue
M='\033[1;35m'       # Magenta
W='\033[1;37m'       # White Bold
D='\033[2m'          # Dim
DIM='\033[2m'
BOLD='\033[1m'
UL='\033[4m'         # Underline
RESET='\033[0m'
BG_R='\033[41m'      # BG Red
BG_DK='\033[48;5;52m' # BG Dark Red

# Aliases for compatibility
PRIMARY="$BR"
ACCENT="$LR"
WARN="$Y"
ERROR="$BR"
TITLE="$W"
GREEN="$G"
CYAN="$C"
BLUE="$B"
MAGENTA="$M"

# ─────────────────── LAYOUT ───────────────────
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)
[ "$TERM_WIDTH" -gt 90 ] && TERM_WIDTH=90
BOX_W=$((TERM_WIDTH - 4))

# ─────────────────── BUILD ───────────────────
BUILD_ID="$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo local)"
OPERATOR="$(whoami)"
HOSTNAME_SYS="$(hostname)"

# ─────────────────── SMART FLAGS ───────────────────
FLAG_DEEP=false
FLAG_STEALTH=false
FLAG_WEB_ONLY=false
FLAG_NO_RECON=false
FLAG_OSINT=false
FLAG_AI=false
CLI_TARGET=""
CLI_MODE=""
CLI_THREADS=""
INTERACTIVE=true

parse_flags() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)    
                if [[ ! "$2" =~ ^[a-zA-Z0-9.-]+$ ]]; then
                    echo -e "${ERROR}[✘] ERROR: Invalid domain format.${RESET}"
                    exit 1
                fi
                CLI_TARGET="$2"; INTERACTIVE=false; shift 2 ;;
            -m|--mode)      CLI_MODE="$2"; shift 2 ;;
            -t|--threads)   CLI_THREADS="$2"; shift 2 ;;
            --deep)         FLAG_DEEP=true; shift ;;
            --stealth)      FLAG_STEALTH=true; shift ;;
            --web-only)     FLAG_WEB_ONLY=true; shift ;;
            --no-recon)     FLAG_NO_RECON=true; shift ;;
            --osint)        FLAG_OSINT=true; shift ;;
            --ai)           FLAG_AI=true; shift ;;
            -h|--help)      show_help; exit 0 ;;
            *)              echo -e "${ERROR}[✘] Unknown flag: $1${RESET}"; show_help; exit 1 ;;
        esac
    done
}

show_help() {
    echo -e "${BR}${BOLD}REDHAVEN 1.2.4 — Command Reference${RESET}"
    echo ""
    echo -e "${W}USAGE:${RESET}"
    echo "  ./start.sh                              # Interactive wizard"
    echo "  ./start.sh -d target.com -m 85 --deep   # CLI mode"
    echo ""
    echo -e "${W}FLAGS:${RESET}"
    echo "  --deep      Extended payloads (SQLi, SSTI, LFI)"
    echo "  --stealth   Rate-limited (5 threads, 10 req/s)"
    echo "  --web-only  Web vulnerabilities only"
    echo "  --no-recon  Skip recon, use existing data"
    echo "  --osint     Enable OSINT intelligence"
    echo "  --ai        Enable AI Brain (LLM-powered analysis)"
    echo ""
    echo -e "${W}MODES:${RESET}"
    echo "  0-6    Recon          10-17  Secrets & API"
    echo "  20-29  Vulnerabilities 30-39  Elite Security"
    echo "  40-41  Infrastructure  50-51  Mobile"
    echo "  80-85  Automated       99     Report"
}

parse_flags "$@"

# ═══════════════════════════════════════════════════
# ██ UI PRIMITIVES
# ═══════════════════════════════════════════════════

# Draw a horizontal line with optional label
hline() {
    local char="${1:-─}"
    local label="$2"
    if [ -z "$label" ]; then
        printf "${D}"
        printf '%*s' "$TERM_WIDTH" '' | tr ' ' "$char"
        printf "${RESET}\n"
    else
        local clean_label
        clean_label=$(echo -e "$label" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
        local label_len=${#clean_label}
        local side=$(( (TERM_WIDTH - label_len - 4) / 2 ))
        printf "${D}"
        printf '%*s' "$side" '' | tr ' ' "$char"
        printf "${RESET} %b ${D}" "$label"
        printf '%*s' "$side" '' | tr ' ' "$char"
        printf "${RESET}\n"
    fi
}

# Center text on screen
center() {
    local text="$1"
    local clean
    clean=$(echo -e "$text" | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g')
    local pad=$(( (TERM_WIDTH - ${#clean}) / 2 ))
    [ $pad -lt 0 ] && pad=0
    printf "%*s%b\n" "$pad" "" "$text"
}

# Render ASCII art centered
render_ascii() {
    while IFS= read -r line; do
        center "$line"
    done
}

# --- UPDATE CHECKER (NEW) ---
check_framework_updates() {
    echo -ne "   ${INFO}[*] Checking for REDHAVEN updates...${RESET}"
    
    # 1. Check Framework Version (GitHub)
    local remote_version
    # Use -f to return failure on 404/500 errors
    remote_version=$(curl -fs --max-time 3 "https://raw.githubusercontent.com/darkne55x/REDHAVEN/main/VERSION.txt" || echo "Error")
    
    local local_version
    local_version=$(cat VERSION.txt 2>/dev/null || echo "Unknown")
    
    # Remove whitespace
    remote_version=$(echo "$remote_version" | xargs)
    local_version=$(echo "$local_version" | xargs)
    
    if [ "$remote_version" = "Error" ] || [[ "$remote_version" == *"Not Found"* ]]; then
        echo -e " ${D}(Update check skipped: GitHub Unreachable)${RESET}"
    elif [ "$remote_version" != "$local_version" ] && [ -n "$remote_version" ]; then
        echo -e "\n   ${BG_FATAL}${W} UPDATE AVAILABLE: v$remote_version ${RESET}"
        echo -e "   ${WARN}Current version: $local_version${RESET}"
        echo -e "   ${INFO}To update, run:${RESET}"
        echo -e "   ${D}  git pull${RESET}"
        echo -e "   ${D}  docker build -t darkne55-redhaven:latest .${RESET}\n"
        read -p "   Press [Enter] to continue..."
    else
        echo -e " ${SUCCESS}v$local_version (Latest)${RESET}"
    fi
}

# Ask yes/no
ask_yn() {
    local prompt="$1" default="$2" result
    if [ "$default" = "y" ]; then
        read -p "$(echo -e "   ${D}›${RESET} $prompt ${D}[Y/n]:${RESET} ")" result
        result=${result:-y}
    else
        read -p "$(echo -e "   ${D}›${RESET} $prompt ${D}[y/N]:${RESET} ")" result
        result=${result:-n}
    fi
    case "${result,,}" in y|yes|si|sí) return 0 ;; *) return 1 ;; esac
}

print_ok() { echo -e "   ${G}✓${RESET} $1"; }
print_item() { echo -e "   ${D}│${RESET}  $1"; }

error_exit() { echo -e "\n ${BR}✘ ERROR:${RESET} $1\n"; exit 1; }

# ═══════════════════════════════════════════════════
# ██ PERSISTENT HEADER
# ═══════════════════════════════════════════════════
draw_header() {
    clear
    echo ""
    echo -e "${BR}"
    cat <<'LOGO' | render_ascii
▄▄▄  ▄▄▄▄▄▄ ▄▄▄▄  ▄  ▄ ▄▄▄  ▄   ▄ ▄▄▄▄▄▄ ▄▄   ▄
█  █ █      █   █ █  █ █  █ █   █ █      █  █  █
█▄▄▀ █▀▀▀   █   █ █▀▀█ █▀▀█ ▀▄ ▄▀ █▀▀▀   █ ▀▄ █
█  █ █▄▄▄▄▄ █▄▄▄▀ █  █ █  █  █▄█  █▄▄▄▄▄ █  ▀▄█
LOGO
    echo -e "${RESET}"
    center "${D}=========================================================${RESET}"
    center "${LR}[*]${RESET} ${W}v1.2.4${RESET}  ${D}|${RESET}  ${W}AI Analyst Edition${RESET}  ${D}|${RESET}  ${D}by darkne55${RESET}"
    center "${D}Build ${BUILD_ID} // ${OPERATOR}@${HOSTNAME_SYS}${RESET}"
    center "${D}=========================================================${RESET}"
    echo ""
}

# Compact header for sub-screens (keeps branding visible)
draw_subheader() {
    clear
    echo ""
    center "${BR}${BOLD}[*] R E D H A V E N${RESET}  ${D}v1.2.4  //  AI Analyst Edition${RESET}"
    hline "-"
    echo ""
}

# ═══════════════════════════════════════════════════
# ██ MENU RENDERING
# ═══════════════════════════════════════════════════
menu_section() {
    local title="$1"
    shift
    echo ""
    echo -e "   ${BR}${BOLD}$title${RESET}"
    echo -e "   ${D}$(printf '%*s' 60 '' | tr ' ' '─')${RESET}"
    for line in "$@"; do
        print_item "$line"
    done
}

wizard_option() {
    local num="$1" icon="$2" name="$3" desc="$4"
    printf "   ${D}│${RESET}  ${G}${BOLD}[%s]${RESET}  %s  ${W}${BOLD}%-22s${RESET} ${D}%s${RESET}\n" "$num" "$icon" "$name" "$desc"
}

# ═══════════════════════════════════════════════════
# ██ BOOT ANIMATION
# ═══════════════════════════════════════════════════
boot_sequence() {
    clear
    echo ""
    echo ""
    echo ""

    # Dramatic fade-in of the name
    local name="R E D H A V E N"
    center "${D}${name}${RESET}"
    sleep 0.3
    center "${R}${name}${RESET}"
    sleep 0.3
    center "${BR}${name}${RESET}"
    sleep 0.3
    center "${LR}${BOLD}${name}${RESET}"
    sleep 0.5

    echo ""
    center "${D}Initializing offensive framework...${RESET}"
    echo ""

    # Progress bar
    local bar_width=40
    for i in $(seq 1 $bar_width); do
        local pct=$(( i * 100 / bar_width ))
        local filled=$(printf '%*s' "$i" '' | tr ' ' '█')
        local empty=$(printf '%*s' "$((bar_width - i))" '' | tr ' ' '░')
        center "$(printf "${BR}${filled}${D}${empty}${RESET} ${W}%3d%%${RESET}" "$pct")"
        sleep 0.02
        # Move cursor up to overwrite
        printf "\033[1A"
    done
    echo ""
    sleep 0.3
}

# ═══════════════════════════════════════════════════
# ██ GUIDED WIZARD
# ═══════════════════════════════════════════════════
run_wizard() {
    draw_header
    check_framework_updates
    echo ""

    echo -e "   ${C}${BOLD}SELECT YOUR MISSION${RESET}"
    echo -e "   ${D}$(printf '%*s' 60 '' | tr ' ' '─')${RESET}"
    echo ""
    wizard_option "1" "🔍" "Reconnaissance"     "Subdomains, endpoints, surface mapping"
    wizard_option "2" "🎯" "Vulnerability Hunt"  "XSS, SSRF, injections, IDOR & more"
    wizard_option "3" "🔐" "Secrets & API Intel" "API keys, JWT, OAuth, GraphQL"
    wizard_option "4" "🌐" "OSINT Intelligence"  "Dorks, emails, SPF/DMARC, DNS"
    wizard_option "5" "📱" "Mobile Security"     "Android APK / iOS IPA analysis"
    wizard_option "6" "💀" "FULL ASSAULT"        "Everything. Maximum coverage."
    echo ""
    echo -e "   ${D}$(printf '%*s' 60 '' | tr ' ' '─')${RESET}"
    wizard_option "A" "⚙ " "Advanced Mode"       "All 46 individual modules"

    wizard_option "U" "🛠️" "Update Toolchain"    "Update framework & tools"
    wizard_option "R" "📄" "Generate Report"     "From existing scan results"
    echo ""

    echo -ne "   ${BR}❯${RESET} "
    read WIZARD_CHOICE

    case "${WIZARD_CHOICE,,}" in
        1) wizard_recon ;;
        2) wizard_vulns ;;
        3) wizard_secrets ;;
        4) wizard_osint ;;
        5) wizard_mobile ;;
        6) wizard_full_assault ;;
        # 17) run_ai_hunter ;; # DISABLED: Module under refactoring
        a) run_advanced_menu ;;

        u) MODO=98; MODE_NAME="UPDATE TOOLCHAIN" ;;
        r) MODO=99; MODE_NAME="REPORT GENERATION" ;;
        *) error_exit "Invalid choice." ;;
    esac
}

# ═══════════════════════════════════════════════════
# ██ WIZARD: RECONNAISSANCE
# ═══════════════════════════════════════════════════
wizard_recon() {
    draw_subheader
    echo -e "   ${C}${BOLD}🔍 RECONNAISSANCE SETUP${RESET}"
    echo ""

    echo -e "   ${W}How deep should we go?${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[1]${RESET} Quick Recon    ${D}— Passive + active discovery (5 min)${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[2]${RESET} Standard Recon ${D}— + screenshots + tech detect (15 min)${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[3]${RESET} Deep Recon     ${D}— Full enum, ports, visual (30+ min)${RESET}"
    echo ""
    echo -ne "   ${BR}❯${RESET} "
    read RECON_DEPTH

    case "$RECON_DEPTH" in
        1) MODO=80; MODE_NAME="QUICK RECON";    print_ok "Quick recon" ;;
        2) MODO=80; MODE_NAME="STANDARD RECON";  print_ok "Standard recon" ;;
        3) MODO=80; FLAG_DEEP=true; MODE_NAME="DEEP RECON"; print_ok "Deep recon" ;;
        *) MODO=80; MODE_NAME="QUICK RECON" ;;
    esac

    echo ""
    ask_yn "Include OSINT? (dorks, emails, SPF/DMARC)" "n" && { FLAG_OSINT=true; print_ok "OSINT enabled"; }
    ask_yn "Include port scanning?" "n" && print_ok "Port scan included"
    ask_yn "Stealth mode? (slower, harder to detect)" "n" && { FLAG_STEALTH=true; print_ok "Stealth ON"; }
}

# ═══════════════════════════════════════════════════
# ██ WIZARD: VULNERABILITY HUNT
# ═══════════════════════════════════════════════════
wizard_vulns() {
    draw_subheader
    echo -e "   ${C}${BOLD}🎯 VULNERABILITY HUNT SETUP${RESET}"
    echo ""

    echo -e "   ${W}What do you want to find?${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[1]${RESET} Web Vulns      ${D}— XSS, SSRF, CRLF, 403 bypass${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[2]${RESET} Injections     ${D}— SQLi, SSTI, LFI, CmdInj${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[3]${RESET} Logic & Auth   ${D}— IDOR, Race, 2FA, BOLA${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[4]${RESET} Infrastructure ${D}— Takeover, Smuggling, Cache${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[5]${RESET} Everything     ${D}— All of the above${RESET}"
    echo ""
    echo -ne "   ${BR}❯${RESET} "
    read VULN_CHOICE

    MODO=81; FLAG_WEB_ONLY=true
    case "$VULN_CHOICE" in
        1) MODE_NAME="WEB VULNERABILITY HUNT";  print_ok "Web vulns" ;;
        2) FLAG_DEEP=true; MODE_NAME="INJECTION HUNT"; print_ok "Injections (deep mode)" ;;
        3) MODE_NAME="LOGIC & AUTH HUNT"; print_ok "Logic & auth" ;;
        4) FLAG_WEB_ONLY=false; MODE_NAME="INFRASTRUCTURE HUNT"; print_ok "Infrastructure" ;;
        5) FLAG_DEEP=true; FLAG_WEB_ONLY=false; MODO=85; MODE_NAME="FULL VULNERABILITY HUNT"; print_ok "Everything (deep + infra)" ;;
        *) MODE_NAME="WEB VULNERABILITY HUNT" ;;
    esac

    echo ""
    ask_yn "Skip recon? (faster if you already scanned)" "n" && { FLAG_NO_RECON=true; print_ok "Skipping recon"; }
    ask_yn "Stealth mode? (rate-limited, evasive)" "n" && { FLAG_STEALTH=true; print_ok "Stealth ON"; }
}

# ═══════════════════════════════════════════════════
# ██ WIZARD: SECRETS & API INTEL
# ═══════════════════════════════════════════════════
wizard_secrets() {
    draw_subheader
    echo -e "   ${C}${BOLD}🔐 SECRETS & API INTELLIGENCE${RESET}"
    echo ""

    echo -e "   ${W}What intel are you after?${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[1]${RESET} Secrets Only   ${D}— API keys, tokens, credentials${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[2]${RESET} API Analysis   ${D}— GraphQL, Swagger, BOLA${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[3]${RESET} JWT & OAuth    ${D}— Token attacks, auth flow${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[4]${RESET} JS Deep Dive   ${D}— PostMessage, DOM XSS, maps${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[5]${RESET} Full Intel     ${D}— All of the above${RESET}"
    echo ""
    echo -ne "   ${BR}❯${RESET} "
    read SECRETS_CHOICE

    MODO=82; FLAG_WEB_ONLY=true
    case "$SECRETS_CHOICE" in
        1) MODE_NAME="SECRETS HUNT"; print_ok "Secrets" ;;
        2) MODE_NAME="API ANALYSIS"; print_ok "API analysis" ;;
        3) MODE_NAME="JWT & OAUTH ATTACK"; print_ok "JWT & OAuth" ;;
        4) FLAG_OSINT=true; MODE_NAME="JS DEEP DIVE"; print_ok "JS deep dive" ;;
        5) FLAG_DEEP=true; FLAG_OSINT=true; MODE_NAME="FULL INTELLIGENCE"; print_ok "Full intel" ;;
        *) MODE_NAME="SECRETS HUNT" ;;
    esac

    echo ""
    ask_yn "Skip recon? (faster if you already scanned)" "n" && { FLAG_NO_RECON=true; print_ok "Skipping recon"; }
}

# ═══════════════════════════════════════════════════
# ██ WIZARD: OSINT
# ═══════════════════════════════════════════════════
wizard_osint() {
    draw_subheader
    echo -e "   ${C}${BOLD}🌐 OSINT INTELLIGENCE${RESET}"
    echo ""

    MODO=83; FLAG_OSINT=true; MODE_NAME="OSINT INTELLIGENCE"

    echo -e "   ${W}OSINT modules:${RESET}"
    echo -e "   ${G}✓${RESET} Google Dork generation (30+ queries)"
    echo -e "   ${G}✓${RESET} SPF/DMARC email spoofing analysis"
    echo -e "   ${G}✓${RESET} JavaScript source map extraction"
    echo -e "   ${G}✓${RESET} DNS Zone Transfer check"
    echo -e "   ${G}✓${RESET} Email harvesting from web pages"

    echo ""
    if ask_yn "Also run full recon first?" "n"; then
        MODO=85; FLAG_WEB_ONLY=true; MODE_NAME="RECON + OSINT"
        print_ok "Full recon + OSINT"
    else
        print_ok "OSINT only"
    fi
}

# ═══════════════════════════════════════════════════
# ██ WIZARD: MOBILE
# ═══════════════════════════════════════════════════
wizard_mobile() {
    draw_subheader
    echo -e "   ${C}${BOLD}📱 MOBILE SECURITY${RESET}"
    echo ""

    echo -e "   ${W}Platform?${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[1]${RESET} Android (APK)"
    echo -e "   ${D}│${RESET}  ${G}[2]${RESET} iOS (IPA)"
    echo -e "   ${D}│${RESET}  ${G}[3]${RESET} Both"
    echo ""
    echo -ne "   ${BR}❯${RESET} "
    read MOBILE_CHOICE

    case "$MOBILE_CHOICE" in
        1)
            MODO=50; MODE_NAME="ANDROID APK ANALYSIS"
            read -p "   > APK file path: " APK_FILE
            [ -z "$APK_FILE" ] && error_exit "APK path is required."
            [ ! -f "$APK_FILE" ] && error_exit "File not found: $APK_FILE"
            print_ok "Android: $APK_FILE"
            ;;
        2)
            MODO=51; MODE_NAME="iOS IPA ANALYSIS"
            read -p "   > IPA file path: " IPA_FILE
            [ -z "$IPA_FILE" ] && error_exit "IPA path is required."
            [ ! -f "$IPA_FILE" ] && error_exit "File not found: $IPA_FILE"
            print_ok "iOS: $IPA_FILE"
            ;;
        3)
            MODO=85; MODE_NAME="MOBILE SECURITY (BOTH)"
            read -p "   > APK file path: " APK_FILE
            read -p "   > IPA file path: " IPA_FILE
            print_ok "Both platforms"
            ;;
        *) error_exit "Invalid choice." ;;
    esac
}

# ═══════════════════════════════════════════════════
# ██ WIZARD: FULL ASSAULT
# ═══════════════════════════════════════════════════
wizard_full_assault() {
    draw_subheader

echo ""
echo -e "${LR}"
cat <<'FA' | render_ascii
 ██████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
 ██████╔╝█████╗  ███████║██║  ██║ ╚████╔╝ 
 ██╔══██╗██╔══╝  ██╔══██║██║  ██║  ╚██╔╝  
 ██║  ██║███████╗██║  ██║██████╔╝   ██║   
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   

      TO HACK?
FA
echo -e "${RESET}"


    center "${LR}${BOLD}ALL-IN OFFENSIVE PIPELINE${RESET}"
    center "${D}Every module. Every vector. Maximum coverage.${RESET}"
    echo ""

    MODO=85; MODE_NAME="RED TEAM ELITE — FULL ASSAULT"

    ask_yn "Enable Deep Mode? (SQLi, SSTI, LFI)" "y" && { FLAG_DEEP=true; print_ok "Deep Mode ON"; }
    ask_yn "Include OSINT Intelligence?" "y" && { FLAG_OSINT=true; print_ok "OSINT enabled"; }
    ask_yn "Stealth mode? (rate-limited)" "n" && { FLAG_STEALTH=true; print_ok "Stealth ON"; }
    ask_yn "Enable AI Brain? (LLM analysis)" "y" && { FLAG_AI=true; print_ok "AI Brain ON 🧠"; }

    echo ""
    echo -e "   ${W}Mobile analysis:${RESET}"
    if ask_yn "Analyze an Android APK?" "n"; then
        read -p "   > APK file path: " APK_FILE
        [ -n "$APK_FILE" ] && [ -f "$APK_FILE" ] && print_ok "APK: $APK_FILE"
    fi
    if ask_yn "Analyze an iOS IPA?" "n"; then
        read -p "   > IPA file path: " IPA_FILE
        [ -n "$IPA_FILE" ] && [ -f "$IPA_FILE" ] && print_ok "IPA: $IPA_FILE"
    fi
}

# ═══════════════════════════════════════════════════
# ██ ADVANCED MENU
# ═══════════════════════════════════════════════════
run_advanced_menu() {
    draw_subheader
    echo -e "   ${W}${BOLD}ADVANCED MODE${RESET} ${D}— Individual module selection${RESET}"

    menu_section "RECONNAISSANCE  ${D}[0-6]${RESET}" \
      "${G}[0]${RESET}  Passive Recon      ${D}Subfinder, DNS, HTTP${RESET}" \
      "${G}[1]${RESET}  Active Recon       ${D}Crawling, endpoints${RESET}" \
      "${G}[2]${RESET}  Visual Recon       ${D}Screenshots & mapping${RESET}" \
      "${G}[3]${RESET}  Parameter Mining   ${D}Hidden params${RESET}" \
      "${G}[4]${RESET}  Port Scanning      ${D}Naabu top 1000${RESET}" \
      "${G}[5]${RESET}  Alternate Recon    ${D}Nelux1 integration${RESET}" \
      "${G}[6]${RESET}  OSINT Recon        ${D}Dorks, SPF, emails${RESET}"

    menu_section "SECRETS & API  ${D}[10-17]${RESET}" \
      "${G}[10]${RESET} Secrets Hunter     ${D}Tokens, keys, creds${RESET}" \
      "${G}[11]${RESET} Metadata Hunter    ${D}PDF/DOCX intel${RESET}" \
      "${G}[12]${RESET} Backup Discovery   ${D}.bak, .old, .swp${RESET}" \
      "${G}[13]${RESET} Swagger Discovery  ${D}API documentation${RESET}" \
      "${G}[14]${RESET} GraphQL Deep       ${D}Introspection & injection${RESET}" \
      "${G}[15]${RESET} JWT Attacks        ${D}Token manipulation${RESET}" \
      "${G}[16]${RESET} OAuth / OIDC       ${D}Auth flow compromise${RESET}" \
      "${G}[17]${RESET} AI Hunter          ${D}Gemini-powered${RESET}"

    menu_section "VULNERABILITIES  ${D}[20-29]${RESET}" \
      "${G}[20]${RESET} XSS Engine         ${D}Reflection & DOM${RESET}" \
      "${G}[21]${RESET} SSRF Storm         ${D}Internal access${RESET}" \
      "${G}[22]${RESET} CRLF Injection     ${D}Header injection${RESET}" \
      "${G}[23]${RESET} IDOR Hunter        ${D}Auth logic abuse${RESET}" \
      "${G}[24]${RESET} Client-Side        ${D}Redirects, proto${RESET}" \
      "${G}[25]${RESET} Deep Fuzzing       ${D}SQLi/SSTI/LFI/CmdInj${RESET}" \
      "${G}[26]${RESET} 403 Bypass         ${D}Access control${RESET}" \
      "${G}[27]${RESET} Logic Flaws        ${D}Business logic${RESET}" \
      "${G}[28]${RESET} Rate Limit Bypass  ${D}API exhaustion${RESET}" \
      "${G}[29]${RESET} Supply Chain       ${D}CDN & third-party${RESET}"

    menu_section "ELITE SECURITY  ${D}[30-39]${RESET}" \
      "${G}[30]${RESET} HTTP Smuggling     ${D}CL.TE/TE.CL${RESET}" \
      "${G}[31]${RESET} CORS Testing       ${D}Origin misconfig${RESET}" \
      "${G}[32]${RESET} Cache Poisoning    ${D}CPDoS attacks${RESET}" \
      "${G}[33]${RESET} Race Conditions    ${D}Async abuse${RESET}" \
      "${G}[34]${RESET} WebSocket Hunter   ${D}WS/WSS discovery${RESET}" \
      "${G}[35]${RESET} BOLA/BFLA          ${D}API auth bypass${RESET}" \
      "${G}[36]${RESET} PostMessage Scan   ${D}DOM XSS, origin${RESET}" \
      "${G}[37]${RESET} Blind XSS          ${D}OOB callbacks${RESET}" \
      "${G}[38]${RESET} 2FA Bypass         ${D}MFA security${RESET}" \
      "${G}[39]${RESET} Hunter Toolkit     ${D}Unicode, Email, Click${RESET}"

    menu_section "INFRASTRUCTURE  ${D}[40-41]${RESET}  •  MOBILE  ${D}[50-51]${RESET}" \
      "${G}[40]${RESET} Cloud Scan         ${D}S3, Azure, GCP${RESET}" \
      "${G}[41]${RESET} Subdomain Takeover ${D}Dangling CNAME${RESET}" \
      "${G}[50]${RESET} APK Analysis       ${D}Android static${RESET}" \
      "${G}[51]${RESET} iOS Analysis       ${D}iOS .ipa audit${RESET}"

    menu_section "AUTOMATED PIPELINES  ${D}[80-85]${RESET}" \
      "${G}[80]${RESET} Quick Recon        ${D}Surface discovery${RESET}" \
      "${G}[81]${RESET} Vulnerability Hunt ${D}Recon + all vulns${RESET}" \
      "${G}[82]${RESET} Secrets & API      ${D}Recon + intel${RESET}" \
      "${G}[83]${RESET} OSINT Intelligence ${D}Recon + OSINT${RESET}" \
      "${G}[84]${RESET} Elite Classic      ${D}Full chained${RESET}" \
      "${LR}${BOLD}[85]${RESET} ${LR}${BOLD}RED TEAM ELITE${RESET}    ${D}ALL-IN PIPELINE${RESET}"

    echo ""
    echo -e "   ${D}[98] Update Toolchain${RESET}"
    echo -e "   ${D}[99] Generate Report${RESET}"
    echo ""

    echo -ne "   ${BR}❯ MODE:${RESET} "
    read MODO
    MODE_NAME="ADVANCED: MODE $MODO"
}

# ═══════════════════════════════════════════════════
# ██ MAIN EXECUTION
# ═══════════════════════════════════════════════════

# Boot
boot_sequence

# Docker check
if ! command -v docker &>/dev/null; then error_exit "Docker is not installed."; fi

# Mode selection
APK_FILE=""
IPA_FILE=""

if [ "$INTERACTIVE" = true ]; then
    run_wizard
else
    MODO="$CLI_MODE"
fi

case "$MODO" in
  80) MODE_NAME="${MODE_NAME:-QUICK RECON}" ;;
  81) MODE_NAME="${MODE_NAME:-VULNERABILITY HUNT}" ;;
  82) MODE_NAME="${MODE_NAME:-SECRETS & API INTEL}" ;;
  83) MODE_NAME="${MODE_NAME:-OSINT INTELLIGENCE}" ;;
  84) MODE_NAME="${MODE_NAME:-ELITE CLASSIC}" ;;
  85) MODE_NAME="${MODE_NAME:-RED TEAM ELITE}" ;;
  98) MODE_NAME="${MODE_NAME:-UPDATE TOOLCHAIN}" ;;
esac

[ -z "$MODO" ] && error_exit "No mode selected."

# ═══════════════════════════════════════════════════

# Special Mode: Update Toolchain (Host-side execution)
if [ "$MODO" -eq 98 ]; then
    echo ""
    hline "=" "${BR}${BOLD}UPDATING TOOLCHAIN${RESET}"
    echo ""
    echo -e "   ${INFO}Detected Request: Toolchain Update${RESET}"
    echo -e "   ${D}This will rebuild the Docker image to fetch latest tools & templates.${RESET}"
    echo ""
    
    if ask_yn "Proceed with full update?" "y"; then
        echo ""
        echo -e "   ${INFO}Running: docker build -t darkne55-redhaven:latest .${RESET}"
        if groups | grep -q docker; then
            docker build -t darkne55-redhaven:latest .
        else
            sudo docker build -t darkne55-redhaven:latest .
        fi
        
        if [ $? -eq 0 ]; then
            echo ""
            print_ok "Update Complete! Please restart REDHAVEN."
            exit 0
        else
            error_exit "Update failed. Check Docker logs."
        fi
    else
        echo -e "   ${WARN}Update cancelled.${RESET}"
        exit 0
    fi
fi

# ═══════════════════════════════════════════════════
# ██ TARGET CONFIG
# ═══════════════════════════════════════════════════
draw_subheader

if [ "$INTERACTIVE" = true ]; then
    echo -e "   ${C}${BOLD}TARGET CONFIGURATION${RESET}"
    echo ""
    read -p "$(echo -e "   ${BR}❯${RESET} Target domain: ")" TARGET
else
    TARGET="$CLI_TARGET"
fi

[ -z "$TARGET" ] && error_exit "Target domain is required."
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    error_exit "Invalid target format. Use domains or IPs only (no schemes/paths)."
fi

# Threads
if [ -n "$CLI_THREADS" ]; then
    THREADS="$CLI_THREADS"
elif [ "$INTERACTIVE" = true ]; then
    read -p "$(echo -e "   ${BR}❯${RESET} Threads ${D}[25]:${RESET} ")" THREADS
    THREADS=${THREADS:-25}
else
    THREADS=25
fi

$FLAG_STEALTH && { THREADS=5; echo -e "   ${Y}⚡ Stealth: threads → 5${RESET}"; }

# Results dir
PARENT_DIR="$(pwd)/results"
TARGET_DIR="$PARENT_DIR/$TARGET"

if [ -d "$TARGET_DIR" ] && [ "$INTERACTIVE" = true ]; then
    echo ""
    echo -e "   ${Y}Previous scan data found for ${W}$TARGET${RESET}"
    echo -e "   ${D}│${RESET}  ${G}[C]${RESET} Continue (resume)"
    echo -e "   ${D}│${RESET}  ${G}[R]${RESET} Reset (backup & fresh)"
    echo -ne "   ${BR}❯${RESET} "
    read RESUME_CHOICE
    case "${RESUME_CHOICE,,}" in
        r) mv "$TARGET_DIR" "$PARENT_DIR/${TARGET}_backup_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$TARGET_DIR"; print_ok "Fresh start" ;;
        *) print_ok "Resuming" ;;
    esac
else
    mkdir -p "$TARGET_DIR"
fi

# ═══════════════════════════════════════════════════
# ██ OPERATION SUMMARY
# ═══════════════════════════════════════════════════
echo ""
hline "=" "${BR}${BOLD}OPERATION SUMMARY${RESET}"
echo ""
echo -e "   ${D}Mission${RESET}   ${LR}${BOLD}$MODE_NAME${RESET}"
echo -e "   ${D}Target${RESET}    ${W}$TARGET${RESET}"
echo -e "   ${D}Mode${RESET}      ${W}$MODO${RESET}"
echo -e "   ${D}Threads${RESET}   ${W}$THREADS${RESET}"
echo ""

# Active flags
$FLAG_DEEP     && echo -e "   ${G}▸${RESET} Deep Mode      ${D}Extended payloads${RESET}"
$FLAG_STEALTH  && echo -e "   ${G}▸${RESET} Stealth        ${D}Rate-limited${RESET}"
$FLAG_WEB_ONLY && echo -e "   ${G}▸${RESET} Web Only       ${D}No infra/mobile${RESET}"
$FLAG_NO_RECON && echo -e "   ${G}▸${RESET} No Recon       ${D}Skip recon${RESET}"
$FLAG_OSINT    && echo -e "   ${G}▸${RESET} OSINT          ${D}Intelligence module${RESET}"
$FLAG_AI       && echo -e "   ${G}▸${RESET} AI Brain       ${D}LLM-powered analysis${RESET}"
[ -n "$APK_FILE" ] && echo -e "   ${G}▸${RESET} APK            ${D}$APK_FILE${RESET}"
[ -n "$IPA_FILE" ] && echo -e "   ${G}▸${RESET} IPA            ${D}$IPA_FILE${RESET}"

echo ""
hline "="

if [ "$INTERACTIVE" = true ]; then
    echo ""
    echo -ne "   ${W}Press ENTER to launch${RESET} ${D}(Ctrl+C to abort)${RESET} "
    read -r
fi

# ═══════════════════════════════════════════════════
# ██ LAUNCH
# ═══════════════════════════════════════════════════
draw_subheader
center "${LR}${BOLD}LAUNCHING SCAN${RESET}"
echo ""

# Build Docker command
CMD_ARGS=(run --rm -it --shm-size=2g \
  --entrypoint /bin/bash \
  -e "DEEP_MODE=$FLAG_DEEP" \
  -e "STEALTH_MODE=$FLAG_STEALTH" \
  -e "WEB_ONLY=$FLAG_WEB_ONLY" \
  -e "SKIP_RECON=$FLAG_NO_RECON" \
  -e "OSINT_MODE=$FLAG_OSINT" \
  -e "AI_MODE=$FLAG_AI" \
  -v "$PARENT_DIR":/results \
  -v "$(readlink -f scanner.sh)":/usr/local/bin/scanner \
  -v "$(pwd)/modules":/usr/local/bin/modules \

  -v "$(pwd)/modules/hunter_toolkit.py":/usr/local/bin/hunter_toolkit \
  -v "$(pwd)/modules/ai_hunter.py":/usr/local/bin/ai_hunter \
  -v "$(pwd)/modules/correlator.py":/usr/local/bin/correlator \
  -v "$(pwd)/modules/blind_xss.py":/usr/local/bin/blind_xss \
  -v "$(pwd)/modules/postmessage_analyzer.py":/usr/local/bin/postmessage_analyzer \
  -v "$(pwd)/modules/twofa_bypass.py":/usr/local/bin/twofa_bypass \
  -v "$(pwd)/modules/swagger_discovery.py":/usr/local/bin/swagger_discovery \
  -v "$(pwd)/modules/bola_bfla.py":/usr/local/bin/bola_bfla \
  -v "$(pwd)/modules/smuggler.py":/usr/local/bin/smuggler \
  -v "$(pwd)/modules/cors_tester.py":/usr/local/bin/cors_tester \
  -v "$(pwd)/modules/cache_poison.py":/usr/local/bin/cache_poison \
  -v "$(pwd)/modules/race_cond.py":/usr/local/bin/race_cond \
  -v "$(pwd)/modules/ws_scanner.py":/usr/local/bin/ws_scanner \
  -v "$(pwd)/modules/osint_recon.py":/usr/local/bin/osint_recon \
)

$FLAG_STEALTH && CMD_ARGS+=(-e "RATE_LIMIT=10")

if [ -n "$APK_FILE" ] && [ -f "$APK_FILE" ]; then
  CMD_ARGS+=(-v "$(realpath "$APK_FILE")":/app.apk)
  CMD_ARGS+=(darkne55-redhaven:latest /usr/local/bin/scanner -d "$TARGET" -m "$MODO" -t "$THREADS" -a /app.apk)
elif [ -n "$IPA_FILE" ] && [ -f "$IPA_FILE" ]; then
  CMD_ARGS+=(-v "$(realpath "$IPA_FILE")":/app.ipa)
  CMD_ARGS+=(darkne55-redhaven:latest /usr/local/bin/scanner -d "$TARGET" -m "$MODO" -t "$THREADS" -i /app.ipa)
else
  CMD_ARGS+=(darkne55-redhaven:latest /usr/local/bin/scanner -d "$TARGET" -m "$MODO" -t "$THREADS")
fi

if groups | grep -q docker; then
  docker "${CMD_ARGS[@]}"
else
  sudo docker "${CMD_ARGS[@]}"
fi

echo ""
hline "=" "${G}${BOLD}OPERATION COMPLETE${RESET}"
echo ""
center "${W}Results saved in: ${G}results/$TARGET${RESET}"
echo ""
