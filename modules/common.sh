#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === COMMON FUNCTIONS ===
# --- PALETA DE COLORES ANSI (REDHAVEN STANDARD) ---
PRIMARY='\033[1;31m'      # Rojo identidad (usar con cuidado)
INFO='\033[0;34m'         # Azul proceso
INFO_DIM='\033[2;34m'
SUCCESS='\033[0;32m'      # Verde OK
WARN='\033[1;33m'         # Amarillo warning
ERROR='\033[0;31m'        # Rojo error
STAT='\033[0;37m'         # Gris stats
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

BG_FATAL='\033[41m'       # Fondo rojo solo fatal

# --- CONFIGURACIÓN GLOBAL ---
RATE_LIMIT=10; MODE=""; TARGET=""; THREADS=25; APK_FILE=""; IPA_FILE=""
# --- LOGIC CONTROL ---
IS_WORDPRESS=false; IS_SPRING=false; HAS_GRAPHQL=false; IS_REST=false; IS_DOTNET=false
OUT_DIR=""

# --- SMART FLAGS (V2.0 — read from Docker env vars passed by start.sh) ---
DEEP_MODE="${DEEP_MODE:-false}"
STEALTH_MODE="${STEALTH_MODE:-false}"
WEB_ONLY="${WEB_ONLY:-false}"
SKIP_RECON="${SKIP_RECON:-false}"
OSINT_MODE="${OSINT_MODE:-false}"

# --- OOB CALLBACK (for blind SSRF, blind XSS, DNS exfiltration) ---
# Set via: docker run -e OOB_DOMAIN=xxx.interact.sh ...
OOB_DOMAIN="${OOB_DOMAIN:-}"

# Override rate limit in stealth mode
if [ "$STEALTH_MODE" = "true" ]; then
    RATE_LIMIT=10
    THREADS=5
fi
JUNK_EXT="jpg,jpeg,png,svg,gif,webp,ico,woff,woff2,ttf,eot,css,mp4,mp3,flv,avi,wmv,zip,gz,rar"

# --- OS TUNING ---
ulimit -n 65535 2>/dev/null || true

# --- CONTROL DE SEÑALES ---
cleanup() {
    if [ $? -ne 0 ]; then
        echo -e "\n${ERROR}[✘] Process interrupted or failed.${RESET}"
        jobs -p | xargs -r kill >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

# --- UTILIDADES DE LOGGING (COHERENTE) ---
log_phase() {
    echo -e "\n${BOLD}${INFO}▶ PHASE:${RESET} ${BOLD}${INFO}$1${RESET}"
}

log_step() {
    echo -e "  ${INFO}➥${RESET} $1"
}

log_success() {
    echo -e "  ${SUCCESS}✓${RESET} $1"
}

log_warn() {
    echo -e "  ${WARN}⚠${RESET} ${DIM}$1${RESET}"
}

log_err() {
    echo -e "  ${ERROR}✘${RESET} ${BOLD}$1${RESET}"
}

log_stat() {
    echo -e "  ${STAT}📊${RESET} ${DIM}$1:${RESET} ${BOLD}$2${RESET}"
}

log_fatal() {
    echo -e "\n${BG_FATAL}${BOLD} CRITICAL ERROR ${RESET} ${ERROR}$1${RESET}"
    exit 1
}

# --- HTTPX BINARY RESOLUTION (CENTRALIZED) ---
resolve_httpx_bin() {
    if command -v httpx-pd >/dev/null; then HTTPX_BIN="httpx-pd"
    else HTTPX_BIN=$(find /root/go/bin /usr/local/bin -name httpx -type f 2>/dev/null | grep -v "python" | head -n 1)
    fi
    [ -z "$HTTPX_BIN" ] && HTTPX_BIN="/root/go/bin/httpx"
    export HTTPX_BIN
}
resolve_httpx_bin

# --- PROGRESS BAR (PHASE-BASED, SAFE) ---
PROGRESS_TOTAL=0
PROGRESS_CURRENT=0

progress_init() {
    PROGRESS_TOTAL="$1"
    PROGRESS_CURRENT=0
}

progress_step() {
    PROGRESS_CURRENT=$((PROGRESS_CURRENT + 1))
    local width=30
    local filled=$(( PROGRESS_CURRENT * width / PROGRESS_TOTAL ))
    local empty=$(( width - filled ))

    printf "\r${INFO}["
    printf "%0.s█" $(seq 1 $filled)
    printf "%0.s░" $(seq 1 $empty)
    printf "] %d/%d phases${RESET}" "$PROGRESS_CURRENT" "$PROGRESS_TOTAL"
}

progress_done() {
    echo -e "\n${SUCCESS}✓ SCAN WORKFLOW COMPLETED.${RESET}"
}


# --- VALIDACIONES ---
check_required_output() {
    local file=$1; local context=$2
    if [ ! -s "$file" ]; then 
        log_warn "WARNING: The phase '$context' did not generate any results in '$file'. Resuming with precaution..."
        return 1
    fi
    return 0
}

check_dependency() {
    local file=$1; local name=$2
    if [ -f "$file" ] && [ -s "$file" ]; then
        echo -e "  ${DIM}↻ $name already completed. Skipping...${RESET}"
        return 0
    else
        return 1
    fi
}

verify_tools() {
    local tools=("subfinder" "nuclei" "katana" "naabu" "dalfox" "uro" "parallel" "qsreplace")
    local missing=0
    
    log_phase "VERIFYING TOOLCHAIN INTEGRITY"
    
    # Check for httpx specifically (naming variation)
    if command -v httpx-pd >/dev/null || command -v httpx >/dev/null; then
        log_success "httpx found"
    else
        log_err "httpx (or httpx-pd) NOT found"
        missing=1
    fi

    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null; then
            log_success "$tool found"
        else
            log_err "$tool NOT found"
            missing=$((missing + 1))
        fi
    done
    
    if [ $missing -gt 0 ]; then
        log_fatal "Missing $missing critical tools. Please rebuild the Docker image."
    fi
}

show_banner() {
    clear
    echo -e "${RED}    REDHAVEN v1.2.0 - COMMUNITY EDITION    ${RESET}"
    echo -e "${DIM}Restoring complete logic for /results...${RESET}\n"
}
