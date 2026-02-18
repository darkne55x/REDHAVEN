#!/bin/bash

# =======================================================================================
# REDHAVEN v1.2.1 • Offensive Bug Bounty Framework • Modular Architecture • by darkne55
# =======================================================================================

set -euo pipefail

# --- RESOLVE SCRIPT DIRECTORY ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="${SCRIPT_DIR}/modules"

# --- CONFIGURACIÓN GLOBAL ---
RATE_LIMIT=10; MODE=""; TARGET=""; THREADS=25; APK_FILE=""; IPA_FILE=""
IS_WORDPRESS=false; IS_SPRING=false; HAS_GRAPHQL=false; IS_REST=false; IS_DOTNET=false
OUT_DIR=""

# --- SMART FLAGS (read from Docker env vars passed by start.sh) ---
DEEP_MODE="${DEEP_MODE:-false}"
STEALTH_MODE="${STEALTH_MODE:-false}"
WEB_ONLY="${WEB_ONLY:-false}"
SKIP_RECON="${SKIP_RECON:-false}"
OSINT_MODE="${OSINT_MODE:-false}"

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
        echo -e "\n\033[0;31m[✘] Process interrupted or failed.\033[0m"
        jobs -p | xargs -r kill >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

# ============================================================================
# SOURCE ALL MODULES
# ============================================================================
source "$MODULE_DIR/common.sh"
source "$MODULE_DIR/recon.sh"
source "$MODULE_DIR/endpoints.sh"
source "$MODULE_DIR/idor.sh"
source "$MODULE_DIR/xss.sh"
source "$MODULE_DIR/secrets.sh"
source "$MODULE_DIR/ssrf.sh"
source "$MODULE_DIR/crlf.sh"
source "$MODULE_DIR/supply.sh"
source "$MODULE_DIR/fuzzing.sh"
source "$MODULE_DIR/bypass403.sh"
source "$MODULE_DIR/jwt.sh"
source "$MODULE_DIR/logic.sh"
source "$MODULE_DIR/intel.sh"
source "$MODULE_DIR/client.sh"
source "$MODULE_DIR/graphql.sh"
source "$MODULE_DIR/ratelimit.sh"
source "$MODULE_DIR/oauth.sh"
source "$MODULE_DIR/infra.sh"
source "$MODULE_DIR/race.sh"
source "$MODULE_DIR/websocket.sh"
source "$MODULE_DIR/swagger.sh"
source "$MODULE_DIR/osint.sh"
source "$MODULE_DIR/advanced.sh"
source "$MODULE_DIR/bola.sh"
source "$MODULE_DIR/smuggling.sh"
source "$MODULE_DIR/cors.sh"
source "$MODULE_DIR/cache.sh"

# --- PROCESAMIENTO DE ARGUMENTOS ---
while getopts "d:m:r:t:a:i:vp" opt; do
    case $opt in
        d) TARGET=$OPTARG ;;
        m) MODE=$OPTARG ;;
        r) RATE_LIMIT=$OPTARG ;;
        t) THREADS=$OPTARG ;;
        a) APK_FILE=$OPTARG ;; 
        i) IPA_FILE=$OPTARG ;;
        *) log_err "Option not recognized."; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then
    show_banner
    echo -e "Mode of use: ./scanner.sh -d target.com -m 32"
    exit 1
fi

# ESTRUCTURA DE DIRECTORIOS
OUT_DIR="/results/$TARGET"
mkdir -p "$OUT_DIR/recon" "$OUT_DIR/vulns" "$OUT_DIR/secrets" "$OUT_DIR/endpoints" "$OUT_DIR/reports" "$OUT_DIR/.temp"

# --- LÓGICA DE PROVIDER CONFIG (API KEYS) ---
if [ -f "/config/provider-config.yaml" ]; then
    log_success "Provider Config detected. Loading API keys..."
    cp "/config/provider-config.yaml" "/root/.config/subfinder/provider-config.yaml" 2>/dev/null || true
    cp "/config/provider-config.yaml" "/root/.config/nuclei/provider-config.yaml" 2>/dev/null || true
fi

# ============================================================================
# MAIN EXECUTION CASE
# ============================================================================

verify_tools
case "$MODE" in
    # ========================================================================
    # 0-7: RECONNAISSANCE
    # ========================================================================
    0) run_recon_passive ;;
    1) run_recon_active; clean_targets ;;
    2) run_visual_recon ;;
    3) run_param_mining ;;
    4) run_port_scan ;;
    5) run_alternate_recon ;;    # Nelux1 integration
    5) run_alternate_recon ;;    # Nelux1 integration
    6) run_osint_recon ;;        # OSINT Intelligence
    7) run_cms_detection ;;      # CMSeeK CMS Detection
    
    # ========================================================================
    # 10-17: SECRETS & API ANALYSIS
    # ========================================================================
    10) run_secrets_hunter ;;
    11) run_metadata_hunter ;;
    12) run_backup_discovery ;;
    13) run_swagger_discovery ;;
    14) run_graphql_deep ;;
    15) run_jwt_suite ;;
    16) run_oauth_analysis ;;
    # 17) run_ai_hunter ;; # DISABLED UNTIL MODULE RESTORATION
    
    # ========================================================================
    # 20-29: VULNERABILITY HUNTING
    # ========================================================================
    20) run_xss_engine ;;
    21) run_ssrf_storm ;;
    22) run_crlf_scan ;;
    23) run_idor_hunter ;;
    24) run_client_fuzzing ;;     # Open Redirect + Proto Pollution
    25) run_deep_fuzzing ;;       # Unified Strategic Fuzzing (SQLi, SSTI, LFI, CmdInj)
    26) run_403_bypass ;;
    27) run_logic_flaws ;;
    28) run_api_limit_bypass ;;
    29) run_dephunter ;;          # Supply Chain
    
    # ========================================================================
    # 30-39: ELITE SECURITY & ADVANCED
    # ========================================================================
    30) run_http_smuggling ;;
    31) run_cors_testing ;;
    32) run_cache_poisoning ;;
    33) run_race_conditions ;;
    34) run_websocket_analysis ;;
    35) run_bola_bfla ;;
    36) run_postmessage_analyzer ;;
    37) run_blind_xss ;;
    38) run_twofa_bypass ;;
    39) run_hunter_toolkit ;;
    
    # ========================================================================
    # 40-41: INFRASTRUCTURE & CLOUD
    # ========================================================================
    40) run_infrastructure_scan ;;
    40) run_infrastructure_scan ;;
    41) run_subdomain_takeover ;;
    46) run_cloud_enum ;;         # Cloud Bucket Enumeration
    
    # ========================================================================
    # 50-51: MOBILE SECURITY
    # ========================================================================
    50) run_apk_analysis ;;
    51) run_ios_analysis ;;

    # ========================================================================
    # 80-85: AUTOMATED SCAN MODES
    # ========================================================================
    80) # QUICK RECON — Fast surface discovery
        log_phase ">>> MODE 80: QUICK RECON <<<"
        run_recon_passive
        run_recon_active
        clean_targets
        run_visual_recon || true
        run_reporting
        ;;

    81) # VULNERABILITY HUNT — Focused attack surface
        log_phase ">>> MODE 81: VULNERABILITY HUNT <<<"
        if [ "$SKIP_RECON" != "true" ]; then
            run_recon_passive; run_recon_active; clean_targets
        fi
        detect_stack
        run_param_mining || true
        run_xss_engine || true
        run_ssrf_storm || true
        run_crlf_scan || true
        run_idor_hunter || true
        run_403_bypass || true
        run_client_fuzzing || true
        run_deep_fuzzing || true
        run_logic_flaws || true
        run_reporting
        ;;

    82) # SECRETS & API INTEL — Focused intel gathering
        log_phase ">>> MODE 82: SECRETS & API INTEL <<<"
        if [ "$SKIP_RECON" != "true" ]; then
            run_recon_passive; run_recon_active; clean_targets
        fi
        detect_stack
        run_secrets_hunter || true
        run_metadata_hunter || true
        run_backup_discovery || true
        run_swagger_discovery || true
        if [ "$HAS_GRAPHQL" = true ]; then run_graphql_deep || true; fi
        run_jwt_suite || true
        run_oauth_analysis || true
        run_api_limit_bypass || true
        run_bola_bfla || true
        run_reporting
        ;;

    83) # OSINT INTELLIGENCE — Full open-source intel
        log_phase ">>> MODE 83: OSINT INTELLIGENCE <<<"
        run_recon_passive || true
        run_osint_recon || true
        run_cloud_enum || true
        run_metadata_hunter || true
        run_secrets_hunter || true
        run_reporting
        ;;

    84) # ELITE CLASSIC — Full chained workflow
        log_phase ">>> MODE 84: ELITE CLASSIC <<<"
        run_recon_passive
        run_recon_active
        clean_targets
        run_visual_recon || true
        run_param_mining || true
        run_infrastructure_scan || true
        run_idor_hunter || true
        run_xss_engine || true
        run_secrets_hunter || true
        run_ssrf_storm || true
        run_dephunter || true
        run_deep_fuzzing || true
        run_jwt_suite || true
        run_logic_flaws || true
        run_swagger_discovery || true
        run_bola_bfla || true
        run_oauth_analysis || true
        run_reporting
        ;;

    85) # RED TEAM ELITE — ALL-IN OFFENSIVE PIPELINE
        log_phase ">>> RED TEAM ELITE - ALL IN ONE SCAN <<<"
        
        # Show active Smart Flags
        if [ "$DEEP_MODE" = "true" ]; then log_step "FLAG: --deep (extended payloads, SQLi, SSTI, LFI)"; fi
        if [ "$STEALTH_MODE" = "true" ]; then log_step "FLAG: --stealth (rate-limited, evasive)"; fi
        if [ "$WEB_ONLY" = "true" ]; then log_step "FLAG: --web-only (web vulns only)"; fi
        if [ "$SKIP_RECON" = "true" ]; then log_step "FLAG: --no-recon (skipping reconnaissance)"; fi
        if [ "$OSINT_MODE" = "true" ]; then log_step "FLAG: --osint (OSINT intelligence enabled)"; fi
        
        # STEP 0: NELUX1 DEEP RECON
        if [ "$SKIP_RECON" != "true" ]; then
            run_alternate_recon || true
        fi
        
        # STEP 1: FOUNDATION (passive + active recon)
        if [ "$SKIP_RECON" != "true" ]; then
            run_recon_passive
            run_recon_active
            clean_targets
        else
            log_warn "--no-recon: Skipping reconnaissance. Using existing data."
            if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ] && [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
                log_err "No existing recon data found! Remove --no-recon flag."
                exit 1
            fi
        fi
        
        # STEP 1.5: OSINT INTELLIGENCE
        if [ "$OSINT_MODE" = "true" ]; then
            run_osint_recon || true
            run_cloud_enum || true
        fi
        
        # STEP 2: BRAIN (Decision Matrix)
        run_visual_recon || true
        detect_stack
        run_cms_detection || true
        
        # STEP 3: CORE ATTACKS (Context Independent)
        run_metadata_hunter || true
        run_subdomain_takeover || true
        if [ "$WEB_ONLY" != "true" ]; then
            run_infrastructure_scan || true
        fi
        run_403_bypass || true
        
        # STEP 4: TRIGGERED MODULES (Context Dependent)
        if [ "$IS_WORDPRESS" = true ]; then run_wordpress_trigger || true; fi
        if [ "$IS_SPRING" = true ]; then run_spring_trigger || true; fi
        if [ "$HAS_GRAPHQL" = true ]; then run_graphql_trigger || true; fi
        
        # STEP 5: DEEP ATTACKS
        run_param_mining || true
        run_idor_hunter || true
        run_xss_engine || true
        run_secrets_hunter || true
        run_ssrf_storm || true
        run_crlf_scan || true
        run_client_fuzzing || true
        run_jwt_suite || true
        run_logic_flaws || true
        
        # STEP 6: FINALIZATION
        run_dephunter || true
        run_api_limit_bypass || true
        run_oauth_analysis || true
        run_backup_discovery || true
        
        # STEP 7: Elite Differentiators
        run_swagger_discovery || true
        run_bola_bfla || true
        run_race_conditions || true
        run_websocket_analysis || true
        run_deep_fuzzing || true
        run_postmessage_analyzer || true
        run_hunter_toolkit || true
        
        # STEP 8: Advanced Exploits
        run_blind_xss || true
        run_twofa_bypass || true
        
        # Version: v1.2.1a (Emergency Stability Fix)g
        run_http_smuggling || true
        run_cors_testing || true
        run_cache_poisoning || true
        
        # STEP 10: Mobile Analysis (skip if --web-only)
        if [ "$WEB_ONLY" != "true" ]; then
            if [ -n "$APK_FILE" ]; then run_apk_analysis || true; fi
            if [ -n "$IPA_FILE" ]; then run_ios_analysis || true; fi
        fi
        
        # STEP 11: Post-Procesado & Reporte
        run_correlation || true
        run_reporting
        log_success "REDHAVEN ELITE LOGIC COMPLETED"
        ;;

    99) run_reporting ;;

    *) log_err "Error: The mode '$MODE' is not valid."; exit 1 ;;
esac
