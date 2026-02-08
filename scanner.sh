#!/bin/bash

# =======================================================================================
# REDHAVEN 1.0.3 • Offensive Bug Bounty Framework • Elite Red Team Edition • by darkne55
# =======================================================================================


set -euo pipefail

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
    echo -e "${RED}    REDHAVEN v1.0.1 - COMMUNITY EDITION    ${RESET}"
    echo -e "${DIM}Restoring complete logic for /results...${RESET}\n"
}

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
# FUNCIONES MODULARES
# ============================================================================

# ============================================================================
# LOGIC ENGINE & TRIGGERS
# ============================================================================

detect_stack() {
    log_phase "03: TECHNOLOGY DETECTION (DECISION MATRIX)"
    
    if [ ! -s "$OUT_DIR/reports/web_overview.txt" ]; then
        log_warn "No visual recon data found. Skipping technology detection."
        return
    fi

    # Reset vars
    IS_WORDPRESS=false; IS_SPRING=false; HAS_GRAPHQL=false; IS_DOTNET=false; IS_REST=false

    log_step "Analyzing technology stack..."
    
    if grep -qi "WordPress" "$OUT_DIR/reports/web_overview.txt"; then
        IS_WORDPRESS=true
        log_success "DECISION: WordPress detected!"
    fi
    
    if grep -qiE "Spring|Java" "$OUT_DIR/reports/web_overview.txt"; then
        IS_SPRING=true
        log_success "DECISION: Spring Boot detected!"
    fi

    if grep -qi "GraphQL" "$OUT_DIR/reports/web_overview.txt" || grep -qi "graphql" "$OUT_DIR/recon/urls.txt"; then
        HAS_GRAPHQL=true
        log_success "DECISION: GraphQL detected!"
    fi

    if grep -qiE "ASP.NET|Microsoft|IIS" "$OUT_DIR/reports/web_overview.txt"; then
        IS_DOTNET=true
        log_success "DECISION: .NET Infrastructure detected!"
    fi

    if grep -qiE "application/json|swagger|openapi" "$OUT_DIR/reports/web_overview.txt" || grep -qiE "/api/|/v[0-9]/" "$OUT_DIR/recon/urls.txt"; then
        IS_REST=true
        log_success "DECISION: REST API context detected!"
    fi
}

run_wordpress_trigger() {
    log_phase ">>> TRIGGER: WORDPRESS HUNTER <<<"
    log_step "Using Nuclei for specialized WordPress scan..."
    
    # Usamos Nuclei con tags específicos de WordPress (plugins, temas, usuarios, CVEs)
    nuclei -u "$TARGET" -tags wordpress,wp-plugin,wp-theme -o "$OUT_DIR/vulns/wordpress.txt" -bs 10 -c 20 -silent -dr || true
    
    log_success "WordPress detection completed."
}

run_spring_trigger() {
    log_phase ">>> TRIGGER: SPRING BOOT HUNTER <<<"
    log_step "Scanning for Actuators and Hep Dump..."
    nuclei -l "$OUT_DIR/endpoints/alive_urls.txt" -tags spring,actuator,heapdump -o "$OUT_DIR/vulns/spring_boot.txt" -dr || true
}

run_graphql_trigger() {
    log_phase ">>> TRIGGER: GRAPHQL HARVESTER <<<"
    run_graphql_deep
}

# 1-A. RECON PASIVO
run_recon_passive() {
    if check_dependency "$OUT_DIR/recon/urls.txt" "Recon Pasivo"; then return; fi
    log_phase "01.A: Reconnaissance"    
    log_step "Subfinder: Enumerating subdomains..."
    mkdir -p "$OUT_DIR/.temp"
    # Aseguramos que el archivo exista aunque subfinder no encuentre nada
    # Aseguramos que el archivo exista aunque subfinder no encuentre nada
    subfinder -d "$TARGET" -all -silent -o "$OUT_DIR/.temp/subs_main.txt" || touch "$OUT_DIR/.temp/subs_main.txt"
    
    # --- PHASE 2B: ADVANCED SUBDOMAIN ENUMERATION ---
    touch "$OUT_DIR/.temp/subs_extra.txt"

    # 1. GITHUB SUBDOMAINS (Si hay tokens)
    # Buscamos tokens en varias ubicaciones posibles
    TOKENS_FILE=""
    if [ -f "/results/tokens.txt" ]; then TOKENS_FILE="/results/tokens.txt"; fi
    if [ -f "/root/.config/tokens.txt" ]; then TOKENS_FILE="/root/.config/tokens.txt"; fi
    
    if [ -n "$TOKENS_FILE" ]; then
        log_step "GitHub Subdomains: Searching with provided tokens..."
        github-subdomains -d "$TARGET" -t "$TOKENS_FILE" -raw -o "$OUT_DIR/.temp/subs_github.txt" 2>/dev/null || true
        cat "$OUT_DIR/.temp/subs_github.txt" >> "$OUT_DIR/.temp/subs_extra.txt"
        
        log_step "GitLab Subdomains: Searching..."
        gitlab-subdomains -d "$TARGET" -t "$TOKENS_FILE" -raw -o "$OUT_DIR/.temp/subs_gitlab.txt" 2>/dev/null || true
        cat "$OUT_DIR/.temp/subs_gitlab.txt" >> "$OUT_DIR/.temp/subs_extra.txt"
        
        # --- v1.0.3: GITHUB DEEP RECON WITH TRUFFLEHOG ---
        log_step "TruffleHog: Scanning public repositories for secrets..."
        mkdir -p "$OUT_DIR/secrets"
        
        # Extract organization name from domain
        org_name=$(echo "$TARGET" | cut -d'.' -f1)
        
        # TruffleHog GitHub scanning (only verified secrets to reduce noise)
        if command -v trufflehog >/dev/null 2>&1; then
            trufflehog github --org="$org_name" \
                --token="$(head -n1 $TOKENS_FILE)" \
                --json \
                --only-verified \
                > "$OUT_DIR/secrets/github_deep.json" 2>/dev/null || true
            
            # Parse JSON results to human-readable format
            if [ -s "$OUT_DIR/secrets/github_deep.json" ] && command -v jq >/dev/null 2>&1; then
                cat "$OUT_DIR/secrets/github_deep.json" | \
                jq -r '"[" + .DetectorType + "] " + (.Raw // "N/A") + " | Repo: " + (.SourceMetadata.Data.Github.repository // "N/A")' \
                > "$OUT_DIR/secrets/github_deep.txt" 2>/dev/null || true
                
                local secret_count=$(wc -l < "$OUT_DIR/secrets/github_deep.txt" 2>/dev/null || echo 0)
                if [ "$secret_count" -gt 0 ]; then
                    log_stat "GitHub Verified Secrets" "$secret_count"
                fi
            fi
        else
            log_warn "TruffleHog not installed. Skipping deep secret scan."
        fi
    else
        log_warn "No tokens.txt found. Skipping GitHub/GitLab deep search."
    fi
    
    # Combinamos resultados iniciales
    cat "$OUT_DIR/.temp/subs_main.txt" "$OUT_DIR/.temp/subs_extra.txt" | sort -u > "$OUT_DIR/.temp/subs_pre_perm.txt"
    
    # 2. DNSGEN PERMUTATIONS (La clave para encontrar lo oculto)
    local sub_count=$(wc -l < "$OUT_DIR/.temp/subs_pre_perm.txt")
    if [ "$sub_count" -gt 0 ] && [ "$sub_count" -lt 5000 ]; then # Límite de seguridad
        log_step "DNSGen: Generating permutations for $sub_count subdomains..."
        
        # Generamos permutaciones y resolvemos al vuelo con dnsx
        # dnsgen genera muchas basuras, dnsx valida que existan
        dnsgen "$OUT_DIR/.temp/subs_pre_perm.txt" | \
        dnsx -silent -a -aaaa -cname -resp -o "$OUT_DIR/.temp/subs_perm_resolved.txt" 2>/dev/null || true
        
        # Extraemos solo el dominio de la respuesta de dnsx
        if [ -s "$OUT_DIR/.temp/subs_perm_resolved.txt" ]; then
            awk '{print $1}' "$OUT_DIR/.temp/subs_perm_resolved.txt" >> "$OUT_DIR/.temp/subs_pre_perm.txt"
            log_success "Permutations added new variations!"
        fi
    fi
    
    # Consolidación Final
    sort -u "$OUT_DIR/.temp/subs_pre_perm.txt" > "$OUT_DIR/.temp/subs.txt"
    
    # Si sigue vacío, fallback
    if [ ! -s "$OUT_DIR/.temp/subs.txt" ]; then
        echo "$TARGET" > "$OUT_DIR/.temp/subs.txt"
    fi

 
    log_step "Httpx: Locating binary and resolving hosts..."
 
 log_step "Httpx: Resolving alive hosts..."
    
    # Intentamos usar el binario renombrado, si no, buscamos el de Go específicamente
    if command -v httpx-pd >/dev/null; then
        HTTPX_BIN="httpx-pd"
    else
        HTTPX_BIN=$(find /root/go/bin /usr/local/bin -name httpx -type f 2>/dev/null | grep -v "python" | head -n 1)
    fi

  
    [ -z "$HTTPX_BIN" ] && HTTPX_BIN="/root/go/bin/httpx"

    cat "$OUT_DIR/.temp/subs.txt" | $HTTPX_BIN --silent -p 80,443,8080,8443 -o "$OUT_DIR/recon/alive_full.txt"
      
  
    
    if [ -s "$OUT_DIR/recon/alive_full.txt" ]; then
        cat "$OUT_DIR/recon/alive_full.txt" | awk '{print $1}' | sort -u > "$OUT_DIR/recon/urls.txt"
    else
        # Fallback de seguridad para no detener el Modo 2
        echo "https://$TARGET" > "$OUT_DIR/recon/urls.txt"
    fi
    
    log_stat "Initial alive hosts" "$(wc -l < "$OUT_DIR/recon/urls.txt")"
}

# 1-B. PORT SCANNING
run_port_scan() {
    if check_dependency "$OUT_DIR/recon/open_ports.txt" "Port Scan"; then return; fi
    log_phase "01.B: PORT SCANNING"
    
    mkdir -p "$OUT_DIR/recon"
    
    log_step "Naabu: Searching for open ports in subdomains..."
    if [ -s "$OUT_DIR/.temp/subs.txt" ]; then
        naabu -list "$OUT_DIR/.temp/subs.txt" -top-ports 1000 -silent -o "$OUT_DIR/recon/open_ports.txt" || true
        log_stat "Open ports" "$(wc -l < "$OUT_DIR/recon/open_ports.txt" 2>/dev/null || echo 0)"
    else
        touch "$OUT_DIR/recon/open_ports.txt"
    fi
}

# 2. RECON ACTIVO
run_recon_active() {
    run_recon_passive
    run_port_scan
    
    if check_dependency "$OUT_DIR/endpoints/alive_urls.txt" "Recon Activo"; then return; fi
    log_phase "02: HYBRID URL DISCOVERY (KATANA & URLFINDER)"
    
    mkdir -p "$OUT_DIR/.temp"
    
    # 1. URLFINDER (Estático - Busca en JS y código fuente)
    log_step "URLFinder: Mining endpoints in source code..."
    urlfinder -list "$OUT_DIR/recon/urls.txt" -silent -o "$OUT_DIR/.temp/urlfinder_raw.txt" || true
    
    # 2. KATANA (Dinámico - Navegación real)
    log_step "Katana: Dynamic Crawling (Depth 2)..."
    if command -v katana >/dev/null; then KATANA_BIN="katana"; else KATANA_BIN="/root/go/bin/katana"; fi
    
    $KATANA_BIN -list "$OUT_DIR/recon/urls.txt" -d 2 -jc -silent -kf all -ct 10m -o "$OUT_DIR/endpoints/crawled.txt" || true
    
    # 3. WAYBACKURLS (Histórico)
    log_step "Waybackurls: Recovering history..."
    cat "$OUT_DIR/recon/urls.txt" | waybackurls > "$OUT_DIR/.temp/wayback.txt" || true
    
    # 4. FILTRADO & DEDUPLICACIÓN (LA CLAVE DE LA VELOCIDAD)
    log_step "Consolidating and optimizing with Uro..."
    
    # Unimos las 3 fuentes
    cat "$OUT_DIR/endpoints/crawled.txt" "$OUT_DIR/.temp/wayback.txt" "$OUT_DIR/.temp/urlfinder_raw.txt" | sort -u > "$OUT_DIR/.temp/all_raw.txt"
    
    # Agregamos puertos si existen
    if [ -s "$OUT_DIR/recon/open_ports.txt" ]; then 
        cat "$OUT_DIR/recon/open_ports.txt" >> "$OUT_DIR/.temp/all_raw.txt"
    fi

    # Filtro de extensiones basura + URO (Esto reduce de 60k a 2k URLs de calidad)
    grep -viE "\.(jpg|jpeg|png|gif|svg|css|bmp|tif|tiff|woff|woff2|ttf|eot|mp4|mp3|mkv|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|iso|exe|dll|bin)$" \
        "$OUT_DIR/.temp/all_raw.txt" | uro | sort -u > "$OUT_DIR/.temp/clean_candidates.txt"

    log_stat "Raw URLs" "$(wc -l < "$OUT_DIR/.temp/all_raw.txt")"
    log_stat "Unique URLs (Uro)" "$(wc -l < "$OUT_DIR/.temp/clean_candidates.txt")"
    
    # 5. HTTPX: Validación final
    log_step "Httpx: Validation of active URLs..."
    if command -v httpx-pd >/dev/null; then HTTPX_BIN="httpx-pd"; else
        HTTPX_BIN=$(find /root/go/bin /usr/local/bin -name httpx -type f 2>/dev/null | grep -v "python" | head -n 1)
    fi
    [ -z "$HTTPX_BIN" ] && HTTPX_BIN="/root/go/bin/httpx"

    $HTTPX_BIN -list "$OUT_DIR/.temp/clean_candidates.txt" \
        -mc 200,403,301,302,401,500,400,404 \
        -threads 60 -timeout 5 -retries 1 \
        -silent -o "$OUT_DIR/endpoints/alive_urls.txt"
    
    log_stat "Final live endpoints" "$(wc -l < "$OUT_DIR/endpoints/alive_urls.txt")"
    
    # --- FEATURES REQUESTED: STATUS CODE SPLITTING ---
    log_step "Categorizing URLs by Status Code for Manual Review..."
    mkdir -p "$OUT_DIR/recon/status_codes"
    
    # Re-run httpx fast just to get codes and split them (using pipelining)
    # We use the already alive_urls.txt to be faster
    $HTTPX_BIN -l "$OUT_DIR/endpoints/alive_urls.txt" -status-code -silent -no-color | while read -r line; do
        url=$(echo "$line" | awk '{print $1}')
        code=$(echo "$line" | awk '{print $2}' | tr -d '[]')
        
        if [[ "$code" == "200" ]]; then
            echo "$url" >> "$OUT_DIR/recon/status_codes/200_ok.txt"
        elif [[ "$code" =~ ^3 ]]; then
            echo "$url" >> "$OUT_DIR/recon/status_codes/3xx_redirects.txt"
        elif [[ "$code" == "401" ]]; then
            echo "$url" >> "$OUT_DIR/recon/status_codes/401_auth_required.txt"
        elif [[ "$code" == "403" ]]; then
            echo "$url" >> "$OUT_DIR/recon/status_codes/403_forbidden.txt"
        elif [[ "$code" == "404" ]]; then
            echo "$url" >> "$OUT_DIR/recon/status_codes/404_not_found.txt"
        elif [[ "$code" =~ ^5 ]]; then
            echo "$url" >> "$OUT_DIR/recon/status_codes/5xx_errors.txt"
        else
            echo "$url" >> "$OUT_DIR/recon/status_codes/other_codes.txt"
        fi
    done
}

# LIMPIEZA Y FILTRADO
clean_targets() {
    log_phase "TARGET CLEANING & DATA EXTRACTION"
    
    if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No live URLs found. Skipping cleanup."
        touch "$OUT_DIR/endpoints/clean_urls.txt" "$OUT_DIR/endpoints/params_only.txt" "$OUT_DIR/endpoints/js_files.txt"
        return
    fi
    
    log_step "Removing static files from the attack list..."
    local EXTS="jpg|jpeg|png|svg|gif|webp|ico|woff|woff2|ttf|eot|css|mp4|mp3|flv|avi|wmv|zip|gz|rar|pdf|doc|docx|xls|xlsx"
    
    grep -vE "\.($EXTS)(\?|$)" "$OUT_DIR/endpoints/alive_urls.txt" > "$OUT_DIR/endpoints/clean_urls.txt" || true
    
    log_step "Extracting URLs with parameters (Intelligent Deduplication)..."
    # AQUI ESTA EL CAMBIO: Usamos 'uro' para guardar solo estructuras únicas
    grep "?" "$OUT_DIR/endpoints/alive_urls.txt" | uro > "$OUT_DIR/endpoints/params_only.txt" || true
    
    log_step "Extracting libraries and JS files..."
    grep -iE "\.js(\?|$)" "$OUT_DIR/endpoints/alive_urls.txt" | cut -d '?' -f 1 | sort -u > "$OUT_DIR/endpoints/js_files.txt" || true
    
    touch "$OUT_DIR/endpoints/clean_urls.txt" "$OUT_DIR/endpoints/params_only.txt" "$OUT_DIR/endpoints/js_files.txt"
}

# 3. VISUAL RECON
run_visual_recon() {
    # Verificamos si ya existe el reporte
    if check_dependency "$OUT_DIR/reports/web_overview.txt" "Visual Recon (Lite)"; then return; fi
    
    log_phase "03: RECON METADATA & TITLES"
    
    if [ ! -s "$OUT_DIR/recon/urls.txt" ]; then
        log_warn "No URLs from passive recon. Skipping visual reconnaissance."
        touch "$OUT_DIR/reports/web_overview.txt"
        return
    fi
    
    mkdir -p "$OUT_DIR/reports"
    
    log_step "Httpx: Extracting Titles, Servers and Technologies (No Screenshots)..."
    
    # BUSCADOR DE BINARIO (Igual que en fase 1 y 2 para evitar errores)
    if command -v httpx-pd >/dev/null; then HTTPX_BIN="httpx-pd"; else
        HTTPX_BIN=$(find /root/go/bin /usr/local/bin -name httpx -type f 2>/dev/null | grep -v "python" | head -n 1)
    fi
    [ -z "$HTTPX_BIN" ] && HTTPX_BIN="/root/go/bin/httpx"

    # EJECUCIÓN LIGERA
    # -title: Obtiene el <title> de la web
    # -tech-detect: Identifica si usan React, PHP, AWS, etc.
    # -status-code: Para ver si es 200, 403, etc.
    # -follow-redirects: Sigue redirecciones para ver el destino final
    $HTTPX_BIN -list "$OUT_DIR/recon/urls.txt" \
        -title -tech-detect -status-code -web-server -follow-redirects \
        -threads 50 \
        -no-color -o "$OUT_DIR/reports/web_overview.txt"
    
    log_success "Visual recognition complete. Summary saved in reports/web_overview.txt"
    
    # Mostramos una vista previa de 5 líneas para que veas qué encontró
    echo -e "\n${DIM}--- Report Preview ---${RESET}"
    head -n 5 "$OUT_DIR/reports/web_overview.txt"
    echo -e "${DIM}--------------------------------${RESET}\n"
}

# 39. HUNTER'S TOOLKIT (Phase 2C Extension)
run_hunter_toolkit() {
    log_phase "39: HUNTER'S TOOLKIT (UNICODE/EMAIL/CLICKJACKING)"
    
    # 1. Clickjacking & Uploads on Base Domain
    python3 /usr/local/bin/hunter_toolkit -u "https://$TARGET" || true
    
    # 2. Param Fuzzing on Collected URLs
    if [ -f "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_step "Running Unicode/Email injection on discovered parameters..."
        python3 /usr/local/bin/hunter_toolkit -u "https://$TARGET" -l "$OUT_DIR/endpoints/clean_urls.txt" || true
    else
        log_warn "No URL list found for param fuzzing. Testing root only."
    fi
}

# --------------------------------------------------------
# 9. UTILS & REPORTING
# --------------------------------------------------------

# 4. METADATA HUNTER
run_metadata_hunter() {
    log_phase "04: METADATA & SENSITIVE FILES"
    
    if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No alive URLs found for metadata extraction. Skipping phase."
        return
    fi
    
    log_step "Searching for documents and media files..."
    grep -iE '\.(pdf|docx|xlsx|jpg|png|zip|sql|tar|gz)' "$OUT_DIR/endpoints/alive_urls.txt" > "$OUT_DIR/vulns/files_to_check.txt" || true
    
    if [ -s "$OUT_DIR/vulns/files_to_check.txt" ]; then
        log_step "Analyzing metadata with ExifTool..."
        # Lógica simplificada: listar archivos encontrados
        log_stat "Files detected" "$(wc -l < "$OUT_DIR/vulns/files_to_check.txt")"
    fi
    
    # --- v1.0.3: CI/CD CONFIGURATION DISCOVERY ---
    log_step "Searching for CI/CD configuration files..."
    
    # CI/CD config paths to test
    CICD_PATHS=(
        ".gitlab-ci.yml"
        ".gitlab-ci.yaml"
        ".github/workflows/main.yml"
        ".github/workflows/ci.yml"
        ".github/workflows/deploy.yml"
        ".github/workflows/build.yml"
        ".github/workflows/release.yml"
        "Jenkinsfile"
        "azure-pipelines.yml"
        ".circleci/config.yml"
        ".drone.yml"
        ".travis.yml"
        "bitbucket-pipelines.yml"
        ".buildkite/pipeline.yml"
        "wercker.yml"
        "codefresh.yml"
        ".teamcity/settings.kts"
    )
    
    mkdir -p "$OUT_DIR/.temp"
    > "$OUT_DIR/.temp/cicd_tests.txt"
    
    # Generate test URLs from base domains
    while IFS= read -r url; do
        # Extract base URL (remove paths)
        base_url=$(echo "$url" | sed 's|^\(https\?://[^/]*\).*|\1|')
        
        # Test each CI/CD path
        for path in "${CICD_PATHS[@]}"; do
            echo "${base_url}/${path}" >> "$OUT_DIR/.temp/cicd_tests.txt"
        done
    done < "$OUT_DIR/recon/urls.txt"
    
    # Test with httpx
    if [ -s "$OUT_DIR/.temp/cicd_tests.txt" ]; then
        if command -v httpx-pd >/dev/null; then HTTPX_BIN="httpx-pd"; else
            HTTPX_BIN=$(find /root/go/bin /usr/local/bin -name httpx -type f 2>/dev/null | grep -v "python" | head -n 1)
        fi
        [ -z "$HTTPX_BIN" ] && HTTPX_BIN="/root/go/bin/httpx"
        
        $HTTPX_BIN -list "$OUT_DIR/.temp/cicd_tests.txt" \
            -mc 200 \
            -silent \
            -threads 30 \
            -o "$OUT_DIR/vulns/cicd_exposure.txt" 2>/dev/null || true
        
        if [ -s "$OUT_DIR/vulns/cicd_exposure.txt" ]; then
            local cicd_count=$(wc -l < "$OUT_DIR/vulns/cicd_exposure.txt")
            log_stat "CI/CD Configs Exposed" "$cicd_count"
            log_warn "CRITICAL: CI/CD files may contain secrets!"
        fi
    fi
}

# 5. PARAM MINING
run_param_mining() {
    if check_dependency "$OUT_DIR/endpoints/params_only.txt" "Param Mining"; then return; fi
    log_phase "05: HYBRID PARAM MINING"
    
    # Non-fatal check
    if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No live endpoints found for param mining. Skipping phase."
        touch "$OUT_DIR/endpoints/params_only.txt"
        return
    fi
    
    log_step "ParamSpider: Extracting historical parameters..."
    # Ejecutamos paramspider. Si falla (ej: 0 resultados), no detenemos el script (|| true)
    # ParamSpider v3 usa --domain y --exclude
    paramspider -d "$TARGET" || true
    
    # ParamSpider guarda en output/{domain}.txt o results/{domain}.txt dependiendo de la versión
    if [ -f "results/$TARGET.txt" ]; then 
        cat "results/$TARGET.txt" >> "$OUT_DIR/endpoints/params_only.txt"
        rm -rf results/
    elif [ -f "output/$TARGET.txt" ]; then
        cat "output/$TARGET.txt" >> "$OUT_DIR/endpoints/params_only.txt"
        rm -rf output/
    fi
    
    log_step "Arjun: Discovering hidden parameters (Mode: Passive+Active)..."
    
    # TRUCO PRO: Arjun falla si le pasas solo el dominio. Necesita un endpoint.
    # Usamos los endpoints vivos encontrados en la Fase 2 en lugar de solo urls.txt
    if [ -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        # Tomamos las 5 URLs más interesantes (api, v1, auth) para no saturar
        grep -iE "api|v1|auth|user" "$OUT_DIR/endpoints/alive_urls.txt" | head -n 5 > "$OUT_DIR/.temp/arjun_targets.txt" || true
        
        # Si no hay interesantes, tomamos las primeras 5 cualquiera
        if [ ! -s "$OUT_DIR/.temp/arjun_targets.txt" ]; then
             head -n 5 "$OUT_DIR/endpoints/alive_urls.txt" > "$OUT_DIR/.temp/arjun_targets.txt"
        fi

        # Ejecutamos Arjun con:
        # -t 2: Pocos hilos para no ser baneados
        # -d 1: Delay de 1 segundo entre peticiones (Crucial para Fireblocks)
        # --disable-redirects: Para evitar bucles raros
        cat "$OUT_DIR/.temp/arjun_targets.txt" | parallel -j 1 "arjun -u {} -oJ $OUT_DIR/vulns/params_{#}.json -t 2 -d 1 --disable-redirects" || true
    else
        log_warn "No live endpoints were found for Arjun. Jumping..."
    fi
    
    touch "$OUT_DIR/endpoints/params_only.txt"
}

# 6. INFRASTRUCTURE SCAN
run_infrastructure_scan() 
{
    if check_dependency "$OUT_DIR/vulns/infrastructure_findings.txt" "Infrastructure Scan"; then return; fi
    
    log_phase "06: INFRASTRUCTURE & CLOUD SCAN"
    
    if [ ! -s "$OUT_DIR/recon/urls.txt" ]; then
        log_warn "No URLs found for infrastructure testing. Skipping phase."
        touch "$OUT_DIR/vulns/infrastructure_findings.txt"
        return
    fi
    
    log_step "Nuclei: Finding bugs in S3 Buckets, Azure, GCP and Smuggling..."
    nuclei -l "$OUT_DIR/recon/urls.txt" -tags cloud,s3,bucket,azure,gcp,firebase,cors,cache,smuggling -o "$OUT_DIR/vulns/infrastructure_findings.txt" -c 50 -bs 25 -silent -dr
    
    # --- v1.0.3: S3 BUCKET BRUTEFORCE ---
    log_step "S3 Bruteforce: Testing bucket permutations..."
    if [ -f "/usr/local/bin/s3_bruteforce.py" ] || [ -f "./s3_bruteforce.py" ]; then
        S3_SCRIPT="/usr/local/bin/s3_bruteforce.py"
        [ ! -f "$S3_SCRIPT" ] && S3_SCRIPT="./s3_bruteforce.py"
        
        python3 "$S3_SCRIPT" "$TARGET" \
            "$OUT_DIR/vulns/s3_bruteforce.txt" \
            "$THREADS" 2>/dev/null || true
    else
        log_warn "s3_bruteforce.py not found. Skipping S3 discovery."
    fi
    
    # --- v1.0.3: CVE AUTO-MATCHING ---
    # Execute after visual recon to ensure tech versions are detected
    if [ -f "$OUT_DIR/reports/web_overview.txt" ]; then
        log_step "CVE Matcher: Correlating detected versions with CVEs..."
        if [ -f "/usr/local/bin/cve_matcher.py" ] || [ -f "./cve_matcher.py" ]; then
            CVE_SCRIPT="/usr/local/bin/cve_matcher.py"
            [ ! -f "$CVE_SCRIPT" ] && CVE_SCRIPT="./cve_matcher.py"
            
            python3 "$CVE_SCRIPT" "$OUT_DIR" 2>/dev/null || true
        else
            log_warn "cve_matcher.py not found. Skipping CVE correlation."
        fi
    fi
}

# 7. IDOR HUNTER
run_idor_hunter() {
    if check_dependency "$OUT_DIR/vulns/idor_candidates.txt" "IDOR Hunter"; then return; fi
    
    log_phase "07: IDOR & AUTH BYPASS HUNTER"
    
    # Non-fatal check
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for IDOR analysis. Skipping phase."
        touch "$OUT_DIR/vulns/idor_candidates.txt"
        return
    fi
    
    log_step "Looking for numerical patterns and UUIDs..."
    
    mkdir -p "$OUT_DIR/.temp"
    
    # 1. Extracción Cruda (Lo que ya tenías)
    # Busca: param=numero | /numero/ | UUIDs
    grep -E "(=[0-9]+|/[0-9]+$|/[0-9]+/[a-zA-Z]|=[a-f0-9-]{36})" "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/idor_raw.txt" || true
    
    # 2. FILTRO DE RUIDO (La Magia)
    # Eliminamos parámetros que NO son riesgosos (paginación, UI, timestamps, versiones)
    log_step "Filtering false positives (Pagination, UI, Timestamps)..."
    
    grep -viE "page=|p=|limit=|size=|offset=|width=|height=|lang=|v=|ver=|version=|timestamp=|date=|year=|month=|day=|time=|utm_|fbclid|gclid" \
        "$OUT_DIR/.temp/idor_raw.txt" > "$OUT_DIR/vulns/idor_candidates.txt" || true
        
    local raw_count=$(wc -l < "$OUT_DIR/.temp/idor_raw.txt")
    local final_count=$(wc -l < "$OUT_DIR/vulns/idor_candidates.txt")
    
    log_stat "Raw candidates" "$raw_count"
    log_stat "Actual candidates (Filtered)" "$final_count"
    log_success "IDOR analysis completed."
}

# 8. XSS ENGINE
run_xss_engine() {
    if check_dependency "$OUT_DIR/vulns/xss.txt" "XSS Engine"; then return; fi
    log_phase "08: XSS INJECTION ENGINE (KXSS + DALFOX + PORTSWIGGER)"
    
    # Non-fatal check for parameters
    if [ ! -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_warn "No parameters found for XSS testing. Skipping phase."
        touch "$OUT_DIR/vulns/xss.txt"
        return
    fi
    
    # 1. Descargar wordlist de PortSwigger si no existe
    local XSS_WORDLIST="/tools/wordlists/xss-portswigger.txt"
    if [ ! -f "$XSS_WORDLIST" ]; then
        log_step "Downloading XSS Cheat Sheet from PortSwigger..."
        mkdir -p "/tools/wordlists"
        curl -s "https://raw.githubusercontent.com/theMiddleBlue/DNSC-XSS-Payloads/master/payloads.txt" -o "$XSS_WORDLIST" || true
    fi

    log_step "KXSS: Analyzing reflections on parameters..."
   cat "$OUT_DIR/endpoints/params_only.txt" | uro | kxss | awk '{print $NF}' | sort -u > "$OUT_DIR/.temp/kxss_reflective.txt" || true
    
    if [ -s "$OUT_DIR/.temp/kxss_reflective.txt" ]; then
        log_stat "Candidates with reflection" "$(wc -l < "$OUT_DIR/.temp/kxss_reflective.txt")"
        log_step "Dalfox: Launching PortSwigger payloads..."
                  
        cat "$OUT_DIR/.temp/kxss_reflective.txt" | dalfox pipe \
            --custom-payload "$XSS_WORDLIST" \
            --worker 40 \
            -o "$OUT_DIR/vulns/xss.txt" || true
    else
        log_warn "No reflections detected. Skipping payload attack."
        touch "$OUT_DIR/vulns/xss.txt"
    fi
    log_success "XSS Engine completed."
}

# 9. SECRETS HUNTER
run_secrets_hunter() {
    if check_dependency "$OUT_DIR/secrets/js_secrets.txt" "Secrets Hunter"; then return; fi
    log_phase "09: SECRETS & LEAKED KEYS (DEEP JS ANALYSIS)"
    
    log_step "Consolidating JS and Sourcemap files..."
    rm -f "$OUT_DIR/endpoints/js_targets.txt" || true
    
    # 1. Recopilar todos los JS encontrados en Recon
    grep -iE "\.js(\?|$)" "$OUT_DIR/endpoints/alive_urls.txt" | sort -u > "$OUT_DIR/endpoints/js_targets.txt" || true
    cat "$OUT_DIR/endpoints/js_files.txt" >> "$OUT_DIR/endpoints/js_targets.txt" 2>/dev/null || true
    sort -u "$OUT_DIR/endpoints/js_targets.txt" -o "$OUT_DIR/endpoints/js_targets.txt"
    
    local js_count=$(wc -l < "$OUT_DIR/endpoints/js_targets.txt")
    log_stat "JS Files to Analyze" "$js_count"
    
    if [ "$js_count" -gt 0 ]; then
    
        # A. MANTRA (Si está instalado)
        if [ -d "/tools/Mantra" ]; then
            log_step "Mantra: Hunting for API keys and secrets in JS..."
            # Mantra es muy ruidoso, filtramos un poco
            # Usamos parallel para velocidad si son muchos, o directo si son pocos.
            # Mantra toma URL directa.
            
            # Nota: Mantra busca secretos en el código fuente de la página/js.
            cat "$OUT_DIR/endpoints/js_targets.txt" | parallel -j 10 --timeout 60 "python3 /tools/Mantra/Mantra.py -u {} 2>/dev/null" >> "$OUT_DIR/secrets/mantra_raw.txt" || true
            
            # Limpieza básica de Mantra
            if [ -s "$OUT_DIR/secrets/mantra_raw.txt" ]; then
                grep -E "API_KEY|SECRET|TOKEN|PASSWORD" "$OUT_DIR/secrets/mantra_raw.txt" > "$OUT_DIR/secrets/mantra_findings.txt" || true
                local mantra_found=$(wc -l < "$OUT_DIR/secrets/mantra_findings.txt")
                log_stat "Mantra Findings" "$mantra_found"
            fi
        else
            log_warn "Mantra tool not found. Skipping."
        fi

        # B. LINKFINDER (Si está instalado)
        if [ -d "/tools/LinkFinder" ]; then
             log_step "LinkFinder: Extracting hidden endpoints from JS..."
             mkdir -p "$OUT_DIR/.temp/linkfinder"
             
             # Tomamos top 20 JS más grandes/relevantes para no tardar años (LinkFinder es lento)
             head -n 20 "$OUT_DIR/endpoints/js_targets.txt" > "$OUT_DIR/.temp/js_top20.txt"
             
             cat "$OUT_DIR/.temp/js_top20.txt" | parallel -j 5 "python3 /tools/LinkFinder/linkfinder.py -i {} -o cli >> $OUT_DIR/endpoints/linkfinder_endpoints.txt 2>/dev/null" || true
             
             # Limpiamos resultados ruidosos
             grep -v "Running against:" "$OUT_DIR/endpoints/linkfinder_endpoints.txt" | grep -v "Invalid input" | sort -u -o "$OUT_DIR/endpoints/linkfinder_endpoints.txt"
             
             local lf_count=$(wc -l < "$OUT_DIR/endpoints/linkfinder_endpoints.txt")
             log_stat "LinkFinder New Endpoints" "$lf_count"
             
             # Feedback Loop: Agregar estos endpoints nuevos al recon
             if [ "$lf_count" -gt 0 ]; then
                 cat "$OUT_DIR/endpoints/linkfinder_endpoints.txt" >> "$OUT_DIR/endpoints/clean_urls.txt"
             fi
        fi
        
        # C. JSLUICE (Si está instalado - Nuevo Phase 2B)
        if command -v jsluice >/dev/null; then
            log_step "JSLuice: Tree-sitter analysis for secrets..."
            # Necesitamos descargar los JS primero para JSLuice o usar pipe curl
            mkdir -p "$OUT_DIR/.temp/js_download"
            
            # Descargar top 50 JS
            head -n 50 "$OUT_DIR/endpoints/js_targets.txt" | parallel -j 20 "wget -q -P $OUT_DIR/.temp/js_download {}" || true
            
            # Analizar carpeta
            jsluice secrets -r "$OUT_DIR/.temp/js_download" > "$OUT_DIR/secrets/jsluice_secrets.json" 2>/dev/null || true
            
            # Extraer info útil del JSON
            if [ -s "$OUT_DIR/secrets/jsluice_secrets.json" ]; then
                 jq -r '"\(.severity) - \(.kind) - \(.data)"' "$OUT_DIR/secrets/jsluice_secrets.json" | sort -u > "$OUT_DIR/secrets/jsluice_summary.txt" || true
                 log_stat "JSLuice Findings" "$(wc -l < "$OUT_DIR/secrets/jsluice_summary.txt")"
            fi
        fi

    else
        log_warn "No JS files found for analysis."
    fi
    
    if [ -s "$OUT_DIR/endpoints/secrets_targets.txt" ]; then
        log_step "Nuclei: Scanning tokens and private keys..."
        nuclei -l "$OUT_DIR/endpoints/secrets_targets.txt" -tags token,keys,exposure -c 50 -rl 150 -o "$OUT_DIR/secrets/js_secrets.txt" -dr || true
    fi
    
    log_step "Gitleaks: Searching for secrets in downloaded files..."
    gitleaks detect --source="$OUT_DIR" --no-git --report-path "$OUT_DIR/secrets/gitleaks_report.json" || true
    log_success "Secrets Hunter completed."
}

# 10. SSRF STORM
run_ssrf_storm() {
    log_phase "10: SSRF & REDIRECT STORM"
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for SSRF testing. Skipping phase."
        return
    fi
    
    log_step "Nuclei: Scanning for SSRF vulnerabilities..."
    nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" -tags ssrf -c 50 -rl 150 -o "$OUT_DIR/vulns/ssrf.txt" -dr -duc || true
    log_success "SSRF Storm completed."
}

# 11. CRLF INJECTION
run_crlf_scan() {
    if check_dependency "$OUT_DIR/vulns/crlf.txt" "CRLF Injection"; then return; fi
    
    log_phase "11: CRLF INJECTION (NINJA MODE)"
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for CRLF testing. Skipping phase."
        touch "$OUT_DIR/vulns/crlf.txt"
        return
    fi
    
    mkdir -p "$OUT_DIR/.temp"
    log_step "Filtering and deduplicating parameters with Uro..."

    # Filtro: Parámetros y Redirecciones + Deduplicación de estructura
    grep -iE "\?|redir|url=|next=|dest=|destination=|out=|view=|from=|callback=|checkout=|logout=" \
        "$OUT_DIR/endpoints/clean_urls.txt" | uro | sort -u > "$OUT_DIR/.temp/crlf_targets.txt"

    local total=$(wc -l < "$OUT_DIR/endpoints/clean_urls.txt")
    local optimized=$(wc -l < "$OUT_DIR/.temp/crlf_targets.txt")
    
    log_stat "Input URLs" "$total"
    log_stat "Unique Targets (Uro)" "$optimized"

    if [ "$optimized" -gt 0 ]; then
        log_step "CRLFuzz: Starting quick scan..."
        crlfuzz -l "$OUT_DIR/.temp/crlf_targets.txt" -o "$OUT_DIR/vulns/crlf.txt" -s || true
        
        local found=$(wc -l < "$OUT_DIR/vulns/crlf.txt" 2>/dev/null || echo 0)
        log_stat "CRLF Vulnerabilities" "$found"
        log_success "CRLF Scan completed."
    else
        log_warn "No unique targets for CRLF were detected."
        echo "# No CRLF targets found" > "$OUT_DIR/vulns/crlf.txt"
    fi
}

# 12. SUPPLY CHAIN (CORREGIDO - REGEX FIX)
run_dephunter() {
    if check_dependency "$OUT_DIR/vulns/supply_chain.txt" "Supply Chain"; then return; fi
    
    log_phase "12: SUPPLY CHAIN & REPO EXPOSURE (ROOTS ONLY)"
    
    # 0. Validación
    if [ ! -s "$OUT_DIR/recon/urls.txt" ] && [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No URL files were found."
        return 1
    fi
    
    log_step "Selecting only Roots and Level 1 Directories..."
    mkdir -p "$OUT_DIR/.temp"
    : > "$OUT_DIR/.temp/supply_raw.txt"
    
    # A. Subdominios base
    if [ -s "$OUT_DIR/recon/urls.txt" ]; then
        cat "$OUT_DIR/recon/urls.txt" >> "$OUT_DIR/.temp/supply_raw.txt" || true
    fi

    # B. Extraemos URLs vivas (Nivel 1)
    if [ -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        # Awk para extraer solo hasta la primera carpeta
        awk -F/ '{print $1"//"$3"/"$4}' "$OUT_DIR/endpoints/alive_urls.txt" | sort -u >> "$OUT_DIR/.temp/supply_raw.txt" || true
    fi

    # C. LIMPIEZA CORREGIDA (Aquí estaba el error)
    # Antes: grep -vE "\." (Borraba todo lo que tuviera un punto, incluidos dominios)
    # Ahora: Filtramos solo si termina en extensiones basura conocidas
    
    if [ -s "$OUT_DIR/.temp/supply_raw.txt" ]; then
        grep -viE "\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|eot|pdf)$" "$OUT_DIR/.temp/supply_raw.txt" | sort -u > "$OUT_DIR/.temp/supply_targets.txt" || true
    else
        touch "$OUT_DIR/.temp/supply_targets.txt"
    fi
    
    local count=$(wc -l < "$OUT_DIR/.temp/supply_targets.txt")
    log_stat "Supply Chain Targets (Reduced)" "$count"
    
    # 2. Escaneo
    if [ "$count" -gt 0 ]; then
        log_step "Running Nuclei on critical targets (Optimized)..."
        nuclei -l "$OUT_DIR/.temp/supply_targets.txt" \
            -tags config,cicd,keys,git,svn,env,credential \
            -timeout 4 -retries 0 -mhe 2 \
            -c 30 -rl 150 \
            -o "$OUT_DIR/vulns/supply_chain.txt" \
            -dr -silent || true
            
        log_success "Supply Chain completed."
    else
        log_warn "There are no valid objectives for Supply Chain."
        echo "# No targets found" > "$OUT_DIR/vulns/supply_chain.txt"
    fi
}

# 17. UNIFIED STRATEGIC FUZZING (Phase 2B - Orchestrator)
run_deep_fuzzing() {
    log_phase "17: UNIFIED STRATEGIC FUZZING"
    
    # Aseguramos que el stack esté detectado
    detect_stack

    # 1. FUZZING DE DIRECTORIOS (CONTEXTUAL)
    WORDLIST="/tools/Assetnote/best_directories.txt"
    if [ "$IS_REST" = true ]; then
        log_step "Context: REST/API. Using API wordlists..."
        WORDLIST="/tools/Assetnote/best_api.txt"
    fi
    
    log_step "Strategy 1: Feroxbuster Contextual Directory Fuzzing..."
    feroxbuster -u "https://$TARGET" -w "$WORDLIST" -t 20 --filter-status 404 -r --silent -o "$OUT_DIR/recon/deep_fuzzing.txt" || true

    # 2. INTELLIGENT PARAMETER FUZZING (DSSS / COMMIX / TPLMAP)
    if [ ! -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_warn "No parameters found for intelligent fuzzing. Skipping parameter-based attacks."
        return
    fi
    mkdir -p "$OUT_DIR/.temp"

    # A. SQL Injection (DSSS)
    log_step "Strategy 2: Targetted SQLi Probe (DSSS)..."
    # Filtrado inteligente según el stack
    if [ "$IS_DOTNET" = true ]; then
        grep -iE "\.aspx|\.asmx|\.svc" "$OUT_DIR/endpoints/params_only.txt" | head -n 20 > "$OUT_DIR/.temp/sqli_strat.txt" || true
    else
        grep -iE "\.php|\.jsp|\.cfm|=([0-9]+)$" "$OUT_DIR/endpoints/params_only.txt" | head -n 30 > "$OUT_DIR/.temp/sqli_strat.txt" || true
    fi
    
    if [ -s "$OUT_DIR/.temp/sqli_strat.txt" ]; then
        cat "$OUT_DIR/.temp/sqli_strat.txt" | parallel -j 5 "python3 /usr/local/bin/dsss -u {} >> $OUT_DIR/vulns/dsss_sqli.txt 2>/dev/null" || true
    fi

    # B. Command Injection (Commix)
    log_step "Strategy 3: Targeted CmdInj Probe (Commix)..."
    grep -iE "cmd=|exec=|command=|ping=|query=|file=|read=|img=|log=|report=" "$OUT_DIR/endpoints/params_only.txt" | head -n 10 > "$OUT_DIR/.temp/commix_strat.txt" || true
    
    if [ -s "$OUT_DIR/.temp/commix_strat.txt" ]; then
        while IFS= read -r url; do
            commix --url="$url" --batch --level 1 --output-dir "$OUT_DIR/.temp/commix_logs" > /dev/null || true
        done < "$OUT_DIR/.temp/commix_strat.txt"
        grep -r "Result: detected" "$OUT_DIR/.temp/commix_logs" > "$OUT_DIR/vulns/commix_rce.txt" 2>/dev/null || true
    fi

    # C. Template Injection (Tplmap)
    log_step "Strategy 4: Targeted SSTI Probe (Tplmap)..."
    grep -iE "template=|theme=|view=|page=|name=|msg=|message=" "$OUT_DIR/endpoints/params_only.txt" | head -n 10 > "$OUT_DIR/.temp/ssti_strat.txt" || true
    if [ -s "$OUT_DIR/.temp/ssti_strat.txt" ]; then
         while IFS= read -r url; do
            python3 /usr/local/bin/tplmap -u "$url" >> "$OUT_DIR/vulns/ssti.txt" 2>/dev/null || true
         done < "$OUT_DIR/.temp/ssti_strat.txt"
    fi

    log_success "Unified Strategic Fuzzing completed."
}

# 14. 403 ACCESS BYPASS (OPTIMIZADO CON PARALLEL)
run_403_bypass() {
    if check_dependency "$OUT_DIR/vulns/bypass_403.txt" "403 Bypass"; then return; fi
    
    log_phase "14: 403/401 ACCESS BYPASS (NOMORE403)"
    
    # Extraemos URLs únicas con errores de acceso
    grep -E "403|401" "$OUT_DIR/endpoints/alive_urls.txt" | awk '{print $1}' | sort -u > "$OUT_DIR/.temp/forbidden_urls.txt" || true
    
    local count=$(wc -l < "$OUT_DIR/.temp/forbidden_urls.txt")
    
    if [ "$count" -gt 0 ]; then
        log_step "Starting bypass on $count targets..."
        
        # Guardamos ruta actual
        local OLD_PWD=$(pwd)
        cd /tools/nomore403
        
        # Limpiamos archivo
        : > "$OUT_DIR/vulns/bypass_403.txt"
        
        # USO DE PARALLEL PARA EVITAR OOM (OUT OF MEMORY) KILLER
        # -j 10: Máximo 10 procesos simultáneos (evita saturar RAM)
        # --timeout 60: Si se cuelga, lo mata al minuto
        
        cat "$OUT_DIR/.temp/forbidden_urls.txt" | parallel -j 10 --timeout 60 \
            "/usr/local/bin/nomore403 -u {} >> $OUT_DIR/vulns/bypass_403.txt 2>/dev/null" || true
        
        cd "$OLD_PWD"
        
        if [ ! -s "$OUT_DIR/vulns/bypass_403.txt" ]; then
             echo "# Scan completed. No bypasses found." > "$OUT_DIR/vulns/bypass_403.txt"
        fi

        # --- FEEDBACK LOOP ---
        if grep -q "200 OK" "$OUT_DIR/vulns/bypass_403.txt"; then
             log_success "${ACCENT}BYPASS SUCCESSFUL! Feeding back new endpoints...${RESET}"
             grep "200 OK" "$OUT_DIR/vulns/bypass_403.txt" | awk '{print $2}' >> "$OUT_DIR/endpoints/clean_urls.txt"
             grep "200 OK" "$OUT_DIR/vulns/bypass_403.txt" | awk '{print $2}' >> "$OUT_DIR/endpoints/alive_urls.txt"
             sort -u "$OUT_DIR/endpoints/clean_urls.txt" -o "$OUT_DIR/endpoints/clean_urls.txt"
             sort -u "$OUT_DIR/endpoints/alive_urls.txt" -o "$OUT_DIR/endpoints/alive_urls.txt"
        fi
        
        log_success "Bypass completed. Results in vulns/bypass_403.txt"
    else
        log_warn "No 403 URLs were found to process."
        echo "# No 403 targets found." > "$OUT_DIR/vulns/bypass_403.txt"
    fi
}

# 15. JWT ATTACK
run_jwt_suite() {
    log_phase "15: JWT SECURITY ATTACKS"
    log_step "Extracting live JWT tokens..."
    grep -oP 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' "$OUT_DIR/endpoints/alive_urls.txt" | sort -u > "$OUT_DIR/.temp/jwts.txt" || true
    log_stat "JWTs detected" "$(wc -l < "$OUT_DIR/.temp/jwts.txt" 2>/dev/null || echo 0)"
}

# 16. LOGIC FLAWS (SMART OPTIMIZATION)
run_logic_flaws() {
    log_phase "16: BUSINESS LOGIC FLAWS (SMART FILTER)"
    
    # Non-fatal check
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for Logic Flaws testing. Skipping phase."
        return
    fi
    
    # 1. FILTRADO INTELIGENTE
    # El problema: Pasar 20k URLs (muchas estáticas) a templates lentos.
    # Solución: Seleccionar solo URLs con parámetros, APIs o keywords transaccionales.
    
    log_step "Filtering critical targets (APIs, Auth, Params) to reduce load..."
    
    mkdir -p "$OUT_DIR/.temp"
    
    # REGEX EXPLICADA:
    # \?       -> URLs con parámetros (ej: item?id=1)
    # /api/    -> Endpoints de API
    # auth...  -> Rutas de autenticación o perfil
    # cart...  -> Rutas de compra/negocio
    # .php...  -> Archivos dinámicos conocidos
    grep -iE "\?|/api/|/v[0-9]/|graphql|auth|login|register|signup|admin|account|profile|cart|order|checkout|pay|billing|user|dashboard|\.php|\.jsp|\.asp|\.aspx" \
        "$OUT_DIR/endpoints/clean_urls.txt" | sort -u > "$OUT_DIR/.temp/logic_targets.txt" || true
    
    # Estadísticas para que veas la reducción
    local total_urls=$(wc -l < "$OUT_DIR/endpoints/clean_urls.txt")
    local smart_urls=$(wc -l < "$OUT_DIR/.temp/logic_targets.txt")
    
    log_stat "Total URLs (Ignored)" "$total_urls"
    log_stat "Logical URLs (To Scan)" "$smart_urls"
    
    # Fallback de seguridad: Si el filtro fue muy estricto y dio 0, tomamos una muestra
    if [ "$smart_urls" -lt 5 ] && [ "$total_urls" -gt 0 ]; then
        log_warn "Very strict filter. Using top 500 general URLs..."
        head -n 500 "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/logic_targets.txt"
    fi

    # 2. EJECUCIÓN OPTIMIZADA DE NUCLEI
    if [ -s "$OUT_DIR/.temp/logic_targets.txt" ]; then
        # Flags de velocidad:
        # -timeout 6: Tiempo máximo por petición bajo
        # -retries 1: No reintentar demasiado si falla
        # -mhe 3: Max Host Errors (si falla 3 veces el host, saltarlo)
        nuclei -l "$OUT_DIR/.temp/logic_targets.txt" \
            -tags logic,api,graphql,workflow,business,auth-bypass \
            -timeout 6 -retries 1 -mhe 3 \
            -c 50 -rl 120 \
            -o "$OUT_DIR/vulns/logic.txt" \
            -dr -silent || true
            
        log_success "Logic analysis completed."
    else
        log_warn "No targets suitable for Logic Flaws were found."
    fi
}

# 17. AI CONTENT HUNTER
run_ai_hunter() {
    log_phase "17: AI-POWERED HUNTER"
    log_step "Analyzing sensitive candidates for AI attack..."
    grep -iE "admin|api|v1|config|dashboard|user|auth" "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/vulns/ai_candidates.txt" || true
    # Ejecución del script Python si existe
    if [ -f "/usr/local/bin/ai_hunter" ]; then
    python3 /usr/local/bin/ai_hunter "$OUT_DIR" > "$OUT_DIR/reports/ai_hunter_summary.txt" || true
    fi
}

# 18. CLIENT-SIDE FUZZING (KING'S ONELINERS)
run_client_fuzzing() {
    if check_dependency "$OUT_DIR/vulns/open_redirect.txt" "Client-Side Fuzzing"; then return; fi
    
    log_phase "18: CLIENT-SIDE FUZZING (PROTO & REDIRECTS)"
    
    # Non-fatal check
    if [ ! -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_warn "No parameters found for Client-Side Fuzzing. Skipping phase."
        touch "$OUT_DIR/vulns/open_redirect.txt"
        return
    fi
    
    mkdir -p "$OUT_DIR/.temp"
    
    # --- A. OPEN REDIRECT (The King's One-Liner) ---
    log_step "Open Redirect: Fuzzing navigation parameters..."
    
    # 1. Filtramos URLs que tengan palabras clave de redirección
    grep -iE "redirect|url|next|dest|out|view|to|return|r=|u=" "$OUT_DIR/endpoints/params_only.txt" > "$OUT_DIR/.temp/redirect_targets.txt" || true
    
    if [ -s "$OUT_DIR/.temp/redirect_targets.txt" ]; then
        # 2. Reemplazamos el valor con nuestro payload y verificamos con httpx si el Location header lo refleja
        # Payload: http://example.com (Dominio seguro para validar)
        
        cat "$OUT_DIR/.temp/redirect_targets.txt" | \
        qsreplace "http://example.com" | \
        httpx -silent -status-code -location -mc 301,302 -threads 50 | \
        grep "http://example.com" > "$OUT_DIR/vulns/open_redirect.txt" || true
        
        log_stat "Possible Open Redirects" "$(wc -l < "$OUT_DIR/vulns/open_redirect.txt")"
    else
        log_warn "No redirection parameters found."
        touch "$OUT_DIR/vulns/open_redirect.txt"
    fi

    # --- B. PROTOTYPE POLLUTION (Smart Check) ---
    log_step "Prototype Pollution: Focused Scan..."
    # Usamos Nuclei solo con tags de prototype-pollution sobre los parámetros detectados
    # Es más efectivo que un grep simple para este caso complejo.
    
    if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        nuclei -l "$OUT_DIR/endpoints/params_only.txt" \
            -tags prototype-pollution \
            -c 40 -rl 150 -timeout 5 \
            -o "$OUT_DIR/vulns/prototype_pollution.txt" -dr -silent || true
    fi
    log_success "Client-Side Fuzzing completed."
}

# 19. GRAPHQL DEEP
run_graphql_deep() {
    log_phase "19: GRAPHQL DEEP AUDIT"
    nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" -tags graphql,introspection -o "$OUT_DIR/vulns/graphql.txt" -dr || true
}

# 20. API RATE LIMIT
run_api_limit_bypass() {
    log_phase "20: API RATE LIMIT & WAF BYPASS"
    nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" -tags rate-limit,bypass,waf -o "$OUT_DIR/vulns/ratelimit.txt" -dr || true
}

# 21. OAUTH ANALYSIS
run_oauth_analysis() {
    log_phase "21: OAUTH & OIDC AUDIT"
    nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" -tags oauth,openid-connect,sso -o "$OUT_DIR/vulns/oauth.txt" -dr || true
}

# ============================================================================
# ADVANCED SECURITY MODULES
# ============================================================================

# 22. SUBDOMAIN TAKEOVER
run_subdomain_takeover() {
    if check_dependency "$OUT_DIR/vulns/subdomain_takeover.txt" "Subdomain Takeover"; then return; fi
    
    log_phase "22: SUBDOMAIN TAKEOVER DETECTION"
    
    # AUTO-DEPENDENCY: Si no existe subs.txt, ejecutar recon pasivo
    if [ ! -s "$OUT_DIR/.temp/subs.txt" ]; then
        log_warn "Subdomain list not found. Running passive reconnaissance..."
        run_recon_passive
    fi
    
    log_step "Subzy: Scanning for dangling CNAMEs (S3, Azure, GitHub, Heroku)..."
    
    if [ -s "$OUT_DIR/.temp/subs.txt" ]; then
        subzy run --targets "$OUT_DIR/.temp/subs.txt" \
            --timeout 10 \
            --concurrency 100 \
            --hide_fails \
            | tee "$OUT_DIR/vulns/subdomain_takeover.txt" || true
        
        local count=$(grep -c "VULNERABLE" "$OUT_DIR/vulns/subdomain_takeover.txt" 2>/dev/null || echo 0)
        log_stat "Vulnerable Subdomains" "$count"
    else
        log_warn "No subdomains found even after recon. Skipping takeover detection."
        touch "$OUT_DIR/vulns/subdomain_takeover.txt"
    fi
}

# 23. APK ANALYSIS
run_apk_analysis() {
    if check_dependency "$OUT_DIR/reports/mobsf_apk.json" "APK Analysis"; then return; fi
    
    log_phase "23: APK SECURITY ANALYSIS"
    
    if [ -z "$APK_FILE" ]; then
        log_warn "No APK file specified. Use -a flag to provide an APK."
        echo "# No APK provided" > "$OUT_DIR/reports/mobsf_apk.json"
        return
    fi
    
    if [ ! -f "$APK_FILE" ]; then
        log_err "APK file not found: $APK_FILE"
        return 1
    fi
    
    log_step "MobSF: Static analysis of APK..."
    mobsfscan --apk "$APK_FILE" --json --output "$OUT_DIR/reports/mobsf_apk.json" || true
    
    log_step "APKLeaks: Extracting secrets and URLs..."
    apkleaks -f "$APK_FILE" -o "$OUT_DIR/secrets/apk_secrets.txt" || true
    
    log_success "APK analysis complete. Check reports/mobsf_apk.json and secrets/apk_secrets.txt"
}

# 24. iOS ANALYSIS
run_ios_analysis() {
    if check_dependency "$OUT_DIR/reports/mobsf_ios.json" "iOS Analysis"; then return; fi
    
    log_phase "24: iOS APP ANALYSIS"
    
    if [ -z "$IPA_FILE" ]; then
        log_warn "No IPA file specified. Use -i flag to provide an IPA."
        echo "# No IPA provided" > "$OUT_DIR/reports/mobsf_ios.json"
        return
    fi
    
    if [ ! -f "$IPA_FILE" ]; then
        log_err "IPA file not found: $IPA_FILE"
        return 1
    fi
    
    log_step "MobSF: Static analysis of iOS app..."
    mobsfscan --ipa "$IPA_FILE" --json --output "$OUT_DIR/reports/mobsf_ios.json" || true
    
    log_step "Extracting binary and searching for hardcoded secrets..."
    # Extract IPA (it's a ZIP)
    mkdir -p "$OUT_DIR/.temp/ipa_extract"
    unzip -q "$IPA_FILE" -d "$OUT_DIR/.temp/ipa_extract" || true
    
    # Search for common secrets in extracted files
    grep -rE "(api[_-]?key|secret|password|token|aws_access)" "$OUT_DIR/.temp/ipa_extract" > "$OUT_DIR/secrets/ios_secrets.txt" 2>/dev/null || true
    
    log_success "iOS analysis complete. Check reports/mobsf_ios.json"
}

# 25. BACKUP FILE DISCOVERY
run_backup_discovery() {
    if check_dependency "$OUT_DIR/vulns/backup_files.txt" "Backup Discovery"; then return; fi
    
    log_phase "25: BACKUP FILE DISCOVERY"
    
    # AUTO-DEPENDENCY: Si no existe clean_urls.txt, ejecutar recon activo + limpieza
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "Clean URLs not found. Running active recon and cleanup..."
        run_recon_active
        clean_targets
    fi
    
    log_step "BFAC: Scanning for .bak, .old, .swp, .tmp files..."
    
    # BFAC works best with individual URLs, not lists
    # We'll take the top interesting URLs and scan them
    
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        # Filter for likely targets (root domains, admin panels, config)
        grep -iE "(admin|config|panel|dashboard|api|login)" "$OUT_DIR/endpoints/clean_urls.txt" | head -n 20 > "$OUT_DIR/.temp/backup_targets.txt" || true
        
        # If no matches, take first 10 URLs
        if [ ! -s "$OUT_DIR/.temp/backup_targets.txt" ]; then
            head -n 10 "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/backup_targets.txt"
        fi
        
        : > "$OUT_DIR/vulns/backup_files.txt"
        
        while IFS= read -r url; do
            log_step "Checking: $url"
            bfac --url "$url" --level 2 --verify >> "$OUT_DIR/vulns/backup_files.txt" 2>/dev/null || true
        done < "$OUT_DIR/.temp/backup_targets.txt"
        
        local found=$(grep -c "FOUND" "$OUT_DIR/vulns/backup_files.txt" 2>/dev/null || echo 0)
        log_stat "Backup Files Found" "$found"
    else
        log_warn "No URLs found even after recon. Skipping backup discovery."
        touch "$OUT_DIR/vulns/backup_files.txt"
    fi
}

# 25. RACE CONDITIONS (Phase 2B)
run_race_conditions() {
     if check_dependency "$OUT_DIR/vulns/race_conditions.txt" "Race Conditions"; then return; fi
     log_phase "25: RACE CONDITIONS"
     
     if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
         log_warn "No clean URLs found for Race Condition testing. Skipping phase."
         touch "$OUT_DIR/vulns/race_conditions.txt"
         return
     fi
     
     log_step "Filtering candidates for Race Conditions (RPC, Claim, Buy, Transfer)..."
     
     mkdir -p "$OUT_DIR/.temp"
     # Filtramos endpoints que suenen "transaccionales"
     grep -iE "transfer|buy|claim|gift|promo|coupon|invite|send|verify|register|vote|like|follow" \
        "$OUT_DIR/endpoints/clean_urls.txt" | sort -u > "$OUT_DIR/.temp/race_targets.txt" || true
     
     local race_count=$(wc -l < "$OUT_DIR/.temp/race_targets.txt")
     log_stat "Transactional Candidates" "$race_count"
     
     if [ "$race_count" -gt 0 ]; then
         log_step "Launching Async Race Attack (20 concurrent reqs)..."
         # Limitamos a top 50 para no tirar el server (esto es una prueba de concepto)
         head -n 50 "$OUT_DIR/.temp/race_targets.txt" > "$OUT_DIR/.temp/race_top50.txt"
         
         python3 /usr/local/bin/race_cond -l "$OUT_DIR/.temp/race_top50.txt" -c 20 > "$OUT_DIR/vulns/race_conditions.txt" || true
         
         log_success "Race analysis complete."
     else
         log_warn "No transactional endpoints found."
         touch "$OUT_DIR/vulns/race_conditions.txt"
     fi
}

# 26. WEBSOCKET ANALYSIS
run_websocket_analysis() {
    if check_dependency "$OUT_DIR/vulns/websocket_findings.txt" "WebSocket Analysis"; then return; fi
    log_phase "26: WEBSOCKET ANALYSIS"
    
    if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No alive URLs found for WebSocket analysis. Skipping phase."
        touch "$OUT_DIR/vulns/websocket_findings.txt"
        return
    fi
    
    # Buscamos endpoints que parezcan websockets o tengan 'ws'
    grep -iE "ws://|wss://|socket|realtime|chat|notification|stream" "$OUT_DIR/endpoints/alive_urls.txt" > "$OUT_DIR/.temp/ws_candidates.txt" || true
    
    # También pasamos la raíz del target
    echo "https://$TARGET" >> "$OUT_DIR/.temp/ws_candidates.txt"
    
    log_step "Probing for WebSocket Upgrades..."
    python3 /usr/local/bin/ws_scanner -l "$OUT_DIR/.temp/ws_candidates.txt" > "$OUT_DIR/vulns/websocket_findings.txt" || true
    
    log_success "WebSocket analysis complete."
}


# 27. SWAGGER/OPENAPI DISCOVERY
run_swagger_discovery() {
    log_phase "27: SWAGGER/OPENAPI DISCOVERY"
    
    log_step "Discovering API documentation endpoints..."
    python3 /usr/local/bin/swagger_discovery -u "https://$TARGET" \
        --analyze \
        --wordlist "$OUT_DIR/endpoints/swagger_endpoints.txt" \
        --output "$OUT_DIR/reports/swagger_analysis.json" || true
    
    # If wordlist was generated, add to fuzzing targets
    if [ -s "$OUT_DIR/endpoints/swagger_endpoints.txt" ]; then
        local count=$(wc -l < "$OUT_DIR/endpoints/swagger_endpoints.txt")
        log_stat "Swagger Endpoints Discovered" "$count"
        
        # Append to clean_urls for further testing
        cat "$OUT_DIR/endpoints/swagger_endpoints.txt" >> "$OUT_DIR/endpoints/clean_urls.txt"
        sort -u "$OUT_DIR/endpoints/clean_urls.txt" -o "$OUT_DIR/endpoints/clean_urls.txt"
    else
        log_warn "No Swagger/OpenAPI documentation found"
    fi
    
    log_success "Swagger discovery completed"
}


# CORRELACIÓN FINAL
run_correlation() {
    log_phase "90: DATA CORRELATION (SMART)"
    if [ -f "/usr/local/bin/correlator" ]; then
        python3 /usr/local/bin/correlator "$OUT_DIR" > "$OUT_DIR/reports/correlated_findings.txt" || true
    fi
}

# REPORTING
run_reporting() {
    log_phase "99: FINAL REPORTING"
    local report="$OUT_DIR/reports/final_summary.txt"
    echo "====================================================" > "$report"
    echo " REDHAVEN FRAMEWORK SUMMARY - $TARGET " >> "$report"
    echo " Date: $(date)" >> "$report"
    echo "====================================================" >> "$report"
    echo -e "\n--- FINDINGS BY CATEGORY ---" >> "$report"
    find "$OUT_DIR/vulns" "$OUT_DIR/secrets" -type f -exec wc -l {} + >> "$report" 2>/dev/null || true
    log_success "Scan complete. Report in: $report"
}

# 33. POSTMESSAGE SECURITY ANALYZER (Phase 2B)
run_postmessage_analyzer() {
    log_phase "33: POSTMESSAGE SECURITY ANALYSIS"
    
    # Check if JS files have been downloaded
    if [ ! -d "$OUT_DIR/.temp/js_download" ] || [ -z "$(ls -A $OUT_DIR/.temp/js_download 2>/dev/null)" ]; then
        log_warn "No JS files found. Run Secrets Hunter (Module 8) first."
        return
    fi
    
    log_step "Analyzing postMessage handlers in JavaScript files..."
    python3 /usr/local/bin/postmessage_analyzer \
        --js-dir "$OUT_DIR/.temp/js_download" \
        --generate-poc \
        > "$OUT_DIR/vulns/postmessage_findings.txt" 2>&1 || true
    
    # Move generated PoCs to reports
    if ls postmessage_poc_*.html 1> /dev/null 2>&1; then
        mkdir -p "$OUT_DIR/reports/pocs"
        mv postmessage_poc_*.html "$OUT_DIR/reports/pocs/" || true
        log_stat "PoC Files Generated" "$(ls $OUT_DIR/reports/pocs/postmessage_poc_*.html 2>/dev/null | wc -l)"
    fi
    
    log_success "PostMessage analysis completed"
}

# 34. BLIND XSS HUNTER (Phase 2B - Requires Callback Server)
run_blind_xss() {
    log_phase "34: BLIND XSS HUNTER"
    
    # Check for callback server configuration
    local callback_domain=""
    
    # Look for callback in environment or config
    if [ -n "${BLIND_XSS_CALLBACK:-}" ]; then
        callback_domain="$BLIND_XSS_CALLBACK"
    elif [ -f "/results/callback.txt" ]; then
        callback_domain=$(cat /results/callback.txt | head -n1)
    else
        log_warn "No callback server configured!"
        log_warn "Set BLIND_XSS_CALLBACK env var or create /results/callback.txt"
        log_warn "Example: export BLIND_XSS_CALLBACK='xxx.interact.sh'"
        log_warn "Skipping Blind XSS testing."
        return
    fi
    
    log_step "Using callback server: $callback_domain"
    
    # Test URLs with parameters (most likely to be vulnerable)
    if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_step "Injecting Blind XSS payloads into parameters..."
        python3 /usr/local/bin/blind_xss \
            -l "$OUT_DIR/endpoints/params_only.txt" \
            -c "$callback_domain" \
            --context all > "$OUT_DIR/vulns/blind_xss_injections.txt" 2>&1 || true
        
        log_success "Blind XSS payloads injected"
        log_warn "IMPORTANT: Monitor your callback server for hits!"
    else
        log_warn "No parameterized URLs found"
    fi
}

# 35. 2FA BYPASS TESTER (Phase 2B - Requires Manual Configuration)
run_twofa_bypass() {
    log_phase "35: 2FA/MFA BYPASS TESTING"
    
    # Check if 2FA endpoints are configured
    if [ -z "${TFA_VERIFY_URL:-}" ]; then
        log_warn "No 2FA endpoints configured!"
        log_warn "Set TFA_VERIFY_URL and optionally TFA_ENROLLMENT_URL"
        log_warn "Example: export TFA_VERIFY_URL='https://target.com/2fa/verify'"
        log_warn "Skipping 2FA bypass testing."
        return
    fi
    
    log_step "Testing 2FA security on: ${TFA_VERIFY_URL:-}"
    
    # Build command
    local cmd="python3 /usr/local/bin/twofa_bypass -u https://$TARGET --verify ${TFA_VERIFY_URL:-}"
    
    if [ -n "${TFA_ENROLLMENT_URL:-}" ]; then
        cmd="$cmd --enrollment ${TFA_ENROLLMENT_URL:-}"
    fi
    
    if [ -n "${SESSION_COOKIE:-}" ]; then
        cmd="$cmd --session ${SESSION_COOKIE:-}"
    fi
    
    # Run tests
    $cmd > "$OUT_DIR/vulns/2fa_bypass_results.txt" 2>&1 || true
    
    log_success "2FA bypass testing completed"
}

# 28. BOLA/BFLA API TESTING (Phase 2C)
run_bola_bfla() {
    log_phase "28: BOLA/BFLA API AUTHORIZATION TESTING"
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for BOLA/BFLA testing. Skipping phase."
        return
    fi
    
    # Filter API endpoints (containing /api/, /v1/, /v2/, etc.)
    grep -iE "/api/|/v[0-9]/|/graphql" "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/api_endpoints.txt" || true
    
    if [ -s "$OUT_DIR/.temp/api_endpoints.txt" ]; then
        log_step "Testing $(wc -l < $OUT_DIR/.temp/api_endpoints.txt) API endpoints for BOLA/BFLA..."
        python3 /usr/local/bin/bola_bfla -l "$OUT_DIR/.temp/api_endpoints.txt" \
            -o "$OUT_DIR/vulns/bola_bfla_findings.json" 2>&1 | tee "$OUT_DIR/vulns/bola_bfla.txt"
        
        local found=$(grep -c "HIGH\|CRITICAL" "$OUT_DIR/vulns/bola_bfla.txt" 2>/dev/null || echo 0)
        log_stat "BOLA/BFLA Vulnerabilities" "$found"
    else
        log_warn "No API endpoints found. Skipping BOLA/BFLA testing."
    fi
    
    log_success "BOLA/BFLA testing completed"
}

# 36. HTTP REQUEST SMUGGLING (Phase 2C)
run_http_smuggling() {
    log_phase "36: HTTP REQUEST SMUGGLING"
    
    log_step "Testing for CL.TE, TE.CL, and TE.TE smuggling..."
    python3 /usr/local/bin/smuggler -u "https://$TARGET" > "$OUT_DIR/vulns/http_smuggling.txt" 2>&1 || true
    
    local found=$(grep -c "DETECTED" "$OUT_DIR/vulns/http_smuggling.txt" 2>/dev/null || echo 0)
    if [ "$found" -gt 0 ]; then
        log_stat "Smuggling Vulnerabilities" "$found"
    else
        log_success "No HTTP smuggling detected"
    fi
}

# 37. CORS MISCONFIGURATION (Phase 2C)
run_cors_testing() {
    log_phase "37: CORS MISCONFIGURATION TESTING"
    
    if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No alive URLs found for CORS testing. Skipping phase."
        return
    fi
    
    # Test top 20 URLs for CORS issues
    head -n 20 "$OUT_DIR/endpoints/alive_urls.txt" > "$OUT_DIR/.temp/cors_targets.txt"
    
    log_step "Testing CORS on $(wc -l < $OUT_DIR/.temp/cors_targets.txt) URLs..."
    python3 /usr/local/bin/cors_tester -l "$OUT_DIR/.temp/cors_targets.txt" > "$OUT_DIR/vulns/cors_misconfigs.txt" 2>&1 || true
    
    local found=$(grep -c "CRITICAL\|HIGH" "$OUT_DIR/vulns/cors_misconfigs.txt" 2>/dev/null || echo 0)
    log_stat "CORS Misconfigurations" "$found"
    
    log_success "CORS testing completed"
}

# 38. CACHE POISONING (Phase 2C)
run_cache_poisoning() {
    log_phase "38: CACHE POISONING TESTING"
    
    log_step "Testing for cache poisoning and CPDoS..."
    python3 /usr/local/bin/cache_poison -u "https://$TARGET" > "$OUT_DIR/vulns/cache_poisoning.txt" 2>&1 || true
    
    local found=$(grep -c "detected" "$OUT_DIR/vulns/cache_poisoning.txt" 2>/dev/null || echo 0)
    log_stat "Cache Poisoning Vulnerabilities" "$found"
    
    log_success "Cache poisoning testing completed"
}
# ============================================================================
# MAIN EXECUTION CASE
# ============================================================================

verify_tools
case "$MODE" in
    # ========================================================================
    # RECONNAISSANCE (1-5)
    # ========================================================================
    1) run_recon_passive ;;
    2) run_recon_active; clean_targets ;;
    3) run_visual_recon ;;
    4) run_param_mining ;;
    5) run_port_scan ;;
    
    # ========================================================================
    # METADATA & FILE DISCOVERY (6-8)
    # ========================================================================
    6) run_metadata_hunter ;;
    7) run_backup_discovery ;;  # NEW: Moved from 25
    8) run_secrets_hunter ;;
    
    # ========================================================================
    # ELITE SECURITY TESTING (32-34)
    # ========================================================================
    32) run_http_smuggling ;;
    33) run_cors_testing ;;
    34) run_cache_poisoning ;;
    
    # ========================================================================
    # VULNERABILITIES (9-18)
    # ========================================================================
    9) run_idor_hunter ;;
    10) run_xss_engine ;;
    11) run_ssrf_storm ;;
    12) run_crlf_scan ;;
    13) run_403_bypass ;;
    14) run_client_fuzzing ;;  # Open Redirect + Proto Pollution
    15) run_jwt_suite ;;
    16) run_logic_flaws ;;
    17) run_deep_fuzzing ;; # Unified Strategic Fuzzing
    18) run_dephunter ;;  # Supply Chain
    
    # ========================================================================
    # INFRASTRUCTURE & CLOUD (19-22)
    # ========================================================================
    19) run_infrastructure_scan ;;  # S3, Azure, GCP
    20) run_subdomain_takeover ;;  # NEW: Moved from 22
    21) run_graphql_deep ;;
    22) run_api_limit_bypass ;;
    
    # ========================================================================
    # ADVANCED API & OAUTH (23-24)
    # ========================================================================
    23) run_oauth_analysis ;;
    24) run_ai_hunter ;;
    
    # ========================================================================
    # ELITE DISCOVERY (25-28)
    # ========================================================================
    25) run_race_conditions ;;
    26) run_websocket_analysis ;;
    27) run_swagger_discovery ;;
    28) run_bola_bfla ;;
    
    # ========================================================================
    # ADVANCED ANALYSIS (29-31)
    # ========================================================================
    29) run_postmessage_analyzer ;;
    30) run_blind_xss ;;
    31) run_twofa_bypass ;;
    
    # ========================================================================
    # ELITE SECURITY TESTING (32-34)
    # ========================================================================
    32) run_http_smuggling ;;
    33) run_cors_testing ;;
    34) run_cache_poisoning ;;
    39) run_hunter_toolkit ;;
    
    # ========================================================================
    # MOBILE SECURITY (50-51)
    # ========================================================================
    50) run_apk_analysis ;;  # NEW: Moved from 23
    51) run_ios_analysis ;;  # NEW: Moved from 24

    # AUTOMATIZACIONES COMPLETAS (40-42)
    40) # STANDARD SCAN
        log_phase ">>> STARTING STANDARD SCAN <<<"
        run_recon_active; clean_targets; run_idor_hunter; run_secrets_hunter; run_ssrf_storm; run_reporting 
        ;;

    41) # ELITE SCAN (CLASSIC)
        log_phase ">>> STARTING ELITE SCAN (CLASSIC) <<<"
        run_recon_active; clean_targets; run_visual_recon; run_param_mining; run_infrastructure_scan; run_idor_hunter; run_xss_engine; run_secrets_hunter; run_ssrf_storm; run_dephunter; run_deep_fuzzing; run_jwt_suite; run_logic_flaws; run_reporting 
        ;;

    42) # RED TEAM ELITE (NON-LINEAR LOGIC)
        log_phase ">>> STARTING RED TEAM ELITE SCAN <<<"
        
        # STEP 1: FOUNDATION
        run_recon_active
        clean_targets
        
        # STEP 2: BRAIN (Decision Matrix)
        # We need visual recon data for the brain to work
        run_visual_recon
        detect_stack
        
        # STEP 3: CORE ATTACKS (Context Independent)
        run_metadata_hunter
        run_subdomain_takeover
        run_infrastructure_scan
        run_403_bypass # Important: Runs early to feed back results
        
        # STEP 4: TRIGGERED MODULES (Context Dependent)
        if [ "$IS_WORDPRESS" = true ]; then run_wordpress_trigger; fi
        if [ "$IS_SPRING" = true ]; then run_spring_trigger; fi
        if [ "$HAS_GRAPHQL" = true ]; then run_graphql_trigger; fi
        
        # STEP 5: DEEP ATTACKS
        run_param_mining
        run_idor_hunter
        run_xss_engine
        run_secrets_hunter
        run_ssrf_storm
        run_client_fuzzing
        run_jwt_suite
        run_logic_flaws
        
        # STEP 6: FINALIZATION
        run_dephunter
        run_api_limit_bypass
        run_oauth_analysis
        
        # 5b. Phase 2A: Critical Security Checks
        run_subdomain_takeover
        run_backup_discovery
        
        # 6. Elite Differentiators (Phase 2B)
        run_swagger_discovery  # Discover APIs BEFORE fuzzing
        run_bola_bfla  # Test API authorization (uses Swagger findings)
        run_race_conditions
        run_websocket_analysis
        run_deep_fuzzing  # Unified Strategic Fuzzing (uses Swagger wordlist)
        run_postmessage_analyzer  # Analyze downloaded JS
        run_hunter_toolkit        # manual bug bounty checks (Uni/Email/Clickjacking)
        
        # 6b. Advanced Exploits (Optional - Requires Config)
        run_blind_xss || true  # Requires BLIND_XSS_CALLBACK
        run_twofa_bypass || true  # Requires TFA_VERIFY_URL
        
        # 6c. Elite Security Testing (Phase 2C - 10/10)
        run_http_smuggling || true  # HTTP Request Smuggling
        run_cors_testing  # CORS Misconfiguration
        run_cache_poisoning || true  # Cache Poisoning & CPDoS
        
        # 6d. Hunter's Toolkit (Phase 2C Extension)
        run_hunter_toolkit
        
        # 7. Mobile Analysis (if files provided) (NUEVO)
        if [ -n "$APK_FILE" ]; then run_apk_analysis; fi
        if [ -n "$IPA_FILE" ]; then run_ios_analysis; fi
        
        # 8. Post-Procesado & Reporte
        run_correlation
        run_reporting
        log_success "REDHAVEN ELITE LOGIC COMPLETED"
        ;;

    99) run_reporting ;;

    *) log_err "Error: The mode '$MODE' is not valid."; exit 1 ;;
esac
