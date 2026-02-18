#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === RECONNAISSANCE ===
detect_stack() {
    log_phase "TECHNOLOGY DETECTION (DECISION MATRIX V2.0)"
    
    local report_file="$OUT_DIR/reports/web_overview.txt"
    if [ ! -s "$report_file" ]; then
        log_warn "No visual recon data found. Skipping technology detection."
        return
    fi

    # Reset vars
    IS_WORDPRESS=false; IS_SPRING=false; HAS_GRAPHQL=false
    IS_DOTNET=false; IS_REST=false; IS_JOOMLA=false; IS_DRUPAL=false
    IS_AWS=false; IS_AZURE=false; IS_GCP=false

    log_step "Analyzing technology stack (Smart Detection)..."
    
    # CMS DETECTION
    if grep -qiE "WordPress|wp-content|wp-includes" "$report_file"; then
        IS_WORDPRESS=true
        log_success "DECISION: WordPress detected! (Enabling WP specific scans)"
    fi
    if grep -qi "Joomla" "$report_file"; then IS_JOOMLA=true; log_success "DECISION: Joomla detected!"; fi
    if grep -qi "Drupal" "$report_file"; then IS_DRUPAL=true; log_success "DECISION: Drupal detected!"; fi
    
    # FRAMEWORK DETECTION
    if grep -qiE "Spring|Java|Whitelabel Error Page" "$report_file"; then
        IS_SPRING=true
        log_success "DECISION: Spring Boot detected! (Enabling Actuator/HeapDump scans)"
    fi

    if grep -qi "GraphQL" "$report_file" || grep -qi "graphql" "$OUT_DIR/recon/urls.txt"; then
        HAS_GRAPHQL=true
        log_success "DECISION: GraphQL detected! (Enabling Introspection/Injection scans)"
    fi

    if grep -qiE "ASP.NET|Microsoft|IIS|Mvc" "$report_file"; then
        IS_DOTNET=true
        log_success "DECISION: .NET Infrastructure detected!"
    fi

    if grep -qiE "application/json|swagger|openapi" "$report_file" || grep -qiE "/api/|/v[0-9]/" "$OUT_DIR/recon/urls.txt"; then
        IS_REST=true
        log_success "DECISION: REST API context detected!"
    fi
    
    # CLOUD PROVIDER DETECTION
    if grep -qiE "amazonaws|cloudfront|elasticbeanstalk" "$report_file"; then
        IS_AWS=true
        log_success "DECISION: AWS Infrastructure detected! (Checking S3 buckets)"
    fi
    if grep -qiE "azure|windows.net" "$report_file"; then
        IS_AZURE=true
        log_success "DECISION: Azure Infrastructure detected!"
    fi
    if grep -qiE "google|gcp|appspot" "$report_file"; then
        IS_GCP=true
        log_success "DECISION: Google Cloud Platform detected!"
    fi
}

run_cms_detection() {
    log_phase "CMS DETECTION & VULN SCAN (CMSeeK)"
    
    if check_dependency "$OUT_DIR/recon/cms_detection.json" "CMSeeK"; then return; fi
    
    # Check if CMSeek is installed
    if ! command -v cmseek >/dev/null 2>&1; then
        log_warn "CMSeeK not found. Skipping CMS detection."
        return
    fi
    
    log_step "Running CMSeeK against $TARGET..."
    
    # Run in batch mode
    # cmseek --batch -u URL
    # It saves results to Results/target/cms.json inside CWD.
    # We need to handle the output directory carefully.
    
    mkdir -p "$OUT_DIR/.temp/cmseek_out"
    cd "$OUT_DIR/.temp/cmseek_out" || return
    
    cmseek -u "https://$TARGET" --batch --random-agent >/dev/null 2>&1 || true
    
    # CMSeeK structure: [cwd]/Result/[domain]/cms.json
    local result_file=""
    result_file=$(find . -name "cms.json" | head -n 1)
    
    if [ -s "$result_file" ]; then
        log_success "CMS Detected!"
        cp "$result_file" "$OUT_DIR/recon/cms_detection.json"
        
        # Parse result for variables
        if command -v jq >/dev/null 2>&1; then
            local cms_name
            cms_name=$(jq -r '.cms_name' "$OUT_DIR/recon/cms_detection.json" 2>/dev/null)
            local cms_ver
            cms_ver=$(jq -r '.cms_version' "$OUT_DIR/recon/cms_detection.json" 2>/dev/null)
            
            if [ -n "$cms_name" ] && [ "$cms_name" != "null" ]; then
                log_stat "CMS Name" "$cms_name"
                export CMS_TYPE="$cms_name"
                
                # Feedback loop to stack detection
                if echo "$cms_name" | grep -qi "WordPress"; then IS_WORDPRESS=true; fi
                if echo "$cms_name" | grep -qi "Joomla"; then IS_JOOMLA=true; fi
                if echo "$cms_name" | grep -qi "Drupal"; then IS_DRUPAL=true; fi
            fi
            
            if [ -n "$cms_ver" ] && [ "$cms_ver" != "null" ]; then
                log_stat "CMS Version" "$cms_ver"
                export CMS_VERSION="$cms_ver"
            fi
        fi
    else
        log_warn "No CMS detected or CMSeeK failed."
    fi
    
    # Return to previous directory
    cd - >/dev/null || true
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
    GITHUB_TOKEN=""
    
    # Buscar tokens.txt en ubicaciones conocidas
    if [ -f "/results/tokens.txt" ]; then TOKENS_FILE="/results/tokens.txt"; fi
    if [ -f "/root/.config/tokens.txt" ]; then TOKENS_FILE="/root/.config/tokens.txt"; fi
    
    # Si no hay tokens.txt, intentar extraer de provider-config.yaml
    if [ -z "$TOKENS_FILE" ]; then
        for config_path in "/root/.config/subfinder/provider-config.yaml" \
                           "/home/kali/.config/subfinder/provider-config.yaml" \
                           "/root/.config/nuclei/provider-config.yaml" \
                           "/results/provider-config.yaml"; do
            if [ -f "$config_path" ]; then
                # Extraer token de GitHub del YAML
                GITHUB_TOKEN=$(grep -E '^\s*-\s*' "$config_path" | grep -v '^#' | head -n1 | sed 's/^\s*-\s*//' | tr -d '"' | tr -d "'" || true)
                if [ -n "$GITHUB_TOKEN" ]; then
                    log_step "GitHub token found in $config_path"
                    break
                fi
            fi
        done
    else
        # Si hay tokens.txt, leer el primer token
        GITHUB_TOKEN=$(head -n1 "$TOKENS_FILE" 2>/dev/null || true)
    fi
    
    if [ -n "$GITHUB_TOKEN" ] || [ -n "$TOKENS_FILE" ]; then
        log_step "GitHub Subdomains: Searching with provided tokens..."
        
        # Si tenemos TOKENS_FILE, usarlo directamente
        if [ -n "$TOKENS_FILE" ]; then
            github-subdomains -d "$TARGET" -t "$TOKENS_FILE" -raw -o "$OUT_DIR/.temp/subs_github.txt" 2>/dev/null || true
        elif [ -n "$GITHUB_TOKEN" ]; then
            # Si solo tenemos el token extraído, crear archivo temporal
            echo "$GITHUB_TOKEN" > "$OUT_DIR/.temp/github_token.txt"
            github-subdomains -d "$TARGET" -t "$OUT_DIR/.temp/github_token.txt" -raw -o "$OUT_DIR/.temp/subs_github.txt" 2>/dev/null || true
            rm -f "$OUT_DIR/.temp/github_token.txt"
        fi
        
        cat "$OUT_DIR/.temp/subs_github.txt" >> "$OUT_DIR/.temp/subs_extra.txt"
        
        log_step "GitLab Subdomains: Searching..."
        if [ -n "$TOKENS_FILE" ]; then
            gitlab-subdomains -d "$TARGET" -t "$TOKENS_FILE" -raw -o "$OUT_DIR/.temp/subs_gitlab.txt" 2>/dev/null || true
        fi
        cat "$OUT_DIR/.temp/subs_gitlab.txt" >> "$OUT_DIR/.temp/subs_extra.txt"
        
        # --- v1.0.3: GITHUB DEEP RECON WITH TRUFFLEHOG ---
        log_step "TruffleHog: Scanning public repositories for secrets..."
        mkdir -p "$OUT_DIR/secrets"
        
        # Extract organization name from domain
        org_name=$(echo "$TARGET" | cut -d'.' -f1)
        
        # TruffleHog GitHub scanning (only verified secrets to reduce noise)
        if command -v trufflehog >/dev/null 2>&1 && [ -n "$GITHUB_TOKEN" ]; then
            trufflehog github --org="$org_name" \
                --token="$GITHUB_TOKEN" \
                --json \
                --only-verified \
                > "$OUT_DIR/secrets/github_deep.json" 2>/dev/null || true
            
            # Parse JSON results to human-readable format
            if [ -s "$OUT_DIR/secrets/github_deep.json" ] && command -v jq >/dev/null 2>&1; then
                cat "$OUT_DIR/secrets/github_deep.json" | \
                jq -r '"[" + .DetectorType + "] " + (.Raw // "N/A") + " | Repo: " + (.SourceMetadata.Data.Github.repository // "N/A")' \
                > "$OUT_DIR/secrets/github_deep.txt" 2>/dev/null || true
                
                local secret_count=$(wc -l <"$OUT_DIR/secrets/github_deep.txt" 2>/dev/null || echo 0)
                if [ "$secret_count" -gt 0 ]; then
                    log_stat "GitHub Verified Secrets" "$secret_count"
                fi
            fi
        else
            if ! command -v trufflehog >/dev/null 2>&1; then
                log_warn "TruffleHog not installed. Skipping deep secret scan."
            fi
        fi
    else
        log_warn "No GitHub token found. Checked tokens.txt and provider-config.yaml."
        log_warn "Skipping GitHub/GitLab deep search."
    fi
    
    # 2. NELUX1 INTEGRATION (Mode 44 Results)
    if [ -s "$OUT_DIR/recon/nelux1_final.txt" ]; then
        log_step "Nelux1 Results found! Merging alternative recon data..."
        cat "$OUT_DIR/recon/nelux1_final.txt" >> "$OUT_DIR/.temp/subs_extra.txt"
        log_stat "Nelux1 Subdomains Added" "$(wc -l < "$OUT_DIR/recon/nelux1_final.txt")"
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
    
    # HTTPX_BIN resolved by common.sh:resolve_httpx_bin()

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
    log_phase "HYBRID URL DISCOVERY (KATANA & URLFINDER)"
    
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
    # HTTPX_BIN resolved by common.sh:resolve_httpx_bin()

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
    
    log_phase "RECON METADATA & TITLES"
    
    # 1. Validación de Input
    if [ ! -s "$OUT_DIR/recon/urls.txt" ]; then
        log_warn "No URLs from passive recon (urls.txt is empty). Skipping visual reconnaissance."
        touch "$OUT_DIR/reports/web_overview.txt"
        return
    fi
    
    local url_count=$(wc -l < "$OUT_DIR/recon/urls.txt")
    
    mkdir -p "$OUT_DIR/reports"
    
    # 2. Validación de Binario
    if [ -z "$HTTPX_BIN" ] || [ "$HTTPX_BIN" == "false" ]; then
        log_err "CRITICAL: httpx binary is not available. Skipping visual recon."
        return
    fi

    log_step "Httpx: Extracting Titles, Servers and Technologies..."
    log_stat "Target URLs" "$url_count"
    log_stat "Using Binary" "$HTTPX_BIN"

    # 3. Ejecución Controlada con Logs de Depuración
    # -title: Obtiene el <title> de la web
    # -tech-detect: Identifica si usan React, PHP, AWS, etc.
    # -status-code: Para ver si es 200, 403, etc.
    # -follow-redirects: Sigue redirecciones para ver el destino final
    
    $HTTPX_BIN -list "$OUT_DIR/recon/urls.txt" \
        -title -tech-detect -status-code -web-server -follow-redirects \
        -threads 50 \
        -no-color -o "$OUT_DIR/reports/web_overview.txt" 2>/dev/null
        
    local exit_code=$?

    # 4. Verificación de Resultados
    if [ $exit_code -ne 0 ]; then
        log_err "Httpx failed with output code: $exit_code"
        # No retornamos inmediatamente para permitir intentos parciales, pero avisamos
    fi

    if [ -s "$OUT_DIR/reports/web_overview.txt" ]; then
        local found_count=$(wc -l < "$OUT_DIR/reports/web_overview.txt")
        log_success "Visual recognition completed successfully."
        log_stat "Entradas Generadas" "$found_count"
        
        # Mostramos una vista previa de 5 líneas PARA EL HACKER
        echo -e "\n${DIM}--- Report Preview (First 5 lines) ---${RESET}"
        head -n 5 "$OUT_DIR/reports/web_overview.txt"
        echo -e "${DIM}----------------------------------------${RESET}\n"
    else
        log_warn "Httpx finished but generated NO output. Check network or binary permissions."
        log_warn "Debug: Try running '$HTTPX_BIN -version' manually."
    fi
}

# 39. HUNTER'S TOOLKIT (Phase 2C Extension)
run_hunter_toolkit() {
    log_phase "HUNTER'S TOOLKIT (UNICODE/EMAIL/CLICKJACKING)"
    
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

# 40. ALTERNATIVE RECON (NELUX1 INTEGRATION)
run_alternate_recon() {
    if check_dependency "$OUT_DIR/recon/nelux1_final.txt" "Alternate Recon"; then return; fi
    log_phase "ALTERNATIVE RECON (NELUX1)"
    log_step "[*] Based on Alternative Recon tools by Nelux1"
    
    local domain="$TARGET"
    mkdir -p "$OUT_DIR/recon/"
    
    # Subfinder skipped (redundant with run_recon_passive)
    
    # 2. AMASS (Passive)
    if command -v amass >/dev/null; then
        log_step "Running Amass (Passive Mode)..."
        amass enum -passive -d "$domain" -silent -o "$OUT_DIR/recon/nelux1_amass.txt" 2>/dev/null || true
        log_stat "Amass Results" "$(wc -l < "$OUT_DIR/recon/nelux1_amass.txt" 2>/dev/null || echo 0)"
    else
        log_warn "Amass not found. Skipping."
    fi
    
    # 3. ASSETFINDER
    if command -v assetfinder >/dev/null; then
        log_step "Running Assetfinder..."
        assetfinder --subs-only "$domain" > "$OUT_DIR/recon/nelux1_assetfinder.txt" 2>/dev/null || true
        log_stat "Assetfinder Results" "$(wc -l < "$OUT_DIR/recon/nelux1_assetfinder.txt" 2>/dev/null || echo 0)"
    else
        log_warn "Assetfinder not found. Skipping."
    fi
    
    # 4. FINDOMAIN
    if command -v findomain >/dev/null; then
        log_step "Running Findomain..."
        findomain -t "$domain" -q > "$OUT_DIR/recon/nelux1_findomain.txt" 2>/dev/null || true
        log_stat "Findomain Results" "$(wc -l < "$OUT_DIR/recon/nelux1_findomain.txt" 2>/dev/null || echo 0)"
    else
        log_warn "Findomain not found. Skipping."
    fi
    
    # 5. GITHUB-SUBDOMAINS
    if command -v github-subdomains >/dev/null; then
        log_step "Running Github-Subdomains..."
        # Try to use token from config if available (simple check)
        local gh_token=""
        if [ -n "${GITHUB_TOKEN:-}" ]; then gh_token="-t $GITHUB_TOKEN"; fi
        
        github-subdomains -d "$domain" $gh_token -o "$OUT_DIR/recon/nelux1_github.txt" 2>/dev/null || true
        log_stat "Github-Subdomains Results" "$(wc -l < "$OUT_DIR/recon/nelux1_github.txt" 2>/dev/null || echo 0)"
    else
        log_warn "Github-subdomains not found. Skipping."
    fi
    
    # 6. CRT.SH (Curl + JQ)
    if command -v curl >/dev/null && command -v jq >/dev/null; then
        log_step "Querying Crt.sh..."
        curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | grep -i "$domain" | sort -u > "$OUT_DIR/recon/crtsh.txt" || true
        log_stat "Crt.sh Results" "$(wc -l < "$OUT_DIR/recon/crtsh.txt" 2>/dev/null || echo 0)"
    else
        log_warn "Curl or JQ not found. Skipping Crt.sh."
    fi
    
    # MERGE RESULTS
    log_step "Merging all results..."
    cat "$OUT_DIR/recon/"*.txt 2>/dev/null | sort -u > "$OUT_DIR/recon/nelux1_final.txt" || true
    
    local total=$(wc -l < "$OUT_DIR/recon/nelux1_final.txt" 2>/dev/null || echo 0)
    log_success "Alternative Recon Completed. Total Unique Subdomains: $total"
    log_success "Results saved to: $OUT_DIR/recon/nelux1_final.txt"
}

