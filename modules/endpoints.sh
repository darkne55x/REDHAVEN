#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === ENDPOINT DISCOVERY & INFRASTRUCTURE ===
# 4. METADATA HUNTER
run_metadata_hunter() {
    log_phase "METADATA & SENSITIVE FILES"
    
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
        # HTTPX_BIN resolved by common.sh:resolve_httpx_bin()
        
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
    log_phase "HYBRID PARAM MINING"
    
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
    
    log_phase "INFRASTRUCTURE & CLOUD SCAN"
    
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

