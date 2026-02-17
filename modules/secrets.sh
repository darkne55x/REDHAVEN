#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === SECRETS HUNTER ===
# 9. SECRETS HUNTER v2 (Smart Secrets + JSLuice + Gitleaks)
run_secrets_hunter() {
    if check_dependency "$OUT_DIR/secrets/smart_secrets.txt" "Secrets Hunter"; then return; fi
    log_phase "09: SECRETS & LEAKED KEYS v2 (INTELLIGENT DEEP ANALYSIS)"
    
    mkdir -p "$OUT_DIR/secrets" "$OUT_DIR/.temp/js_download"
    
    # ── STEP 1: CONSOLIDATE JS TARGETS ──
    log_step "Consolidating JS and Sourcemap files..."
    rm -f "$OUT_DIR/endpoints/js_targets.txt" 2>/dev/null || true
    
    # Collect all JS URLs from recon
    grep -iE "\.js(\?|$)" "$OUT_DIR/endpoints/alive_urls.txt" 2>/dev/null | sort -u > "$OUT_DIR/endpoints/js_targets.txt" || true
    cat "$OUT_DIR/endpoints/js_files.txt" >> "$OUT_DIR/endpoints/js_targets.txt" 2>/dev/null || true
    sort -u "$OUT_DIR/endpoints/js_targets.txt" -o "$OUT_DIR/endpoints/js_targets.txt"
    
    local js_count=$(wc -l < "$OUT_DIR/endpoints/js_targets.txt" 2>/dev/null || echo 0)
    log_stat "JS Files to Analyze" "$js_count"
    
    if [ "$js_count" -eq 0 ]; then
        log_warn "No JS files found for analysis."
        touch "$OUT_DIR/secrets/smart_secrets.txt"
        return
    fi
    
    # ── STEP 2: SMART SECRETS (Primary Engine) ──
    # Python module with 40+ patterns, entropy filtering, context analysis, live validation
    if [ -f "/scripts/modules/smart_secrets.py" ]; then
        log_step "Smart Secrets Engine: Entropy + Pattern + Validation scan..."
        
        python3 /scripts/modules/smart_secrets.py \
            --urls "$OUT_DIR/endpoints/js_targets.txt" \
            --output "$OUT_DIR/secrets" \
            --workers 20 2>/dev/null || true
        
        if [ -s "$OUT_DIR/secrets/smart_secrets.json" ]; then
            # Extract summary stats
            local critical=$(jq -r '.summary.CRITICAL // 0' "$OUT_DIR/secrets/smart_secrets.json" 2>/dev/null || echo 0)
            local high=$(jq -r '.summary.HIGH // 0' "$OUT_DIR/secrets/smart_secrets.json" 2>/dev/null || echo 0)
            local medium=$(jq -r '.summary.MEDIUM // 0' "$OUT_DIR/secrets/smart_secrets.json" 2>/dev/null || echo 0)
            local total=$(jq -r '.total_findings // 0' "$OUT_DIR/secrets/smart_secrets.json" 2>/dev/null || echo 0)
            
            log_stat "Smart Secrets Total" "$total"
            if [ "$critical" -gt 0 ]; then
                log_stat "CRITICAL findings" "$critical"
            fi
            if [ "$high" -gt 0 ]; then
                log_stat "HIGH findings" "$high"
            fi
            if [ "$medium" -gt 0 ]; then
                log_stat "MEDIUM findings" "$medium"
            fi
            
            # Show validated keys immediately
            if [ -s "$OUT_DIR/secrets/smart_secrets.txt" ]; then
                local validated=$(grep -c "Status:" "$OUT_DIR/secrets/smart_secrets.txt" 2>/dev/null || echo 0)
                if [ "$validated" -gt 0 ]; then
                    log_stat "Live-validated keys" "$validated"
                fi
            fi
        fi
    elif [ -f "/home/kali/.gemini/antigravity/scratch/REDHAVEN/modules/smart_secrets.py" ]; then
        # Fallback: try local path (outside Docker)
        log_step "Smart Secrets Engine: Entropy + Pattern + Validation scan..."
        python3 /home/kali/.gemini/antigravity/scratch/REDHAVEN/modules/smart_secrets.py \
            --urls "$OUT_DIR/endpoints/js_targets.txt" \
            --output "$OUT_DIR/secrets" \
            --workers 20 2>/dev/null || true
        
        if [ -s "$OUT_DIR/secrets/smart_secrets.json" ]; then
            local total=$(jq -r '.total_findings // 0' "$OUT_DIR/secrets/smart_secrets.json" 2>/dev/null || echo 0)
            log_stat "Smart Secrets Findings" "$total"
        fi
    else
        log_warn "smart_secrets.py not found. Falling back to basic pattern scan."
        # Minimal fallback: grep for obvious secrets in downloaded JS
        head -n 50 "$OUT_DIR/endpoints/js_targets.txt" | \
            parallel -j 20 --timeout 30 "curl -sL {} 2>/dev/null" | \
            grep -iE "(api_key|api_secret|access_key|secret_key|private_key|password)\s*[:=]\s*['\"][^'\"]{8,}" \
            > "$OUT_DIR/secrets/smart_secrets.txt" 2>/dev/null || true
    fi
    
    # ── STEP 3: LINKFINDER (Endpoint Discovery from JS) ──
    if [ -d "/tools/LinkFinder" ]; then
        log_step "LinkFinder: Extracting hidden endpoints from JS..."
        mkdir -p "$OUT_DIR/.temp/linkfinder"
        
        # Analyze ALL JS files (not just top 20)
        cat "$OUT_DIR/endpoints/js_targets.txt" | \
            parallel -j 10 --timeout 60 \
            "python3 /tools/LinkFinder/linkfinder.py -i {} -o cli 2>/dev/null" \
            >> "$OUT_DIR/endpoints/linkfinder_endpoints.txt" 2>/dev/null || true
        
        # Clean noisy output
        if [ -s "$OUT_DIR/endpoints/linkfinder_endpoints.txt" ]; then
            grep -v "Running against:" "$OUT_DIR/endpoints/linkfinder_endpoints.txt" | \
                grep -v "Invalid input" | sort -u -o "$OUT_DIR/endpoints/linkfinder_endpoints.txt"
            
            local lf_count=$(wc -l < "$OUT_DIR/endpoints/linkfinder_endpoints.txt" 2>/dev/null || echo 0)
            log_stat "LinkFinder New Endpoints" "$lf_count"
            
            # Feedback Loop: add new endpoints to clean_urls
            if [ "$lf_count" -gt 0 ]; then
                cat "$OUT_DIR/endpoints/linkfinder_endpoints.txt" >> "$OUT_DIR/endpoints/clean_urls.txt"
            fi
        fi
    fi
    
    # ── STEP 4: JSLUICE (Tree-sitter AST Analysis) ──
    if command -v jsluice >/dev/null 2>&1; then
        log_step "JSLuice: AST-based secret analysis..."
        
        # Download JS files for local analysis
        head -n 50 "$OUT_DIR/endpoints/js_targets.txt" | \
            parallel -j 20 --timeout 30 "wget -q -P $OUT_DIR/.temp/js_download {} 2>/dev/null" || true
        
        # Run JSLuice secrets + URLs
        jsluice secrets -R "$OUT_DIR/.temp/js_download" > "$OUT_DIR/secrets/jsluice_secrets.json" 2>/dev/null || true
        jsluice urls -R "$OUT_DIR/.temp/js_download" > "$OUT_DIR/secrets/jsluice_urls.json" 2>/dev/null || true
        
        if [ -s "$OUT_DIR/secrets/jsluice_secrets.json" ]; then
            jq -r '"[\(.severity // "info")] \(.kind // "unknown") - \(.data // "N/A")"' \
                "$OUT_DIR/secrets/jsluice_secrets.json" 2>/dev/null | sort -u > "$OUT_DIR/secrets/jsluice_summary.txt" || true
            log_stat "JSLuice Findings" "$(wc -l < "$OUT_DIR/secrets/jsluice_summary.txt" 2>/dev/null || echo 0)"
        fi
    fi
    
    # ── STEP 5: NUCLEI EXPOSURE TEMPLATES ──
    if [ -s "$OUT_DIR/endpoints/js_targets.txt" ]; then
        log_step "Nuclei: Scanning for exposed tokens and secrets..."
        nuclei -l "$OUT_DIR/endpoints/js_targets.txt" \
            -tags token,keys,exposure,secret \
            -severity medium,high,critical \
            -c 50 -rl 150 \
            -o "$OUT_DIR/secrets/nuclei_secrets.txt" -dr -duc 2>/dev/null || true
        
        if [ -s "$OUT_DIR/secrets/nuclei_secrets.txt" ]; then
            log_stat "Nuclei Secret Findings" "$(wc -l < "$OUT_DIR/secrets/nuclei_secrets.txt" 2>/dev/null || echo 0)"
        fi
    fi
    
    # ── STEP 6: GITLEAKS (Pattern-based deep scan) ──
    if command -v gitleaks >/dev/null 2>&1; then
        log_step "Gitleaks: Deep pattern scanning on downloaded files..."
        gitleaks detect --source="$OUT_DIR" --no-git \
            --report-path "$OUT_DIR/secrets/gitleaks_report.json" 2>/dev/null || true
        
        if [ -s "$OUT_DIR/secrets/gitleaks_report.json" ]; then
            local gl_count=$(jq 'length' "$OUT_DIR/secrets/gitleaks_report.json" 2>/dev/null || echo 0)
            log_stat "Gitleaks Findings" "$gl_count"
        fi
    fi
    
    # ── FINAL SUMMARY ──
    log_step "Consolidating all secret findings..."
    local total_files=0
    for f in "$OUT_DIR/secrets/smart_secrets.txt" "$OUT_DIR/secrets/jsluice_summary.txt" \
             "$OUT_DIR/secrets/nuclei_secrets.txt" "$OUT_DIR/secrets/gitleaks_report.json"; do
        if [ -s "$f" ]; then
            total_files=$((total_files + 1))
        fi
    done
    log_stat "Engines with findings" "$total_files / 4"
    
    # Create unified summary if smart_secrets didn't create one
    if [ ! -s "$OUT_DIR/secrets/smart_secrets.txt" ]; then
        touch "$OUT_DIR/secrets/smart_secrets.txt"
    fi
    
    log_success "Secrets Hunter v2 completed."
}

