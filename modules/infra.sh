#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === INFRASTRUCTURE & MOBILE ===
# 22. SUBDOMAIN TAKEOVER
run_subdomain_takeover() {
    if check_dependency "$OUT_DIR/vulns/subdomain_takeover.txt" "Subdomain Takeover"; then return; fi
    
    log_phase "SUBDOMAIN TAKEOVER DETECTION"
    
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
        
        local count=$(grep -c "VULNERABLE" "$OUT_DIR/vulns/subdomain_takeover.txt" 2>/dev/null || true)
        log_stat "Vulnerable Subdomains" "$count"
    else
        log_warn "No subdomains found even after recon. Skipping takeover detection."
        touch "$OUT_DIR/vulns/subdomain_takeover.txt"
    fi
}

# 23. APK ANALYSIS
run_apk_analysis() {
    if check_dependency "$OUT_DIR/reports/mobsf_apk.json" "APK Analysis"; then return; fi
    
    log_phase "APK SECURITY ANALYSIS"
    
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
    
    log_phase "iOS APP ANALYSIS"
    
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
    
    log_phase "BACKUP FILE DISCOVERY"
    
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
