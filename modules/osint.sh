#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === OSINT & REPORTING ===
# 45. OSINT INTELLIGENCE RECON (V2.0 — Smart Flag: --osint)
run_osint_recon() {
    if check_dependency "$OUT_DIR/osint/osint_google_dorks.txt" "OSINT Recon"; then return; fi
    log_phase "45: OSINT INTELLIGENCE RECON"
    
    mkdir -p "$OUT_DIR/osint"
    
    log_step "Running OSINT Intelligence Module..."
    python3 /usr/local/bin/osint_recon "$TARGET" "$OUT_DIR/osint" || true
    
    # Count results
    local dork_count=0
    local email_count=0
    if [ -f "$OUT_DIR/osint/osint_google_dorks.txt" ]; then
        dork_count=$(grep -cv "^#" "$OUT_DIR/osint/osint_google_dorks.txt" 2>/dev/null || echo 0)
    fi
    if [ -f "$OUT_DIR/osint/osint_emails.txt" ]; then
        email_count=$(grep -cv "^#" "$OUT_DIR/osint/osint_emails.txt" 2>/dev/null || echo 0)
    fi
    
    log_stat "Google Dorks Generated" "$dork_count"
    log_stat "Emails Harvested" "$email_count"
    
    # Check for critical findings
    if [ -f "$OUT_DIR/osint/osint_zone_transfer.json" ] && grep -q "CRITICAL" "$OUT_DIR/osint/osint_zone_transfer.json"; then
        log_success "CRITICAL: DNS Zone Transfer vulnerability found!"
    fi
    if [ -f "$OUT_DIR/osint/osint_source_maps.json" ] && grep -q "source_maps" "$OUT_DIR/osint/osint_source_maps.json"; then
        local map_count
        map_count=$(python3 -c "import json; print(len(json.load(open('$OUT_DIR/osint/osint_source_maps.json'))['source_maps']))" 2>/dev/null || echo 0)
        if [ "$map_count" -gt 0 ]; then
            log_stat "Exposed Source Maps" "$map_count"
        fi
    fi
    
    log_success "OSINT Intelligence completed. Results in osint/"
}

run_cloud_enum() {
    log_phase "46: CLOUD BUCKET ENUMERATION"
    
    if check_dependency "$OUT_DIR/osint/cloud_buckets.txt" "Cloud Enum"; then return; fi
    
    if ! command -v cloud_enum >/dev/null 2>&1; then
        log_warn "cloud_enum not found. Skipping bucket enumeration."
        return
    fi
    
    mkdir -p "$OUT_DIR/osint"
    
    # Derive keyword from domain (example.com -> example)
    local KEYWORD
    KEYWORD=$(echo "$TARGET" | cut -d'.' -f1)
    
    log_step "Searching for S3/Azure/GCP buckets with keyword: $KEYWORD..."
    
    # Run cloud_enum
    cloud_enum -k "$KEYWORD" -l "$OUT_DIR/osint/cloud_buckets_raw.txt" >/dev/null 2>&1 || true
    
    # Clean up output (cloud_enum output can be messy, we want findings)
    if [ -f "$OUT_DIR/osint/cloud_buckets_raw.txt" ]; then
        grep -E "OPEN|PROTECTED|Accessible" "$OUT_DIR/osint/cloud_buckets_raw.txt" > "$OUT_DIR/osint/cloud_buckets.txt" || true
        
        local bucket_count
        bucket_count=$(wc -l < "$OUT_DIR/osint/cloud_buckets.txt")
        
        if [ "$bucket_count" -gt 0 ]; then
             log_success "Found $bucket_count potentially interesting buckets!"
             cat "$OUT_DIR/osint/cloud_buckets.txt"
        else
             log_step "No interesting buckets found."
        fi
    fi
}


# CORRELACIÓN FINAL
run_correlation() {
    if check_dependency "$OUT_DIR/reports/correlated_findings.txt" "Data Correlation"; then return; fi
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
