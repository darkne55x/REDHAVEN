#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === XSS ENGINE ===
# 8. XSS ENGINE v2
run_xss_engine() {
    if check_dependency "$OUT_DIR/vulns/xss.txt" "XSS Engine"; then return; fi
    log_phase "08: XSS INJECTION ENGINE v2 (REFLECTION + DOM + WAF-EVASION)"
    
    # Non-fatal check for parameters
    if [ ! -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_warn "No parameters found for XSS testing. Skipping phase."
        touch "$OUT_DIR/vulns/xss.txt"
        return
    fi
    
    mkdir -p "$OUT_DIR/.temp"
    
    # ── STEP 1: SMART TARGET SELECTION ──
    log_step "Deduplicating and filtering XSS targets..."
    cat "$OUT_DIR/endpoints/params_only.txt" | uro | sort -u > "$OUT_DIR/.temp/xss_targets.txt" || true
    local target_count=$(wc -l < "$OUT_DIR/.temp/xss_targets.txt" 2>/dev/null || echo 0)
    log_stat "Unique URL/Param combinations" "$target_count"
    
    if [ "$target_count" -eq 0 ]; then
        log_warn "No targets after deduplication. Skipping XSS."
        touch "$OUT_DIR/vulns/xss.txt"
        return
    fi
    
    # ── STEP 2: REFLECTION ANALYSIS (KXSS) ──
    log_step "KXSS: Identifying parameters with unfiltered reflection..."
    cat "$OUT_DIR/.temp/xss_targets.txt" | kxss 2>/dev/null | \
        grep -E "^http" | awk '{print $1}' | sort -u > "$OUT_DIR/.temp/kxss_reflective.txt" || true
    
    local reflect_count=$(wc -l < "$OUT_DIR/.temp/kxss_reflective.txt" 2>/dev/null || echo 0)
    log_stat "Params with unfiltered reflection" "$reflect_count"
    
    # ── STEP 3: DALFOX VERIFIED ATTACK ──
    if [ "$reflect_count" -gt 0 ]; then
        log_step "Dalfox: Verified XSS testing on reflective params..."
        
        # Build dalfox flags based on scan mode
        local dalfox_flags="--silence --worker 30 --timeout 10"
        
        # WAF evasion in deep mode
        if [ "${DEEP_MODE:-false}" = "true" ]; then
            dalfox_flags+=" --waf-evasion"
            log_step "Deep mode: WAF evasion payloads enabled"
        fi
        
        # Run dalfox with built-in payloads (no broken external download)
        cat "$OUT_DIR/.temp/kxss_reflective.txt" | dalfox pipe \
            $dalfox_flags \
            -o "$OUT_DIR/.temp/xss_raw.txt" 2>/dev/null || true
        
        # ── STEP 4: INTELLIGENT OUTPUT FILTERING ──
        # Dalfox outputs: [V] = Verified, [POC] = Proof of Concept, [I] = Informational
        # We only keep VERIFIED findings, not informational noise
        if [ -s "$OUT_DIR/.temp/xss_raw.txt" ]; then
            log_step "Filtering: keeping only verified XSS (removing info noise)..."
            
            # Keep only lines with [POC] or [V] markers — these are CONFIRMED XSS
            grep -E "\[POC\]|\[V\]|Triggered XSS|Vulnerable" "$OUT_DIR/.temp/xss_raw.txt" > "$OUT_DIR/vulns/xss.txt" 2>/dev/null || true
            
            # If no POC/V lines, fall back to any non-info finding
            if [ ! -s "$OUT_DIR/vulns/xss.txt" ]; then
                grep -vE "^\[I\]|^$|^#" "$OUT_DIR/.temp/xss_raw.txt" > "$OUT_DIR/vulns/xss.txt" 2>/dev/null || true
            fi
            
            local verified_count=$(wc -l < "$OUT_DIR/vulns/xss.txt" 2>/dev/null || echo 0)
            local raw_count=$(wc -l < "$OUT_DIR/.temp/xss_raw.txt" 2>/dev/null || echo 0)
            log_stat "Dalfox raw output" "$raw_count"
            log_stat "Verified XSS findings" "$verified_count"
        else
            touch "$OUT_DIR/vulns/xss.txt"
            log_warn "No XSS triggered by dalfox."
        fi
    else
        log_warn "No reflections detected by KXSS. Skipping reflected XSS attack."
        touch "$OUT_DIR/vulns/xss.txt"
    fi
    
    # ── STEP 5: DOM XSS SCANNING ──
    if [ -s "$OUT_DIR/endpoints/js_targets.txt" ]; then
        log_step "Nuclei: Scanning for DOM-based XSS patterns in JS..."
        nuclei -l "$OUT_DIR/endpoints/js_targets.txt" \
            -tags xss,domxss \
            -severity medium,high,critical \
            -c 30 -rl 100 \
            -o "$OUT_DIR/.temp/dom_xss.txt" -dr -duc 2>/dev/null || true
        
        if [ -s "$OUT_DIR/.temp/dom_xss.txt" ]; then
            log_stat "DOM XSS findings (nuclei)" "$(wc -l < "$OUT_DIR/.temp/dom_xss.txt")"
            cat "$OUT_DIR/.temp/dom_xss.txt" >> "$OUT_DIR/vulns/xss.txt"
        fi
    fi
    
    # ── STEP 6: NUCLEI XSS TEMPLATES ON ALL PARAMS ──
    log_step "Nuclei: Running XSS templates on parameter URLs..."
    nuclei -l "$OUT_DIR/.temp/xss_targets.txt" \
        -tags xss \
        -severity medium,high,critical \
        -c 30 -rl 100 \
        -o "$OUT_DIR/.temp/nuclei_xss.txt" -dr -duc 2>/dev/null || true
    
    if [ -s "$OUT_DIR/.temp/nuclei_xss.txt" ]; then
        log_stat "Nuclei XSS findings" "$(wc -l < "$OUT_DIR/.temp/nuclei_xss.txt")"
        cat "$OUT_DIR/.temp/nuclei_xss.txt" >> "$OUT_DIR/vulns/xss.txt"
    fi
    
    # Final dedup
    sort -u "$OUT_DIR/vulns/xss.txt" -o "$OUT_DIR/vulns/xss.txt" 2>/dev/null || true
    local final_count=$(wc -l < "$OUT_DIR/vulns/xss.txt" 2>/dev/null || echo 0)
    log_stat "Total confirmed XSS" "$final_count"
    
    log_success "XSS Engine v2 completed."
}

