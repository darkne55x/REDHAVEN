#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === CORS TESTING ===
# 37. CORS MISCONFIGURATION v2 (Multi-Origin + Credential Check + Bypass)
run_cors_testing() {
    if check_dependency "$OUT_DIR/vulns/cors_misconfigs.txt" "CORS Testing"; then return; fi
    log_phase "CORS MISCONFIGURATION v2 (MULTI-ORIGIN ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/cors_misconfigs.txt"
    local finding_count=0
    
    if [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ] && [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No URLs found for CORS testing. Skipping."
        return
    fi
    
    # ── STEP 1: SELECT TARGETS ──
    log_step "Selecting high-value CORS test targets..."
    
    : > "$OUT_DIR/.temp/cors_targets.txt"
    
    # Prioritize API endpoints and auth pages
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        grep -iE "/api/|/v[0-9]/|/graphql|/user|/account|/me|/profile|/dashboard|/admin|/auth|/oauth|/token" \
            "$OUT_DIR/endpoints/clean_urls.txt" | head -n 30 >> "$OUT_DIR/.temp/cors_targets.txt" 2>/dev/null || true
    fi
    
    # Add base URLs
    if [ -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        head -n 20 "$OUT_DIR/endpoints/alive_urls.txt" >> "$OUT_DIR/.temp/cors_targets.txt"
    fi
    
    # Always test root
    echo "https://$TARGET" >> "$OUT_DIR/.temp/cors_targets.txt"
    
    sort -u "$OUT_DIR/.temp/cors_targets.txt" -o "$OUT_DIR/.temp/cors_targets.txt"
    local target_count=$(wc -l < "$OUT_DIR/.temp/cors_targets.txt")
    log_stat "CORS test targets" "$target_count"
    
    # ── STEP 2: MULTI-ORIGIN TESTS ──
    log_step "Testing CORS with multiple origin bypass techniques..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        # Extract domain for crafting bypass origins
        local domain=$(echo "$url" | sed 's|https\?://||; s|/.*||')
        
        # ── TEST A: Reflected Origin (evil.com) ──
        local headers=$(curl -sI --max-time 5 \
            -H "Origin: https://evil.com" \
            "$url" 2>/dev/null || echo "")
        
        local acao=$(echo "$headers" | grep -i "^access-control-allow-origin:" | head -1 | tr -d '\r')
        local acac=$(echo "$headers" | grep -i "^access-control-allow-credentials:" | head -1 | tr -d '\r')
        
        if echo "$acao" | grep -qi "evil.com"; then
            if echo "$acac" | grep -qi "true"; then
                echo "[CRITICAL] CORS: Reflects arbitrary origin WITH credentials: $url" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                echo "  → Access-Control-Allow-Origin: evil.com + Allow-Credentials: true" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                echo "  → Full account takeover possible via cross-origin request" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                finding_count=$((finding_count + 1))
            else
                echo "[HIGH] CORS: Reflects arbitrary origin (no credentials): $url" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                finding_count=$((finding_count + 1))
            fi
            continue  # Already found worst case, skip other tests
        fi
        
        # ── TEST B: Null Origin ──
        headers=$(curl -sI --max-time 5 \
            -H "Origin: null" \
            "$url" 2>/dev/null || echo "")
        
        acao=$(echo "$headers" | grep -i "^access-control-allow-origin:" | head -1 | tr -d '\r')
        acac=$(echo "$headers" | grep -i "^access-control-allow-credentials:" | head -1 | tr -d '\r')
        
        if echo "$acao" | grep -qi "null"; then
            local severity="HIGH"
            [ "$(echo "$acac" | grep -qi 'true' && echo y)" = "y" ] && severity="CRITICAL"
            echo "[$severity] CORS: Accepts null origin: $url" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
            echo "  → Exploitable via sandboxed iframe (data: URI)" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
            finding_count=$((finding_count + 1))
            continue
        fi
        
        # ── TEST C: Subdomain Bypass (evil.target.com) ──
        headers=$(curl -sI --max-time 5 \
            -H "Origin: https://evil.$domain" \
            "$url" 2>/dev/null || echo "")
        
        acao=$(echo "$headers" | grep -i "^access-control-allow-origin:" | head -1 | tr -d '\r')
        
        if echo "$acao" | grep -qi "evil\.$domain"; then
            echo "[HIGH] CORS: Accepts arbitrary subdomain: $url" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
            echo "  → Origin: evil.$domain was reflected — any subdomain XSS escalates to full CORS bypass" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
            finding_count=$((finding_count + 1))
            continue
        fi
        
        # ── TEST D: Prefix Bypass (targetevil.com, target.com.evil.com) ──
        local bypass_origins=(
            "https://${domain}.evil.com"
            "https://${domain}evil.com"
            "https://evil-${domain}"
        )
        
        for origin in "${bypass_origins[@]}"; do
            headers=$(curl -sI --max-time 5 \
                -H "Origin: $origin" \
                "$url" 2>/dev/null || echo "")
            
            acao=$(echo "$headers" | grep -i "^access-control-allow-origin:" | head -1 | tr -d '\r')
            
            if echo "$acao" | grep -qi "$(echo $origin | sed 's|https://||')"; then
                echo "[HIGH] CORS: Prefix/suffix bypass accepted: $url" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                echo "  → Origin: $origin was reflected" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                finding_count=$((finding_count + 1))
                break
            fi
        done
        
        # ── TEST E: Wildcard + Credentials Check ──
        if [ -n "$acao" ] && echo "$acao" | grep -q '\*'; then
            if echo "$acac" | grep -qi "true"; then
                echo "[HIGH] CORS: Wildcard (*) with credentials=true: $url" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                echo "  → Browser will block this, but indicates misconfiguration" >> "$OUT_DIR/vulns/cors_misconfigs.txt"
                finding_count=$((finding_count + 1))
            fi
        fi
        
    done < "$OUT_DIR/.temp/cors_targets.txt"
    
    
    log_stat "CORS Misconfiguration Findings" "$finding_count"
    log_success "CORS Analysis v2 completed."
}

