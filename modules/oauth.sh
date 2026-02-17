#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === OAUTH ANALYSIS ===
# 21. OAUTH ANALYSIS v2 (Discovery + OIDC + Redirect Manipulation)
run_oauth_analysis() {
    if check_dependency "$OUT_DIR/vulns/oauth.txt" "OAuth Analysis"; then return; fi
    log_phase "21: OAUTH & OIDC AUDIT v2 (DISCOVERY + ATTACK)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/oauth.txt"
    local finding_count=0
    
    # ── STEP 1: OIDC DISCOVERY ──
    log_step "Probing for OpenID Connect / OAuth discovery endpoints..."
    
    local oidc_paths=(
        "/.well-known/openid-configuration"
        "/.well-known/oauth-authorization-server"
        "/oauth/authorize" "/oauth/token" "/oauth/callback"
        "/auth/realms" "/oauth2/authorize" "/oauth2/token"
        "/connect/authorize" "/connect/token"
        "/api/oauth" "/sso/login" "/auth/login"
        "/.well-known/jwks.json" "/oauth/jwks"
    )
    
    : > "$OUT_DIR/.temp/oauth_endpoints.txt"
    local oidc_config=""
    
    for path in "${oidc_paths[@]}"; do
        local url="https://$TARGET${path}"
        local resp=$(curl -sL --max-time 5 "$url" 2>/dev/null || echo "")
        local status=$(echo "$resp" | head -c 5)
        
        if [ -n "$resp" ] && ! echo "$resp" | grep -qi "not found\|404\|error"; then
            # Check for actual OAuth/OIDC content
            if echo "$resp" | grep -qiE "authorization_endpoint|issuer|token_endpoint|client_id|oauth|openid"; then
                echo "$url" >> "$OUT_DIR/.temp/oauth_endpoints.txt"
                
                if echo "$path" | grep -q "openid-configuration\|oauth-authorization-server"; then
                    echo "[HIGH] OIDC DISCOVERY FOUND: $url" >> "$OUT_DIR/vulns/oauth.txt"
                    oidc_config="$resp"
                    finding_count=$((finding_count + 1))
                    
                    # Extract key endpoints
                    local auth_ep=$(echo "$resp" | jq -r '.authorization_endpoint // empty' 2>/dev/null)
                    local token_ep=$(echo "$resp" | jq -r '.token_endpoint // empty' 2>/dev/null)
                    local jwks_uri=$(echo "$resp" | jq -r '.jwks_uri // empty' 2>/dev/null)
                    local issuer=$(echo "$resp" | jq -r '.issuer // empty' 2>/dev/null)
                    
                    echo "  Issuer: ${issuer:-unknown}" >> "$OUT_DIR/vulns/oauth.txt"
                    echo "  Authorization: ${auth_ep:-not found}" >> "$OUT_DIR/vulns/oauth.txt"
                    echo "  Token: ${token_ep:-not found}" >> "$OUT_DIR/vulns/oauth.txt"
                    echo "  JWKS: ${jwks_uri:-not found}" >> "$OUT_DIR/vulns/oauth.txt"
                    
                    # Check for supported grant types
                    local grants=$(echo "$resp" | jq -r '.grant_types_supported[]? // empty' 2>/dev/null)
                    if [ -n "$grants" ]; then
                        echo "  Grant Types:" >> "$OUT_DIR/vulns/oauth.txt"
                        echo "$grants" | sed 's/^/    - /' >> "$OUT_DIR/vulns/oauth.txt"
                        
                        if echo "$grants" | grep -q "implicit"; then
                            echo "  [HIGH] Implicit grant type supported — token leakage risk!" >> "$OUT_DIR/vulns/oauth.txt"
                            finding_count=$((finding_count + 1))
                        fi
                    fi
                    
                    # Check PKCE support
                    local pkce=$(echo "$resp" | jq -r '.code_challenge_methods_supported[]? // empty' 2>/dev/null)
                    if [ -z "$pkce" ]; then
                        echo "  [MEDIUM] PKCE not advertised — authorization code interception risk" >> "$OUT_DIR/vulns/oauth.txt"
                        finding_count=$((finding_count + 1))
                    fi
                fi
            fi
        fi
    done
    
    local oauth_count=$(wc -l < "$OUT_DIR/.temp/oauth_endpoints.txt" 2>/dev/null || echo 0)
    log_stat "OAuth/OIDC endpoints found" "$oauth_count"
    
    # ── STEP 2: CLIENT_ID EXTRACTION FROM JS ──
    log_step "Extracting client_id values from JS files..."
    
    local client_ids=""
    if [ -s "$OUT_DIR/endpoints/js_targets.txt" ]; then
        client_ids=$(head -n 20 "$OUT_DIR/endpoints/js_targets.txt" | \
            parallel -j 5 --timeout 10 "curl -sL {} 2>/dev/null" | \
            grep -oP '(client_id|clientId|client-id|CLIENT_ID)\s*[=:]\s*["\047]?\K[a-zA-Z0-9_.-]+' 2>/dev/null | \
            sort -u || true)
    fi
    
    # Also from clean URLs
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        local url_cids=$(grep -oP 'client_id=\K[^&]+' "$OUT_DIR/endpoints/clean_urls.txt" 2>/dev/null | sort -u || true)
        if [ -n "$url_cids" ]; then
            client_ids=$(printf "%s\n%s" "$client_ids" "$url_cids" | sort -u)
        fi
    fi
    
    if [ -n "$client_ids" ]; then
        echo "" >> "$OUT_DIR/vulns/oauth.txt"
        echo "[MEDIUM] CLIENT_IDs EXTRACTED:" >> "$OUT_DIR/vulns/oauth.txt"
        echo "$client_ids" | sed 's/^/  - /' >> "$OUT_DIR/vulns/oauth.txt"
        finding_count=$((finding_count + 1))
    fi
    
    # ── STEP 3: REDIRECT_URI MANIPULATION ──
    log_step "Testing redirect_uri manipulation..."
    
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        local oauth_urls=$(grep -iE "redirect_uri=|callback=|return_to=" "$OUT_DIR/endpoints/clean_urls.txt" 2>/dev/null || true)
        
        if [ -n "$oauth_urls" ]; then
            echo "" >> "$OUT_DIR/vulns/oauth.txt"
            
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                
                # Test: replace redirect_uri with attacker domain
                local manipulated=$(echo "$url" | sed 's|redirect_uri=[^&]*|redirect_uri=https://evil.com/callback|g; s|callback=[^&]*|callback=https://evil.com|g')
                
                local resp_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -L "$manipulated" 2>/dev/null || echo "000")
                
                if [ "$resp_code" = "200" ] || [ "$resp_code" = "302" ]; then
                    # Check if evil.com is in the Location header
                    local location=$(curl -sI --max-time 5 "$manipulated" 2>/dev/null | grep -i "^location:" || true)
                    
                    if echo "$location" | grep -qi "evil.com"; then
                        echo "[CRITICAL] REDIRECT_URI OPEN REDIRECT: $url" >> "$OUT_DIR/vulns/oauth.txt"
                        echo "  → Redirects to attacker domain!" >> "$OUT_DIR/vulns/oauth.txt"
                        finding_count=$((finding_count + 1))
                    fi
                fi
            done < <(echo "$oauth_urls" | head -n 20)
        fi
    fi
    
    # ── STEP 4: STATE PARAMETER CHECK ──
    log_step "Checking for state parameter enforcement..."
    
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        local auth_urls=$(grep -iE "oauth|authorize|auth.*callback" "$OUT_DIR/endpoints/clean_urls.txt" 2>/dev/null | head -n 10 || true)
        
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            
            if ! echo "$url" | grep -q "state="; then
                echo "[HIGH] NO STATE PARAMETER: $url (CSRF in OAuth flow)" >> "$OUT_DIR/vulns/oauth.txt"
                finding_count=$((finding_count + 1))
            fi
        done < <(echo "$auth_urls")
    fi
    
    # ── STEP 5: JWKS ENDPOINT ANALYSIS ──
    log_step "Analyzing JWKS endpoints..."
    
    local jwks_url="https://$TARGET/.well-known/jwks.json"
    local jwks_resp=$(curl -sL --max-time 5 "$jwks_url" 2>/dev/null || echo "")
    
    if echo "$jwks_resp" | grep -q '"keys"'; then
        echo "" >> "$OUT_DIR/vulns/oauth.txt"
        echo "[INFO] JWKS ENDPOINT FOUND: $jwks_url" >> "$OUT_DIR/vulns/oauth.txt"
        
        # Count keys and check algorithms
        local key_count=$(echo "$jwks_resp" | jq '.keys | length' 2>/dev/null || echo 0)
        echo "  Keys: $key_count" >> "$OUT_DIR/vulns/oauth.txt"
        
        local algs=$(echo "$jwks_resp" | jq -r '.keys[].alg // empty' 2>/dev/null | sort -u || true)
        if [ -n "$algs" ]; then
            echo "  Algorithms: $algs" >> "$OUT_DIR/vulns/oauth.txt"
        fi
    fi
    
    # ── STEP 6: NUCLEI SUPPLEMENTARY ──
    log_step "Nuclei: Running OAuth/SSO templates..."
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" \
            -tags oauth,openid-connect,sso,jwt \
            -c 30 -rl 100 \
            -o "$OUT_DIR/.temp/nuclei_oauth.txt" -dr -duc 2>/dev/null || true
        
        if [ -s "$OUT_DIR/.temp/nuclei_oauth.txt" ]; then
            cat "$OUT_DIR/.temp/nuclei_oauth.txt" >> "$OUT_DIR/vulns/oauth.txt"
            finding_count=$((finding_count + $(wc -l < "$OUT_DIR/.temp/nuclei_oauth.txt")))
        fi
    fi
    
    log_stat "OAuth/OIDC Security Findings" "$finding_count"
    log_success "OAuth Analyzer v2 completed."
}

