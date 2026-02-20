#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === BUSINESS LOGIC FLAWS ===
# 16. LOGIC FLAWS v2 (Price Manipulation + Method Tampering + Param Pollution)
run_logic_flaws() {
    if check_dependency "$OUT_DIR/vulns/logic.txt" "Logic Flaws"; then return; fi
    log_phase "BUSINESS LOGIC FLAWS v2 (SMART ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/logic.txt"
    local finding_count=0
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for Logic Flaws testing. Skipping phase."
        return
    fi
    
    # ── STEP 1: SMART URL FILTER (keep existing logic) ──
    log_step "Filtering transactional and business-critical endpoints..."
    
    grep -iE "\?|/api/|/v[0-9]/|graphql|auth|login|register|signup|admin|account|profile|cart|order|checkout|pay|billing|user|dashboard|transfer|wallet|balance|credit|subscription|upgrade|downgrade|apply|claim|redeem|coupon|promo|gift|invite|verify|confirm|approve|reject|\.php|\.jsp|\.asp|\.aspx" \
        "$OUT_DIR/endpoints/clean_urls.txt" | sort -u > "$OUT_DIR/.temp/logic_targets.txt" || true
    
    local total_urls=$(wc -l < "$OUT_DIR/endpoints/clean_urls.txt")
    local smart_urls=$(wc -l < "$OUT_DIR/.temp/logic_targets.txt")
    
    log_stat "Total URLs" "$total_urls"
    log_stat "Business-critical URLs" "$smart_urls"
    
    if [ "$smart_urls" -lt 5 ] && [ "$total_urls" -gt 0 ]; then
        log_warn "Very strict filter. Using top 500 general URLs..."
        head -n 500 "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/logic_targets.txt"
        smart_urls=$(wc -l < "$OUT_DIR/.temp/logic_targets.txt")
    fi
    
    # ── STEP 2: PRICE/AMOUNT MANIPULATION ──
    log_step "Testing price and quantity manipulation..."
    
    # Find URLs with financial parameters
    grep -iE "(price|amount|total|quantity|qty|cost|fee|discount|balance|credit|value|rate|tax|shipping|tip|donation)=" \
        "$OUT_DIR/.temp/logic_targets.txt" > "$OUT_DIR/.temp/price_targets.txt" 2>/dev/null || true
    
    local price_count=$(wc -l < "$OUT_DIR/.temp/price_targets.txt" 2>/dev/null || echo 0)
    
    if [ "$price_count" -gt 0 ]; then
        log_stat "Financial parameter URLs" "$price_count"
        
        local price_payloads=("0" "-1" "0.01" "0.001" "99999999" "NaN" "null" "undefined")
        
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            
            # Get original response for comparison
            local orig_resp=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}|%{size_download}" "$url" 2>/dev/null || echo "000|0")
            local orig_code=$(echo "$orig_resp" | cut -d'|' -f1)
            local orig_size=$(echo "$orig_resp" | cut -d'|' -f2)
            
            for payload in "${price_payloads[@]}"; do
                local injected=$(echo "$url" | sed -E "s/(price|amount|total|quantity|qty|cost|fee|discount|balance)=[^&]*/\1=$payload/gi" 2>/dev/null || echo "")
                [ -z "$injected" ] || [ "$injected" = "$url" ] && continue
                
                local test_resp=$(curl -sL --max-time 5 -o /dev/null -w "%{http_code}|%{size_download}" "$injected" 2>/dev/null || echo "000|0")
                local test_code=$(echo "$test_resp" | cut -d'|' -f1)
                local test_size=$(echo "$test_resp" | cut -d'|' -f2)
                
                # If server accepts the manipulated value (200 OK, similar page)
                if [ "$test_code" = "200" ] && [ "$test_code" = "$orig_code" ]; then
                    local size_diff=$((test_size - orig_size))
                    [ "$size_diff" -lt 0 ] && size_diff=$((-size_diff))
                    
                    # Similar response = value accepted
                    if [ "$size_diff" -lt 500 ] 2>/dev/null; then
                        echo "[HIGH] PRICE MANIPULATION ACCEPTED: $injected" >> "$OUT_DIR/vulns/logic.txt"
                        echo "  Payload: $payload (response: $test_code, size diff: ${size_diff}B)" >> "$OUT_DIR/vulns/logic.txt"
                        finding_count=$((finding_count + 1))
                        break  # One finding per URL is enough
                    fi
                fi
            done
        done < <(head -n 30 "$OUT_DIR/.temp/price_targets.txt")
    fi
    
    # ── STEP 3: HTTP METHOD TAMPERING ──
    log_step "Testing HTTP method tampering (GET→PUT/DELETE/PATCH)..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        # Get original GET response
        local get_resp=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        
        for method in PUT DELETE PATCH; do
            local method_resp=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null || echo "000")
            
            # Interesting: method returns 200 when it shouldn't, or different behavior
            if [ "$method_resp" = "200" ] && [ "$get_resp" != "200" ]; then
                echo "[HIGH] METHOD TAMPERING ($method returns 200): $url" >> "$OUT_DIR/vulns/logic.txt"
                finding_count=$((finding_count + 1))
            elif [ "$method_resp" = "200" ] && echo "$url" | grep -qiE "delete|remove|admin|user"; then
                echo "[MEDIUM] $method ALLOWED on sensitive endpoint: $url" >> "$OUT_DIR/vulns/logic.txt"
                finding_count=$((finding_count + 1))
            fi
        done
    done < <(head -n 50 "$OUT_DIR/.temp/logic_targets.txt")
    
    # ── STEP 4: PARAMETER POLLUTION ──
    log_step "Testing HTTP parameter pollution..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        # Extract first param name and value
        local param_name=$(echo "$url" | grep -oP '\?\K[^=]+' | head -1)
        local param_val=$(echo "$url" | grep -oP "${param_name}=\K[^&]+" | head -1)
        
        [ -z "$param_name" ] || [ -z "$param_val" ] && continue
        
        # Add duplicate param with different value
        local polluted="${url}&${param_name}=POLLUTED_VALUE"
        
        local orig_resp=$(curl -sL --max-time 5 -o "$OUT_DIR/.temp/hpp_orig.tmp" -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        local poll_resp=$(curl -sL --max-time 5 -o "$OUT_DIR/.temp/hpp_poll.tmp" -w "%{http_code}" "$polluted" 2>/dev/null || echo "000")
        
        if [ "$orig_resp" = "200" ] && [ "$poll_resp" = "200" ]; then
            # Compare responses — if server uses second value, HPP works
            local orig_body=$(cat "$OUT_DIR/.temp/hpp_orig.tmp" 2>/dev/null | md5sum | cut -d' ' -f1)
            local poll_body=$(cat "$OUT_DIR/.temp/hpp_poll.tmp" 2>/dev/null | md5sum | cut -d' ' -f1)
            
            if [ "$orig_body" != "$poll_body" ]; then
                echo "[MEDIUM] HTTP PARAMETER POLLUTION: $url (param: $param_name)" >> "$OUT_DIR/vulns/logic.txt"
                finding_count=$((finding_count + 1))
            fi
        fi
    done < <(grep -E "\?" "$OUT_DIR/.temp/logic_targets.txt" | head -n 30)
    
    rm -f "$OUT_DIR/.temp/hpp_orig.tmp" "$OUT_DIR/.temp/hpp_poll.tmp"
    
    # ── STEP 5: NUCLEI SUPPLEMENTARY ──
    log_step "Nuclei: Running business logic templates..."
    if [ -s "$OUT_DIR/.temp/logic_targets.txt" ]; then
        nuclei -l "$OUT_DIR/.temp/logic_targets.txt" \
            -tags logic,api,graphql,workflow,business,auth-bypass \
            -timeout 6 -retries 1 -mhe 3 \
            -c 50 -rl 120 \
            -o "$OUT_DIR/.temp/nuclei_logic.txt" \
            -dr -silent 2>/dev/null || true
        
        if [ -s "$OUT_DIR/.temp/nuclei_logic.txt" ]; then
            cat "$OUT_DIR/.temp/nuclei_logic.txt" >> "$OUT_DIR/vulns/logic.txt"
            finding_count=$((finding_count + $(wc -l < "$OUT_DIR/.temp/nuclei_logic.txt")))
        fi
    fi
    
    log_stat "Logic Flaw Findings" "$finding_count"
    log_success "Business Logic Analysis v2 completed."
}

