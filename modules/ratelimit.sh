#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === API RATE LIMIT BYPASS ===
# 20. API RATE LIMIT v2 (Discovery + Rapid-Fire + Bypass Techniques)
run_api_limit_bypass() {
    if check_dependency "$OUT_DIR/vulns/ratelimit.txt" "API Rate Limit"; then return; fi
    log_phase "API RATE LIMIT BYPASS v2 (DISCOVERY + ATTACK)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/ratelimit.txt"
    local finding_count=0
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs for rate limit testing. Skipping."
        return
    fi
    
    # ── STEP 1: IDENTIFY HIGH-VALUE RATE-LIMITED ENDPOINTS ──
    log_step "Identifying authentication and sensitive endpoints..."
    
    grep -iE "(login|signin|auth|register|signup|reset|forgot|password|otp|verify|token|2fa|mfa|api/v)" \
        "$OUT_DIR/endpoints/clean_urls.txt" | sort -u > "$OUT_DIR/.temp/ratelimit_targets.txt" 2>/dev/null || true
    
    # Fallback: use root + common paths
    if [ ! -s "$OUT_DIR/.temp/ratelimit_targets.txt" ]; then
        log_warn "No auth endpoints found. Testing common paths..."
        local common_paths=("/login" "/api/auth/login" "/api/v1/login" "/api/users" "/register" "/forgot-password" "/api/otp/send")
        for path in "${common_paths[@]}"; do
            local url="https://$TARGET${path}"
            local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
            if [ "$status" != "000" ] && [ "$status" != "404" ]; then
                echo "$url" >> "$OUT_DIR/.temp/ratelimit_targets.txt"
            fi
        done
    fi
    
    local target_count=$(wc -l < "$OUT_DIR/.temp/ratelimit_targets.txt" 2>/dev/null || echo 0)
    log_stat "Rate limit test targets" "$target_count"
    
    if [ "$target_count" -eq 0 ]; then
        log_warn "No suitable endpoints for rate limit testing."
        echo "# No suitable endpoints found" > "$OUT_DIR/vulns/ratelimit.txt"
        return
    fi
    
    # ── STEP 2: RAPID-FIRE TEST (50 requests burst) ──
    log_step "Rapid-fire testing (50 request burst per endpoint)..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        local success_count=0
        local blocked_count=0
        local last_status=""
        
        for i in $(seq 1 50); do
            local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
            
            if [ "$status" = "429" ] || [ "$status" = "503" ] || [ "$status" = "403" ]; then
                blocked_count=$((blocked_count + 1))
                last_status="$status"
                break
            else
                success_count=$((success_count + 1))
            fi
        done
        
        if [ "$blocked_count" -eq 0 ]; then
            echo "[HIGH] NO RATE LIMITING: $url (50/50 requests succeeded)" >> "$OUT_DIR/vulns/ratelimit.txt"
            finding_count=$((finding_count + 1))
        else
            echo "[INFO] Rate limited at request $success_count: $url (blocked with $last_status)" >> "$OUT_DIR/vulns/ratelimit.txt"
            
            # ── STEP 3: BYPASS TECHNIQUES ──
            log_step "Attempting rate limit bypass for: $url"
            
            # A) X-Forwarded-For rotation
            local xff_success=0
            for i in $(seq 1 20); do
                local random_ip="$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))"
                local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
                    -H "X-Forwarded-For: $random_ip" \
                    -H "X-Real-IP: $random_ip" \
                    -H "X-Original-Forwarded-For: $random_ip" \
                    "$url" 2>/dev/null || echo "000")
                
                if [ "$status" = "200" ] || [ "$status" = "401" ] || [ "$status" = "302" ]; then
                    xff_success=$((xff_success + 1))
                fi
            done
            
            if [ "$xff_success" -ge 15 ]; then
                echo "[CRITICAL] RATE LIMIT BYPASS via X-Forwarded-For: $url ($xff_success/20 succeeded)" >> "$OUT_DIR/vulns/ratelimit.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # B) Path normalization bypass
            local path_variants=("/" "/." "/%2e" "//" "/%20" "/%09")
            for variant in "${path_variants[@]}"; do
                local modified_url=$(echo "$url" | sed "s|$TARGET|$TARGET${variant}|")
                local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$modified_url" 2>/dev/null || echo "000")
                
                if [ "$status" = "200" ] || [ "$status" = "401" ] || [ "$status" = "302" ]; then
                    echo "[MEDIUM] PATH NORMALIZATION BYPASS: $modified_url (variant: '$variant')" >> "$OUT_DIR/vulns/ratelimit.txt"
                    finding_count=$((finding_count + 1))
                    break
                fi
            done
            
            # C) Case variation bypass
            local upper_url=$(echo "$url" | sed 's|/\([a-z]\)|/\U\1|g')
            if [ "$upper_url" != "$url" ]; then
                local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$upper_url" 2>/dev/null || echo "000")
                if [ "$status" = "200" ] || [ "$status" = "401" ]; then
                    echo "[MEDIUM] CASE VARIATION BYPASS: $upper_url" >> "$OUT_DIR/vulns/ratelimit.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
        fi
    done < <(head -n 10 "$OUT_DIR/.temp/ratelimit_targets.txt")
    
    # ── STEP 4: NUCLEI SUPPLEMENTARY ──
    log_step "Nuclei: Running rate limit templates..."
    nuclei -l "$OUT_DIR/.temp/ratelimit_targets.txt" \
        -tags rate-limit,bypass,waf \
        -c 20 -rl 50 \
        -o "$OUT_DIR/.temp/nuclei_ratelimit.txt" -dr -duc 2>/dev/null || true
    
    if [ -s "$OUT_DIR/.temp/nuclei_ratelimit.txt" ]; then
        cat "$OUT_DIR/.temp/nuclei_ratelimit.txt" >> "$OUT_DIR/vulns/ratelimit.txt"
        finding_count=$((finding_count + $(wc -l < "$OUT_DIR/.temp/nuclei_ratelimit.txt")))
    fi
    
    log_stat "Rate Limit Bypass Findings" "$finding_count"
    log_success "API Rate Limit Bypass v2 completed."
}

