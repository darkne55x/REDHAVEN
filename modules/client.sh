#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === CLIENT-SIDE FUZZING ===
# 18. CLIENT-SIDE FUZZING v2 (Redirect + DOM XSS + Clickjacking + Proto Pollution)
run_client_fuzzing() {
    if check_dependency "$OUT_DIR/vulns/open_redirect.txt" "Client-Side Fuzzing"; then return; fi
    
    log_phase "CLIENT-SIDE FUZZING v2 (DOM SECURITY SUITE)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/client_side_findings.txt"
    local finding_count=0
    
    # ── STEP 1: OPEN REDIRECT (Enhanced Payloads) ──
    log_step "Open Redirect: Multi-payload fuzzing..."
    
    if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        grep -iE "redirect|url|next|dest|out|view|to|return|r=|u=|continue|forward|goto|target|link|site" \
            "$OUT_DIR/endpoints/params_only.txt" > "$OUT_DIR/.temp/redirect_targets.txt" 2>/dev/null || true
        
        if [ -s "$OUT_DIR/.temp/redirect_targets.txt" ]; then
            local redir_payloads=(
                "http://evil.com"
                "//evil.com"
                "https://evil.com"
                "/\\evil.com"
                "javascript:alert(1)"
                "//evil.com/%2f.."
                "https://evil.com@legitimate.com"
                "https://legitimate.com.evil.com"
                "/%09/evil.com"
            )
            
            : > "$OUT_DIR/vulns/open_redirect.txt"
            
            for payload in "${redir_payloads[@]}"; do
                cat "$OUT_DIR/.temp/redirect_targets.txt" | head -n 50 | \
                    qsreplace "$payload" 2>/dev/null | \
                    $HTTPX_BIN -silent -status-code -location -mc 301,302,307 -threads 30 2>/dev/null | \
                    grep -iE "evil\.com" >> "$OUT_DIR/vulns/open_redirect.txt" 2>/dev/null || true
            done
            
            sort -u "$OUT_DIR/vulns/open_redirect.txt" -o "$OUT_DIR/vulns/open_redirect.txt"
            local redirect_count=$(wc -l < "$OUT_DIR/vulns/open_redirect.txt" 2>/dev/null || echo 0)
            log_stat "Open Redirects confirmed" "$redirect_count"
            finding_count=$((finding_count + redirect_count))
        else
            log_warn "No redirect parameters found."
            touch "$OUT_DIR/vulns/open_redirect.txt"
        fi
    else
        log_warn "No parameterized URLs. Skipping redirect test."
        touch "$OUT_DIR/vulns/open_redirect.txt"
    fi
    
    # ── STEP 2: DOM XSS SOURCE/SINK ANALYSIS ──
    log_step "Analyzing JavaScript files for DOM XSS sources and sinks..."
    
    local js_dir="$OUT_DIR/.temp/js_download"
    if [ -d "$js_dir" ] && [ -n "$(ls -A $js_dir 2>/dev/null)" ]; then
        : > "$OUT_DIR/.temp/dom_xss_findings.txt"
        
        # Sources (attacker-controlled input)
        local dom_sources='location\.hash|location\.search|location\.href|document\.referrer|document\.URL|document\.documentURI|window\.name|document\.cookie|window\.location|postMessage'
        
        # Sinks (dangerous output)
        local dom_sinks='innerHTML|outerHTML|document\.write|document\.writeln|eval\(|setTimeout\(|setInterval\(|Function\(|\.src\s*=|\.href\s*=|\.action\s*=|\.data\s*=|jQuery\.html\(|\$\(.*\.html\(|\.append\(|\.prepend\(|\.after\(|\.before\('
        
        for jsfile in "$js_dir"/*; do
            [ -f "$jsfile" ] || continue
            local basename=$(basename "$jsfile")
            
            # Find sources
            local sources_found=$(grep -oP "$dom_sources" "$jsfile" 2>/dev/null | sort -u | head -5 || true)
            local sinks_found=$(grep -oP "$dom_sinks" "$jsfile" 2>/dev/null | sort -u | head -5 || true)
            
            if [ -n "$sources_found" ] && [ -n "$sinks_found" ]; then
                echo "[HIGH] DOM XSS POTENTIAL: $basename" >> "$OUT_DIR/vulns/client_side_findings.txt"
                echo "  Sources: $(echo $sources_found | tr '\n' ', ')" >> "$OUT_DIR/vulns/client_side_findings.txt"
                echo "  Sinks: $(echo $sinks_found | tr '\n' ', ')" >> "$OUT_DIR/vulns/client_side_findings.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # DOM Clobbering patterns
            if grep -qP 'document\.getElementById\s*\([^)]+\)\s*\.' "$jsfile" 2>/dev/null; then
                if ! grep -qP 'document\.getElementById\s*\([^)]+\)\s*(\?\.|&&|!==?\s*null)' "$jsfile" 2>/dev/null; then
                    echo "[MEDIUM] DOM CLOBBERING RISK: $basename (getElementById without null check)" >> "$OUT_DIR/vulns/client_side_findings.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
            
            # window.name usage (classic DOM XSS vector)
            if grep -qP 'window\.name' "$jsfile" 2>/dev/null; then
                echo "[MEDIUM] WINDOW.NAME USAGE: $basename (potential DOM XSS via window.name)" >> "$OUT_DIR/vulns/client_side_findings.txt"
                finding_count=$((finding_count + 1))
            fi
        done
        
        log_stat "DOM XSS potential findings" "$(grep -c "\[HIGH\]\|\[MEDIUM\]" "$OUT_DIR/vulns/client_side_findings.txt" 2>/dev/null || echo 0)"
    else
        log_warn "No JS files downloaded. Run Secrets Hunter first for full analysis."
    fi
    
    # ── STEP 3: CLICKJACKING CHECK ──
    log_step "Testing for Clickjacking (missing frame protections)..."
    
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        : > "$OUT_DIR/.temp/clickjack_targets.txt"
        
        # Test top sensitive pages
        grep -iE "login|account|profile|settings|dashboard|admin|payment|checkout|transfer" \
            "$OUT_DIR/endpoints/clean_urls.txt" | head -n 20 > "$OUT_DIR/.temp/clickjack_targets.txt" 2>/dev/null || true
        
        # If no matches, just test root
        if [ ! -s "$OUT_DIR/.temp/clickjack_targets.txt" ]; then
            echo "https://$TARGET" > "$OUT_DIR/.temp/clickjack_targets.txt"
        fi
        
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            
            local headers=$(curl -sI --max-time 5 "$url" 2>/dev/null || echo "")
            
            local has_xfo=$(echo "$headers" | grep -qi "x-frame-options" && echo "yes" || echo "no")
            local has_csp_fa=$(echo "$headers" | grep -qi "frame-ancestors" && echo "yes" || echo "no")
            
            if [ "$has_xfo" = "no" ] && [ "$has_csp_fa" = "no" ]; then
                echo "[MEDIUM] CLICKJACKING POSSIBLE: $url (no X-Frame-Options or CSP frame-ancestors)" >> "$OUT_DIR/vulns/client_side_findings.txt"
                finding_count=$((finding_count + 1))
            fi
        done < "$OUT_DIR/.temp/clickjack_targets.txt"
    fi
    
    # ── STEP 4: PROTOTYPE POLLUTION ──
    log_step "Prototype Pollution: Nuclei + manual __proto__ check..."
    
    if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        # Nuclei templates
        nuclei -l "$OUT_DIR/endpoints/params_only.txt" \
            -tags prototype-pollution \
            -c 40 -rl 150 -timeout 5 \
            -o "$OUT_DIR/vulns/prototype_pollution.txt" -dr -silent 2>/dev/null || true
        
        # Manual __proto__ injection
        head -n 30 "$OUT_DIR/endpoints/params_only.txt" | while IFS= read -r url; do
            [ -z "$url" ] && continue
            local proto_url="${url}&__proto__[test]=polluted"
            local resp=$(curl -sL --max-time 5 "$proto_url" 2>/dev/null || echo "")
            
            if echo "$resp" | grep -q "polluted"; then
                echo "[HIGH] PROTOTYPE POLLUTION CONFIRMED: $url" >> "$OUT_DIR/vulns/client_side_findings.txt"
                finding_count=$((finding_count + 1))
            fi
        done
    fi
    
    log_stat "Client-Side Security Findings" "$finding_count"
    log_success "Client-Side Fuzzing v2 completed."
}

