#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === WEBSOCKET ANALYSIS ===
# 26. WEBSOCKET ANALYSIS v2 (Discovery + Handshake + Origin + CSWSH)
run_websocket_analysis() {
    if check_dependency "$OUT_DIR/vulns/websocket_findings.txt" "WebSocket Analysis"; then return; fi
    log_phase "26: WEBSOCKET ANALYSIS v2 (SECURITY ASSESSMENT)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/websocket_findings.txt"
    local finding_count=0
    
    # ── STEP 1: DISCOVER WEBSOCKET ENDPOINTS ──
    log_step "Discovering WebSocket endpoints..."
    
    : > "$OUT_DIR/.temp/ws_candidates.txt"
    
    # Look in alive URLs for WS references
    if [ -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        grep -iE "ws://|wss://|socket|realtime|chat|notification|stream|websocket|hub|signalr" \
            "$OUT_DIR/endpoints/alive_urls.txt" >> "$OUT_DIR/.temp/ws_candidates.txt" 2>/dev/null || true
    fi
    
    # Look in JS files for WS URLs
    if [ -d "$OUT_DIR/.temp/js_download" ]; then
        grep -rhioE "wss?://[a-zA-Z0-9._/-]+" "$OUT_DIR/.temp/js_download/" >> "$OUT_DIR/.temp/ws_candidates.txt" 2>/dev/null || true
    fi
    
    # Common WS paths to probe
    local ws_paths=("/ws" "/wss" "/websocket" "/socket.io" "/sockjs" "/hub" "/signalr" "/cable" "/realtime" "/chat" "/stream" "/events" "/notifications")
    
    for path in "${ws_paths[@]}"; do
        echo "https://$TARGET${path}" >> "$OUT_DIR/.temp/ws_candidates.txt"
    done
    
    sort -u "$OUT_DIR/.temp/ws_candidates.txt" -o "$OUT_DIR/.temp/ws_candidates.txt"
    local ws_count=$(wc -l < "$OUT_DIR/.temp/ws_candidates.txt")
    log_stat "WS candidates" "$ws_count"
    
    # ── STEP 2: WEBSOCKET UPGRADE HANDSHAKE TEST ──
    log_step "Testing WebSocket upgrade handshake..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        # Convert https to proper URL for curl
        local test_url=$(echo "$url" | sed 's|wss://|https://|; s|ws://|http://|')
        
        local resp=$(curl -sI --max-time 10 \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Version: 13" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            "$test_url" 2>/dev/null || echo "")
        
        # Check for successful upgrade (101 Switching Protocols)
        if echo "$resp" | grep -qi "101"; then
            echo "[INFO] WEBSOCKET ENDPOINT FOUND: $test_url (101 Switching Protocols)" >> "$OUT_DIR/vulns/websocket_findings.txt"
            finding_count=$((finding_count + 1))
            
            # ── STEP 3: ORIGIN VALIDATION CHECK (CSWSH) ──
            local evil_resp=$(curl -sI --max-time 10 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Version: 13" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                -H "Origin: https://evil.com" \
                "$test_url" 2>/dev/null || echo "")
            
            if echo "$evil_resp" | grep -qi "101"; then
                echo "[CRITICAL] CSWSH: WebSocket accepts evil.com origin: $test_url" >> "$OUT_DIR/vulns/websocket_findings.txt"
                echo "  → Cross-Site WebSocket Hijacking possible (no origin validation)" >> "$OUT_DIR/vulns/websocket_findings.txt"
                finding_count=$((finding_count + 1))
            fi
            
            # Check for null origin
            local null_resp=$(curl -sI --max-time 10 \
                -H "Upgrade: websocket" \
                -H "Connection: Upgrade" \
                -H "Sec-WebSocket-Version: 13" \
                -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
                -H "Origin: null" \
                "$test_url" 2>/dev/null || echo "")
            
            if echo "$null_resp" | grep -qi "101"; then
                echo "[HIGH] CSWSH via null origin: $test_url" >> "$OUT_DIR/vulns/websocket_findings.txt"
                finding_count=$((finding_count + 1))
            fi
            
        elif echo "$resp" | grep -qi "200\|403\|404"; then
            # Not a WS endpoint but accessible
            true
        fi
    done < "$OUT_DIR/.temp/ws_candidates.txt"
    
    
    
    log_stat "WebSocket Security Findings" "$finding_count"
    log_success "WebSocket Analysis v2 completed."
}


