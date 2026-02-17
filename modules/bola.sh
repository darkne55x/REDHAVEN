#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === BOLA/BFLA ===
# 28. BOLA/BFLA API TESTING v2 (ID Manipulation + Method Auth + Horizontal Escalation)
run_bola_bfla() {
    if check_dependency "$OUT_DIR/vulns/bola_bfla.txt" "BOLA/BFLA Testing"; then return; fi
    log_phase "BOLA/BFLA v2 (API AUTHORIZATION ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/bola_bfla.txt"
    local finding_count=0
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for BOLA/BFLA testing. Skipping."
        return
    fi
    
    # ── STEP 1: FILTER API ENDPOINTS WITH ID PARAMS ──
    log_step "Identifying API endpoints with object references..."
    
    : > "$OUT_DIR/.temp/bola_targets.txt"
    
    # URLs with numeric IDs in path (/users/123, /api/v1/orders/456)
    grep -iE "/api/|/v[0-9]/|/graphql|/rest/" "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/api_endpoints.txt" 2>/dev/null || true
    
    # Also get parameterized endpoints with ID-like params
    if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        grep -iE "id=|user_id=|uid=|account=|order=|item=|product=|doc=|file_id=|record=" \
            "$OUT_DIR/endpoints/params_only.txt" >> "$OUT_DIR/.temp/bola_targets.txt" 2>/dev/null || true
    fi
    
    # Add API endpoints
    if [ -s "$OUT_DIR/.temp/api_endpoints.txt" ]; then
        cat "$OUT_DIR/.temp/api_endpoints.txt" >> "$OUT_DIR/.temp/bola_targets.txt"
    fi
    
    sort -u "$OUT_DIR/.temp/bola_targets.txt" -o "$OUT_DIR/.temp/bola_targets.txt"
    local target_count=$(wc -l < "$OUT_DIR/.temp/bola_targets.txt" 2>/dev/null || echo 0)
    log_stat "BOLA/BFLA test targets" "$target_count"
    
    if [ "$target_count" -eq 0 ]; then
        log_warn "No API endpoints with object references found."
        echo "# No API endpoints with object references found" > "$OUT_DIR/vulns/bola_bfla.txt"
        return
    fi
    
    # ── STEP 2: IDOR TEST (ID Manipulation) ──
    log_step "Testing IDOR via ID manipulation..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        # Extract numeric ID from URL path or params
        local id=$(echo "$url" | grep -oP '/(\d{1,10})(/|$|\?)' | head -1 | tr -d '/')
        [ -z "$id" ] && id=$(echo "$url" | grep -oP 'id=(\d+)' | head -1 | grep -oP '\d+')
        [ -z "$id" ] && continue
        
        # Get original response
        local orig_status=$(curl -s --max-time 5 -o "$OUT_DIR/.temp/bola_orig.tmp" -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        local orig_size=$(wc -c < "$OUT_DIR/.temp/bola_orig.tmp" 2>/dev/null || echo 0)
        
        # Skip non-accessible endpoints
        [ "$orig_status" = "000" ] || [ "$orig_status" = "404" ] && continue
        
        # Try adjacent IDs (IDOR)
        local next_id=$((id + 1))
        local prev_id=$((id - 1))
        [ "$prev_id" -lt 0 ] && prev_id=0
        
        for test_id in "$next_id" "$prev_id"; do
            local test_url=$(echo "$url" | sed "s|/$id/|/$test_id/|; s|/$id$|/$test_id|; s|id=$id|id=$test_id|")
            [ "$test_url" = "$url" ] && continue
            
            local test_status=$(curl -s --max-time 5 -o "$OUT_DIR/.temp/bola_test.tmp" -w "%{http_code}" "$test_url" 2>/dev/null || echo "000")
            local test_size=$(wc -c < "$OUT_DIR/.temp/bola_test.tmp" 2>/dev/null || echo 0)
            
            if [ "$test_status" = "200" ] && [ "$test_size" -gt 50 ]; then
                # Verify it's different data (not a generic page)
                local orig_hash=$(md5sum "$OUT_DIR/.temp/bola_orig.tmp" 2>/dev/null | cut -d' ' -f1)
                local test_hash=$(md5sum "$OUT_DIR/.temp/bola_test.tmp" 2>/dev/null | cut -d' ' -f1)
                
                if [ "$orig_hash" != "$test_hash" ]; then
                    echo "[HIGH] BOLA/IDOR: ID $id → $test_id returns different data: $test_url" >> "$OUT_DIR/vulns/bola_bfla.txt"
                    echo "  → Original: $orig_status ($orig_size bytes) vs Modified: $test_status ($test_size bytes)" >> "$OUT_DIR/vulns/bola_bfla.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
        done
    done < <(head -n 30 "$OUT_DIR/.temp/bola_targets.txt")
    
    rm -f "$OUT_DIR/.temp/bola_orig.tmp" "$OUT_DIR/.temp/bola_test.tmp"
    
    # ── STEP 3: BFLA (Method Authorization) ──
    log_step "Testing BFLA via unauthorized method access..."
    
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        for method in DELETE PUT PATCH; do
            local method_resp=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null || echo "000")
            
            if [ "$method_resp" = "200" ] || [ "$method_resp" = "204" ]; then
                echo "[HIGH] BFLA: $method accepted (no auth): $url" >> "$OUT_DIR/vulns/bola_bfla.txt"
                echo "  → Unauthenticated $method returned $method_resp — potential unauthorized action" >> "$OUT_DIR/vulns/bola_bfla.txt"
                finding_count=$((finding_count + 1))
            fi
        done
    done < <(head -n 20 "$OUT_DIR/.temp/api_endpoints.txt" 2>/dev/null)
    
    
    
    log_stat "BOLA/BFLA Findings" "$finding_count"
    log_success "BOLA/BFLA Analysis v2 completed."
}

