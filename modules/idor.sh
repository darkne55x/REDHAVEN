#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === IDOR HUNTER ===
# 7. IDOR HUNTER
run_idor_hunter() {
    if check_dependency "$OUT_DIR/vulns/idor_candidates.txt" "IDOR Hunter"; then return; fi
    
    log_phase "IDOR & AUTH BYPASS HUNTER (INTELLIGENT)"
    
    # Non-fatal check
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for IDOR analysis. Skipping phase."
        touch "$OUT_DIR/vulns/idor_candidates.txt"
        return
    fi
    
    mkdir -p "$OUT_DIR/.temp"
    
    # ── STEP 1: SMART PATTERN EXTRACTION ──
    log_step "Extracting URLs with object-reference patterns..."
    
    # A) High-confidence IDOR params (names that reference specific objects)
    local SENSITIVE_PARAMS="user_id|userid|uid|account_id|accountid|acct|profile_id|"
    SENSITIVE_PARAMS+="order_id|orderid|invoice_id|doc_id|document_id|file_id|fileid|"
    SENSITIVE_PARAMS+="msg_id|message_id|chat_id|thread_id|comment_id|post_id|"
    SENSITIVE_PARAMS+="report_id|ticket_id|case_id|customer_id|client_id|member_id|"
    SENSITIVE_PARAMS+="project_id|org_id|organization_id|team_id|group_id|role_id|"
    SENSITIVE_PARAMS+="payment_id|transaction_id|subscription_id|plan_id|"
    SENSITIVE_PARAMS+="record_id|entry_id|item_id|product_id|sku|asset_id|"
    SENSITIVE_PARAMS+="email|username|phone|ssn|pin"
    
    # B) Expanded noise exclusion (70+ params known to NOT be IDORs)
    local NOISE_PARAMS="page|p|per_page|limit|size|offset|start|count|num|"
    NOISE_PARAMS+="width|height|w|h|x|y|zoom|scale|quality|q|dpr|"
    NOISE_PARAMS+="lang|locale|language|country|region|currency|"
    NOISE_PARAMS+="v|ver|version|rev|revision|build|"
    NOISE_PARAMS+="timestamp|ts|date|year|month|day|time|hour|minute|"
    NOISE_PARAMS+="utm_source|utm_medium|utm_campaign|utm_term|utm_content|"
    NOISE_PARAMS+="fbclid|gclid|msclkid|ref|referrer|source|"
    NOISE_PARAMS+="sort|order|orderby|sortby|direction|dir|asc|desc|"
    NOISE_PARAMS+="tab|step|stage|phase|state|status|view|mode|type|"
    NOISE_PARAMS+="filter|search|query|keyword|term|tag|category|"
    NOISE_PARAMS+="color|theme|font|style|format|layout|display|"
    NOISE_PARAMS+="debug|test|preview|draft|demo|sample|"
    NOISE_PARAMS+="callback|jsonp|_|nonce|token|csrf|captcha|"
    NOISE_PARAMS+="redirect|next|prev|back|return|continue|goto|"
    NOISE_PARAMS+="action|cmd|command|op|operation|method|"
    NOISE_PARAMS+="max|min|from|to|range|interval|duration|timeout|"
    NOISE_PARAMS+="columns|rows|fields|include|exclude|expand|"
    NOISE_PARAMS+="cache|expires|ttl|maxage|"
    NOISE_PARAMS+="lat|lon|lng|latitude|longitude|radius|distance|"
    NOISE_PARAMS+="popup|modal|overlay|collapsed|expanded|active|selected"
    
    # C) Find URLs with sensitive param names (HIGH confidence)
    grep -iE "(${SENSITIVE_PARAMS})=[^&]+" "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/idor_high.txt" 2>/dev/null || true
    
    # D) Find URLs with numeric values in params, excluding noise (MEDIUM confidence)
    grep -E "=[0-9]{1,10}(&|$)" "$OUT_DIR/endpoints/clean_urls.txt" | \
        grep -viE "(${NOISE_PARAMS})=" > "$OUT_DIR/.temp/idor_medium_raw.txt" 2>/dev/null || true
    
    # E) Find REST-style path-based IDs: /api/users/123/profile
    grep -E "/api/[a-z]+/[0-9]+(/|$)" "$OUT_DIR/endpoints/clean_urls.txt" > "$OUT_DIR/.temp/idor_path.txt" 2>/dev/null || true
    grep -E "/(users|accounts|orders|invoices|profiles|documents|messages|tickets|reports|customers)/[0-9]+" \
        "$OUT_DIR/endpoints/clean_urls.txt" >> "$OUT_DIR/.temp/idor_path.txt" 2>/dev/null || true
    
    # F) Find UUID-based IDs (suspicious when in known-sensitive paths)
    grep -E "=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}" "$OUT_DIR/endpoints/clean_urls.txt" | \
        grep -viE "(${NOISE_PARAMS})=" > "$OUT_DIR/.temp/idor_uuid.txt" 2>/dev/null || true
    
    local high_count=$(wc -l < "$OUT_DIR/.temp/idor_high.txt" 2>/dev/null || echo 0)
    local medium_count=$(wc -l < "$OUT_DIR/.temp/idor_medium_raw.txt" 2>/dev/null || echo 0)
    local path_count=$(wc -l < "$OUT_DIR/.temp/idor_path.txt" 2>/dev/null || echo 0)
    local uuid_count=$(wc -l < "$OUT_DIR/.temp/idor_uuid.txt" 2>/dev/null || echo 0)
    
    log_stat "HIGH confidence (sensitive param names)" "$high_count"
    log_stat "MEDIUM confidence (numeric values)" "$medium_count"
    log_stat "PATH-based IDs (/api/resource/123)" "$path_count"
    log_stat "UUID-based IDs" "$uuid_count"
    
    # ── STEP 2: DEDUP & MERGE ──
    log_step "Deduplicating and merging candidates..."
    cat "$OUT_DIR/.temp/idor_high.txt" "$OUT_DIR/.temp/idor_medium_raw.txt" \
        "$OUT_DIR/.temp/idor_path.txt" "$OUT_DIR/.temp/idor_uuid.txt" 2>/dev/null | \
        sort -u > "$OUT_DIR/.temp/idor_all.txt" || true
    
    # ── STEP 3: HTTP RESPONSE COMPARISON (Top candidates only) ──
    local total_candidates=$(wc -l < "$OUT_DIR/.temp/idor_all.txt" 2>/dev/null || echo 0)
    
    if [ "$total_candidates" -gt 0 ]; then
        log_step "HTTP verification: comparing response differences (top 30)..."
        
        # Take top 30 HIGH-confidence candidates for HTTP verification
        head -n 30 "$OUT_DIR/.temp/idor_high.txt" > "$OUT_DIR/.temp/idor_verify.txt" 2>/dev/null || true
        
        # For each URL, fetch original, then modify ID to check if response differs
        local verified_count=0
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            
            # Get original response
            local orig_status orig_size
            orig_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
            orig_size=$(curl -s -o /dev/null -w "%{size_download}" --max-time 5 "$url" 2>/dev/null || echo "0")
            
            # Modify the numeric ID: replace last numeric value with 99999
            local modified_url
            modified_url=$(echo "$url" | sed -E 's/=[0-9]+/=99999/g; s|/[0-9]+(/\|$)|/99999\1|g')
            
            if [ "$url" = "$modified_url" ]; then continue; fi
            
            local mod_status mod_size
            mod_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$modified_url" 2>/dev/null || echo "000")
            mod_size=$(curl -s -o /dev/null -w "%{size_download}" --max-time 5 "$modified_url" 2>/dev/null || echo "0")
            
            # If BOTH return 200 with similar sizes → likely NOT an IDOR (no auth check)
            # If original=200 but modified=403/401/404 → access control exists (less interesting)
            # If original=200 and modified=200 but DIFFERENT sizes → POTENTIAL IDOR
            if [ "$orig_status" = "200" ] && [ "$mod_status" = "200" ]; then
                local size_diff=$((orig_size - mod_size))
                [ $size_diff -lt 0 ] && size_diff=$((-size_diff))
                
                if [ "$size_diff" -gt 50 ]; then
                    echo "[VERIFIED-HIGH] $url (original=${orig_size}b, modified=${mod_size}b, diff=${size_diff}b)" >> "$OUT_DIR/vulns/idor_candidates.txt"
                    verified_count=$((verified_count + 1))
                fi
            elif [ "$orig_status" = "200" ] && [ "$mod_status" != "200" ]; then
                # Different status codes — interesting but may be normal auth
                echo "[VERIFIED-MEDIUM] $url (original=$orig_status, modified=$mod_status)" >> "$OUT_DIR/vulns/idor_candidates.txt"
                verified_count=$((verified_count + 1))
            fi
        done < "$OUT_DIR/.temp/idor_verify.txt"
        
        # Append remaining unverified HIGH candidates
        echo "" >> "$OUT_DIR/vulns/idor_candidates.txt"
        echo "# === UNVERIFIED CANDIDATES (manual review needed) ===" >> "$OUT_DIR/vulns/idor_candidates.txt"
        tail -n +31 "$OUT_DIR/.temp/idor_high.txt" >> "$OUT_DIR/vulns/idor_candidates.txt" 2>/dev/null || true
        
        # Append path-based candidates
        if [ -s "$OUT_DIR/.temp/idor_path.txt" ]; then
            echo "" >> "$OUT_DIR/vulns/idor_candidates.txt"
            echo "# === PATH-BASED IDOR CANDIDATES ===" >> "$OUT_DIR/vulns/idor_candidates.txt"
            cat "$OUT_DIR/.temp/idor_path.txt" >> "$OUT_DIR/vulns/idor_candidates.txt"
        fi
        
        local final_count=$(grep -c "^[^#]" "$OUT_DIR/vulns/idor_candidates.txt" 2>/dev/null || true)
        
        log_stat "HTTP-Verified IDOR" "$verified_count"
        log_stat "Total candidates (all confidence)" "$final_count"
    else
        touch "$OUT_DIR/vulns/idor_candidates.txt"
        log_warn "No IDOR candidates found."
    fi
    
    log_success "IDOR Hunter v2 completed."
}

