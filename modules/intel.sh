#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === ENDPOINT INTELLIGENCE ===
# 17. ENDPOINT INTELLIGENCE ANALYZER (Smart Prioritizer)
run_ai_hunter() {
    if check_dependency "$OUT_DIR/vulns/ai_candidates.txt" "Endpoint Intelligence"; then return; fi
    log_phase "17B: ENDPOINT INTELLIGENCE ANALYZER"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns" "$OUT_DIR/reports"
    : > "$OUT_DIR/vulns/ai_candidates.txt"
    : > "$OUT_DIR/reports/ai_hunter_summary.txt"
    local finding_count=0
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs for analysis. Skipping."
        return
    fi
    
    # ── STEP 1: SCORE ENDPOINTS BY VULNERABILITY LIKELIHOOD (single-pass) ──
    log_step "Scoring endpoints by vulnerability likelihood..."
    
    awk '{
        url = $0; score = 0; tags = ""
        u = tolower(url)
        if (u ~ /\?/)                                                              { score += 2; tags = tags "PARAMS " }
        if (u ~ /\/api\/|\/v[0-9]\/|\/rest\/|\/graphql/)                           { score += 2; tags = tags "API " }
        if (u ~ /auth|login|signin|register|password|token|session|oauth|sso/)     { score += 3; tags = tags "AUTH " }
        if (u ~ /upload|file|import|attach|media|image|document/)                  { score += 3; tags = tags "UPLOAD " }
        if (u ~ /admin|dashboard|manage|panel|control|internal|debug|config/)      { score += 3; tags = tags "ADMIN " }
        if (u ~ /user|account|profile|order|payment|billing|invoice|cart/)         { score += 2; tags = tags "USERDATA " }
        if (u ~ /\.php|\.asp|\.jsp|\.cfm|\.cgi/)                                  { score += 1; tags = tags "DYNAMIC " }
        if (score >= 3) print "[" score "] [" tags "] " url
    }' "$OUT_DIR/endpoints/clean_urls.txt" | sort -t'[' -k2 -rn > "$OUT_DIR/vulns/ai_candidates.txt" 2>/dev/null || true
    
    local candidates=$(wc -l < "$OUT_DIR/vulns/ai_candidates.txt" 2>/dev/null || echo 0)
    log_stat "High-value targets identified" "$candidates"
    
    # ── STEP 2: QUICK ANOMALY DETECTION ──
    log_step "Probing top targets for debug mode and verbose errors..."
    
    head -n 20 "$OUT_DIR/vulns/ai_candidates.txt" | grep -oP 'https?://[^ ]+' | while IFS= read -r url; do
        [ -z "$url" ] && continue
        
        local resp=$(curl -sL --max-time 5 "$url" 2>/dev/null || echo "")
        
        # Check for debug/stack trace indicators
        if echo "$resp" | grep -qiE "stack trace|debug mode|traceback|exception|error in|syntax error|undefined variable|warning:.*line|fatal error|laravel|django debug|spring boot error"; then
            echo "[HIGH] DEBUG/VERBOSE ERROR: $url" >> "$OUT_DIR/reports/ai_hunter_summary.txt"
            echo "  → Application may be in debug mode (info disclosure)" >> "$OUT_DIR/reports/ai_hunter_summary.txt"
            finding_count=$((finding_count + 1))
        fi
        
        # Check for technology version disclosure
        if echo "$resp" | grep -qiE "powered by|server:|x-powered-by:|version [0-9]"; then
            local version=$(echo "$resp" | grep -oiE "(powered by|server:|version) [a-zA-Z0-9./ ]+" | head -1)
            echo "[MEDIUM] VERSION DISCLOSURE: $url → $version" >> "$OUT_DIR/reports/ai_hunter_summary.txt"
            finding_count=$((finding_count + 1))
        fi
    done
    
    
    
    log_stat "Intelligence Findings" "$finding_count"
    log_success "Endpoint Intelligence Analysis completed."
}

