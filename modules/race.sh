#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === RACE CONDITIONS ===
# 25. RACE CONDITIONS v2 (Burst Test + Response Analysis + Timing)
run_race_conditions() {
     if check_dependency "$OUT_DIR/vulns/race_conditions.txt" "Race Conditions"; then return; fi
     log_phase "RACE CONDITIONS v2 (CONCURRENT BURST ANALYSIS)"
     
     mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
     : > "$OUT_DIR/vulns/race_conditions.txt"
     local finding_count=0
     
     if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
         log_warn "No clean URLs found for Race Condition testing. Skipping."
         touch "$OUT_DIR/vulns/race_conditions.txt"
         return
     fi
     
     # ── STEP 1: IDENTIFY TRANSACTIONAL ENDPOINTS ──
     log_step "Filtering transactional/state-changing endpoints..."
     
     grep -iE "transfer|buy|claim|gift|promo|coupon|invite|send|verify|register|vote|like|follow|redeem|checkout|purchase|order|confirm|apply|submit|activate|upgrade|downgrade|cancel|refund|withdraw|deposit" \
        "$OUT_DIR/endpoints/clean_urls.txt" | sort -u > "$OUT_DIR/.temp/race_targets.txt" || true
     
     # Also include POST-likely endpoints from params
     if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
         grep -iE "token=|code=|coupon=|promo=|amount=|qty=|quantity=" \
             "$OUT_DIR/endpoints/params_only.txt" | head -n 20 >> "$OUT_DIR/.temp/race_targets.txt" 2>/dev/null || true
     fi
     
     sort -u "$OUT_DIR/.temp/race_targets.txt" -o "$OUT_DIR/.temp/race_targets.txt"
     local race_count=$(wc -l < "$OUT_DIR/.temp/race_targets.txt")
     log_stat "Transactional candidates" "$race_count"
     
     if [ "$race_count" -eq 0 ]; then
         log_warn "No transactional endpoints found."
         echo "# No transactional endpoints found" > "$OUT_DIR/vulns/race_conditions.txt"
         return
     fi
     
     # ── STEP 2: BURST TEST (20 concurrent requests) ──
     log_step "Launching 20-concurrent-request burst test per endpoint..."
     
     while IFS= read -r url; do
         [ -z "$url" ] && continue
         
         mkdir -p "$OUT_DIR/.temp/race_burst"
         rm -f "$OUT_DIR/.temp/race_burst/"* 2>/dev/null
         
         # A) Sequential baseline (3 requests for reference)
         local seq_start=$(date +%s%N 2>/dev/null || date +%s)
         for i in 1 2 3; do
             curl -s --max-time 5 -o "$OUT_DIR/.temp/race_burst/seq_${i}.tmp" -w "%{http_code}" "$url" > "$OUT_DIR/.temp/race_burst/seq_${i}_status.tmp" 2>/dev/null || true
         done
         local seq_end=$(date +%s%N 2>/dev/null || date +%s)
         
         # B) Concurrent burst (20 requests at once via parallel)
         local burst_start=$(date +%s%N 2>/dev/null || date +%s)
         seq 1 20 | parallel -j 20 --timeout 10 \
             "curl -s --max-time 5 -o $OUT_DIR/.temp/race_burst/burst_{}.tmp -w '%{http_code}' '$url' > $OUT_DIR/.temp/race_burst/burst_{}_status.tmp 2>/dev/null" 2>/dev/null || true
         local burst_end=$(date +%s%N 2>/dev/null || date +%s)
         
         # ── STEP 3: ANALYZE RESPONSES ──
         # Count unique response bodies (hash comparison)
         local unique_responses=0
         local total_ok=0
         
         : > "$OUT_DIR/.temp/race_burst/hashes.txt"
         for f in "$OUT_DIR/.temp/race_burst"/burst_*.tmp; do
             [ -f "$f" ] || continue
             local status_file="${f%.tmp}_status.tmp"
             local status=$(cat "$status_file" 2>/dev/null || echo "000")
             
             if [ "$status" = "200" ] || [ "$status" = "201" ] || [ "$status" = "302" ]; then
                 total_ok=$((total_ok + 1))
                 md5sum "$f" 2>/dev/null | cut -d' ' -f1 >> "$OUT_DIR/.temp/race_burst/hashes.txt"
             fi
         done
         
         if [ -s "$OUT_DIR/.temp/race_burst/hashes.txt" ]; then
             unique_responses=$(sort -u "$OUT_DIR/.temp/race_burst/hashes.txt" | wc -l)
         fi
         
         # Race condition indicators:
         # 1. All 20 requests succeeded (200) — no rate limit/lock
         # 2. All responses are identical — same action executed 20 times
         if [ "$total_ok" -ge 18 ]; then
             if [ "$unique_responses" -le 2 ]; then
                 echo "[HIGH] RACE CONDITION CANDIDATE: $url" >> "$OUT_DIR/vulns/race_conditions.txt"
                 echo "  → 20 concurrent requests: $total_ok succeeded, $unique_responses unique responses" >> "$OUT_DIR/vulns/race_conditions.txt"
                 echo "  → Identical responses suggest action executed multiple times without locking" >> "$OUT_DIR/vulns/race_conditions.txt"
                 finding_count=$((finding_count + 1))
             elif [ "$unique_responses" -ge 5 ]; then
                 echo "[MEDIUM] RACE VARIANCE DETECTED: $url" >> "$OUT_DIR/vulns/race_conditions.txt"
                 echo "  → $unique_responses unique responses from 20 concurrent — possible state inconsistency" >> "$OUT_DIR/vulns/race_conditions.txt"
                 finding_count=$((finding_count + 1))
             fi
         fi
         
         # Timing analysis: if burst is faster per-request than sequential, no throttling
         local time_diff=0
         if command -v bc > /dev/null 2>&1; then
             local seq_time=$(( (seq_end - seq_start) ))
             local burst_time=$(( (burst_end - burst_start) ))
             if [ "$burst_time" -gt 0 ] && [ "$seq_time" -gt 0 ]; then
                 if [ "$burst_time" -lt "$seq_time" ]; then
                     echo "[INFO] NO REQUEST THROTTLING: $url (burst faster than sequential)" >> "$OUT_DIR/vulns/race_conditions.txt"
                 fi
             fi
         fi
         
         rm -rf "$OUT_DIR/.temp/race_burst"
     done < <(head -n 30 "$OUT_DIR/.temp/race_targets.txt")
     
     
     
     log_stat "Race Condition Findings" "$finding_count"
     log_success "Race Conditions v2 completed."
}

