#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === CRLF INJECTION ===
# 11. CRLF INJECTION
run_crlf_scan() {
    if check_dependency "$OUT_DIR/vulns/crlf.txt" "CRLF Injection"; then return; fi
    
    log_phase "CRLF INJECTION (NINJA MODE)"
    
    if [ ! -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        log_warn "No clean URLs found for CRLF testing. Skipping phase."
        touch "$OUT_DIR/vulns/crlf.txt"
        return
    fi
    
    mkdir -p "$OUT_DIR/.temp"
    log_step "Filtering and deduplicating parameters with Uro..."

    # Filtro: Parámetros y Redirecciones + Deduplicación de estructura
    grep -iE "\?|redir|url=|next=|dest=|destination=|out=|view=|from=|callback=|checkout=|logout=" \
        "$OUT_DIR/endpoints/clean_urls.txt" | uro | sort -u > "$OUT_DIR/.temp/crlf_targets.txt"

    local total=$(wc -l < "$OUT_DIR/endpoints/clean_urls.txt")
    local optimized=$(wc -l < "$OUT_DIR/.temp/crlf_targets.txt")
    
    log_stat "Input URLs" "$total"
    log_stat "Unique Targets (Uro)" "$optimized"

    if [ "$optimized" -gt 0 ]; then
        log_step "CRLFuzz: Starting quick scan..."
        crlfuzz -l "$OUT_DIR/.temp/crlf_targets.txt" -o "$OUT_DIR/vulns/crlf.txt" -s || true
        
        local found=$(wc -l < "$OUT_DIR/vulns/crlf.txt" 2>/dev/null || echo 0)
        log_stat "CRLF Vulnerabilities" "$found"
        log_success "CRLF Scan completed."
    else
        log_warn "No unique targets for CRLF were detected."
        echo "# No CRLF targets found" > "$OUT_DIR/vulns/crlf.txt"
    fi
}

