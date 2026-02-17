#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === 403 BYPASS ===
# 14. 403 ACCESS BYPASS (OPTIMIZADO CON PARALLEL)
run_403_bypass() {
    if check_dependency "$OUT_DIR/vulns/bypass_403.txt" "403 Bypass"; then return; fi
    
    log_phase "403/401 ACCESS BYPASS (NOMORE403)"
    
    # Extraemos URLs únicas con errores de acceso
    grep -E "403|401" "$OUT_DIR/endpoints/alive_urls.txt" | awk '{print $1}' | sort -u > "$OUT_DIR/.temp/forbidden_urls.txt" || true
    
    local count=$(wc -l < "$OUT_DIR/.temp/forbidden_urls.txt")
    
    if [ "$count" -gt 0 ]; then
        log_step "Starting bypass on $count targets..."
        
        # Limpiamos archivo
        : > "$OUT_DIR/vulns/bypass_403.txt"
        
        # USO DE PARALLEL PARA EVITAR OOM (OUT OF MEMORY) KILLER
        # -j 10: Máximo 10 procesos simultáneos (evita saturar RAM)
        # --timeout 60: Si se cuelga, lo mata al minuto
        # Use subshell to avoid cd breaking orchestrator context
        (
            cd /tools/nomore403 2>/dev/null || true
            cat "$OUT_DIR/.temp/forbidden_urls.txt" | parallel -j 10 --timeout 60 \
                "/usr/local/bin/nomore403 -u {} >> $OUT_DIR/vulns/bypass_403.txt 2>/dev/null" || true
        )
        
        if [ ! -s "$OUT_DIR/vulns/bypass_403.txt" ]; then
             echo "# Scan completed. No bypasses found." > "$OUT_DIR/vulns/bypass_403.txt"
        fi

        # --- FEEDBACK LOOP ---
        if grep -q "200 OK" "$OUT_DIR/vulns/bypass_403.txt"; then
             log_success "${PRIMARY}BYPASS SUCCESSFUL! Feeding back new endpoints...${RESET}"
             grep "200 OK" "$OUT_DIR/vulns/bypass_403.txt" | awk '{print $2}' >> "$OUT_DIR/endpoints/clean_urls.txt"
             grep "200 OK" "$OUT_DIR/vulns/bypass_403.txt" | awk '{print $2}' >> "$OUT_DIR/endpoints/alive_urls.txt"
             sort -u "$OUT_DIR/endpoints/clean_urls.txt" -o "$OUT_DIR/endpoints/clean_urls.txt"
             sort -u "$OUT_DIR/endpoints/alive_urls.txt" -o "$OUT_DIR/endpoints/alive_urls.txt"
        fi
        
        log_success "Bypass completed. Results in vulns/bypass_403.txt"
    else
        log_warn "No 403 URLs were found to process."
        echo "# No 403 targets found." > "$OUT_DIR/vulns/bypass_403.txt"
    fi
}

