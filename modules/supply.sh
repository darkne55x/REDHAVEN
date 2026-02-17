#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === SUPPLY CHAIN (DEPHUNTER) ===
# 12. SUPPLY CHAIN (CORREGIDO - REGEX FIX)
run_dephunter() {
    if check_dependency "$OUT_DIR/vulns/supply_chain.txt" "Supply Chain"; then return; fi
    
    log_phase "SUPPLY CHAIN & REPO EXPOSURE (ROOTS ONLY)"
    
    # 0. Validación
    if [ ! -s "$OUT_DIR/recon/urls.txt" ] && [ ! -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        log_warn "No URL files were found."
        return 0
    fi
    
    log_step "Selecting only Roots and Level 1 Directories..."
    mkdir -p "$OUT_DIR/.temp"
    : > "$OUT_DIR/.temp/supply_raw.txt"
    
    # A. Subdominios base
    if [ -s "$OUT_DIR/recon/urls.txt" ]; then
        cat "$OUT_DIR/recon/urls.txt" >> "$OUT_DIR/.temp/supply_raw.txt" || true
    fi

    # B. Extraemos URLs vivas (Nivel 1)
    if [ -s "$OUT_DIR/endpoints/alive_urls.txt" ]; then
        # Awk para extraer solo hasta la primera carpeta
        awk -F/ '{print $1"//"$3"/"$4}' "$OUT_DIR/endpoints/alive_urls.txt" | sort -u >> "$OUT_DIR/.temp/supply_raw.txt" || true
    fi

    # C. LIMPIEZA CORREGIDA (Aquí estaba el error)
    # Antes: grep -vE "\." (Borraba todo lo que tuviera un punto, incluidos dominios)
    # Ahora: Filtramos solo si termina en extensiones basura conocidas
    
    if [ -s "$OUT_DIR/.temp/supply_raw.txt" ]; then
        grep -viE "\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|eot|pdf)$" "$OUT_DIR/.temp/supply_raw.txt" | sort -u > "$OUT_DIR/.temp/supply_targets.txt" || true
    else
        touch "$OUT_DIR/.temp/supply_targets.txt"
    fi
    
    local count=$(wc -l < "$OUT_DIR/.temp/supply_targets.txt")
    log_stat "Supply Chain Targets (Reduced)" "$count"
    
    # 2. Escaneo
    if [ "$count" -gt 0 ]; then
        log_step "Running Nuclei on critical targets (Optimized)..."
        nuclei -l "$OUT_DIR/.temp/supply_targets.txt" \
            -tags config,cicd,keys,git,svn,env,credential \
            -timeout 4 -retries 0 -mhe 2 \
            -c 30 -rl 150 \
            -o "$OUT_DIR/vulns/supply_chain.txt" \
            -dr -silent || true
            
        log_success "Supply Chain completed."
    else
        log_warn "There are no valid objectives for Supply Chain."
        echo "# No targets found" > "$OUT_DIR/vulns/supply_chain.txt"
    fi
}

