#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === SWAGGER DISCOVERY ===
# 27. SWAGGER/OPENAPI DISCOVERY v2 (Multi-Path Probe + Spec Parser + Endpoint Extraction)
run_swagger_discovery() {
    if check_dependency "$OUT_DIR/reports/swagger_analysis.txt" "Swagger Discovery"; then return; fi
    log_phase "SWAGGER/OPENAPI DISCOVERY v2 (SPEC ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/reports" "$OUT_DIR/endpoints"
    : > "$OUT_DIR/reports/swagger_analysis.txt"
    : > "$OUT_DIR/endpoints/swagger_endpoints.txt"
    local finding_count=0
    
    # ── STEP 1: PROBE COMMON PATHS ──
    log_step "Probing 30+ common Swagger/OpenAPI paths..."
    
    local swagger_paths=(
        "/swagger.json" "/swagger/v1/swagger.json" "/swagger/v2/swagger.json"
        "/api-docs" "/api-docs.json" "/v2/api-docs" "/v3/api-docs"
        "/openapi.json" "/openapi.yaml" "/openapi/v3/api-docs"
        "/swagger-ui.html" "/swagger-ui/" "/swagger-ui/index.html"
        "/api/swagger.json" "/api/openapi.json" "/api/api-docs"
        "/docs" "/docs/api" "/redoc" "/api/docs"
        "/_swagger" "/_api-docs" "/api-explorer"
        "/swagger-resources" "/swagger-resources/configuration/ui"
        "/api/v1/swagger.json" "/api/v2/swagger.json"
        "/graphql/schema" "/__schema"
        "/actuator" "/actuator/info" "/actuator/env" "/actuator/health"
        "/api/schema" "/api/spec" "/apispec.json" "/apispec_1.json"
    )
    
    : > "$OUT_DIR/.temp/swagger_found.txt"
    
    for path in "${swagger_paths[@]}"; do
        local url="https://$TARGET${path}"
        local resp=$(curl -sL --max-time 5 -o "$OUT_DIR/.temp/swagger_resp.tmp" -w "%{http_code}|%{content_type}" "$url" 2>/dev/null || echo "000|")
        local status=$(echo "$resp" | cut -d'|' -f1)
        local ctype=$(echo "$resp" | cut -d'|' -f2)
        
        if [ "$status" = "200" ]; then
            local body=$(cat "$OUT_DIR/.temp/swagger_resp.tmp" 2>/dev/null || echo "")
            local body_size=$(wc -c < "$OUT_DIR/.temp/swagger_resp.tmp" 2>/dev/null || echo 0)
            
            # Skip tiny responses (likely error pages)
            [ "$body_size" -lt 50 ] && continue
            
            # Check if it's actual API documentation
            if echo "$body" | grep -qiE '"swagger"|"openapi"|"paths"|"definitions"|"components"|"info"|api-docs|swagger-ui|actuator'; then
                echo "$url" >> "$OUT_DIR/.temp/swagger_found.txt"
                echo "[HIGH] API DOCUMENTATION EXPOSED: $url" >> "$OUT_DIR/reports/swagger_analysis.txt"
                finding_count=$((finding_count + 1))
                
                # ── STEP 2: PARSE SPEC (if JSON) ──
                if echo "$body" | jq '.' > /dev/null 2>&1; then
                    log_step "Parsing API spec from: $path"
                    
                    # Extract API info
                    local api_title=$(echo "$body" | jq -r '.info.title // empty' 2>/dev/null)
                    local api_version=$(echo "$body" | jq -r '.info.version // empty' 2>/dev/null)
                    
                    if [ -n "$api_title" ]; then
                        echo "  API: $api_title v$api_version" >> "$OUT_DIR/reports/swagger_analysis.txt"
                    fi
                    
                    # Extract all paths → endpoints
                    local paths=$(echo "$body" | jq -r '.paths | keys[]' 2>/dev/null || true)
                    
                    if [ -n "$paths" ]; then
                        local path_count=$(echo "$paths" | wc -l)
                        log_stat "API endpoints in spec" "$path_count"
                        
                        echo "$paths" | while IFS= read -r api_path; do
                            echo "https://$TARGET${api_path}" >> "$OUT_DIR/endpoints/swagger_endpoints.txt"
                        done
                        
                        # ── STEP 3: FLAG DANGEROUS ENDPOINTS ──
                        echo "$paths" | grep -iE "admin|delete|remove|upload|file|exec|debug|internal|private|secret|config|backup|dump|export|import|migrate" | while IFS= read -r dangerous; do
                            echo "  [HIGH] DANGEROUS ENDPOINT: $dangerous" >> "$OUT_DIR/reports/swagger_analysis.txt"
                        done
                        
                        # Extract methods per path
                        local unauth_endpoints=0
                        echo "$body" | jq -r '.paths | to_entries[] | .key as $path | .value | to_entries[] | "\(.key|ascii_upcase) \($path) security:\(.value.security // [] | length)"' 2>/dev/null | while IFS= read -r ep_info; do
                            local method=$(echo "$ep_info" | awk '{print $1}')
                            local ep_path=$(echo "$ep_info" | awk '{print $2}')
                            local sec_count=$(echo "$ep_info" | grep -oP 'security:\K[0-9]+')
                            
                            # Flag DELETE/PUT without security
                            if [ "$sec_count" = "0" ] && echo "$method" | grep -qE "DELETE|PUT|PATCH|POST"; then
                                echo "  [CRITICAL] UNAUTHENTICATED $method: $ep_path" >> "$OUT_DIR/reports/swagger_analysis.txt"
                            fi
                        done
                    fi
                    
                    # Save full spec
                    echo "$body" | jq '.' > "$OUT_DIR/reports/swagger_spec_$(echo $path | tr '/' '_').json" 2>/dev/null || true
                fi
                
                # Check for Spring Boot Actuator (extra dangerous)
                if echo "$body" | grep -qi "actuator"; then
                    echo "[CRITICAL] SPRING BOOT ACTUATOR EXPOSED: $url" >> "$OUT_DIR/reports/swagger_analysis.txt"
                    echo "  → May expose /env (secrets), /heapdump (memory), /beans (internals)" >> "$OUT_DIR/reports/swagger_analysis.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
        fi
    done
    
    rm -f "$OUT_DIR/.temp/swagger_resp.tmp"
    
    local found_count=$(wc -l < "$OUT_DIR/.temp/swagger_found.txt" 2>/dev/null || echo 0)
    log_stat "API docs/specs found" "$found_count"
    
    # Add discovered endpoints to clean_urls
    if [ -s "$OUT_DIR/endpoints/swagger_endpoints.txt" ]; then
        sort -u "$OUT_DIR/endpoints/swagger_endpoints.txt" -o "$OUT_DIR/endpoints/swagger_endpoints.txt"
        local ep_count=$(wc -l < "$OUT_DIR/endpoints/swagger_endpoints.txt")
        log_stat "Endpoints extracted from specs" "$ep_count"
        
        cat "$OUT_DIR/endpoints/swagger_endpoints.txt" >> "$OUT_DIR/endpoints/clean_urls.txt"
        sort -u "$OUT_DIR/endpoints/clean_urls.txt" -o "$OUT_DIR/endpoints/clean_urls.txt"
    fi
    
    
    
    log_stat "Swagger/API Security Findings" "$finding_count"
    log_success "Swagger Discovery v2 completed."
}


