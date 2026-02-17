#!/bin/bash
# REDHAVEN Module — Sourced by scanner.sh
# Do not run directly

# === GRAPHQL DEEP ===
# 19. GRAPHQL DEEP v2 (Discovery + Introspection + Mutation Analysis)
run_graphql_deep() {
    if check_dependency "$OUT_DIR/vulns/graphql.txt" "GraphQL Deep"; then return; fi
    log_phase "19: GRAPHQL DEEP AUDIT v2 (INTROSPECTION + MUTATION ANALYSIS)"
    
    mkdir -p "$OUT_DIR/.temp" "$OUT_DIR/vulns"
    : > "$OUT_DIR/vulns/graphql.txt"
    local finding_count=0
    
    # ── STEP 1: ENDPOINT DISCOVERY ──
    log_step "Discovering GraphQL endpoints..."
    
    local gql_paths=(
        "/graphql" "/gql" "/api/graphql" "/api/gql"
        "/graphql/console" "/graphql/playground" "/graphiql"
        "/altair" "/explorer" "/v1/graphql" "/v2/graphql"
        "/query" "/api/query" "/graphql/v1" "/graphql/schema"
    )
    
    : > "$OUT_DIR/.temp/graphql_endpoints.txt"
    
    for path in "${gql_paths[@]}"; do
        local url="https://$TARGET${path}"
        local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        
        if [ "$status" = "200" ] || [ "$status" = "400" ] || [ "$status" = "405" ]; then
            echo "$url [$status]" >> "$OUT_DIR/.temp/graphql_endpoints.txt"
        fi
    done
    
    # Also check from discovered URLs
    if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
        grep -iE "graphql|gql|query" "$OUT_DIR/endpoints/clean_urls.txt" >> "$OUT_DIR/.temp/graphql_endpoints.txt" 2>/dev/null || true
    fi
    
    sort -u "$OUT_DIR/.temp/graphql_endpoints.txt" -o "$OUT_DIR/.temp/graphql_endpoints.txt"
    local gql_count=$(wc -l < "$OUT_DIR/.temp/graphql_endpoints.txt" 2>/dev/null || echo 0)
    log_stat "GraphQL endpoints found" "$gql_count"
    
    if [ "$gql_count" -eq 0 ]; then
        log_warn "No GraphQL endpoints found."
        echo "# No GraphQL endpoints found" > "$OUT_DIR/vulns/graphql.txt"
        
        # Still run nuclei as fallback
        if [ -s "$OUT_DIR/endpoints/clean_urls.txt" ]; then
            nuclei -l "$OUT_DIR/endpoints/clean_urls.txt" -tags graphql,introspection -o "$OUT_DIR/vulns/graphql.txt" -dr -duc 2>/dev/null || true
        fi
        return
    fi
    
    # ── STEP 2: INTROSPECTION TEST ──
    log_step "Testing introspection on discovered endpoints..."
    
    local introspection_query='{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name } } } } }"}'
    
    while IFS= read -r line; do
        local endpoint=$(echo "$line" | awk '{print $1}')
        [ -z "$endpoint" ] && continue
        
        # Send introspection query
        local response=$(curl -s --max-time 10 \
            -H "Content-Type: application/json" \
            -d "$introspection_query" \
            "$endpoint" 2>/dev/null || echo "")
        
        if echo "$response" | grep -q "__schema"; then
            echo "[CRITICAL] INTROSPECTION ENABLED: $endpoint" >> "$OUT_DIR/vulns/graphql.txt"
            finding_count=$((finding_count + 1))
            
            # Save full schema
            echo "$response" | jq '.' > "$OUT_DIR/vulns/graphql_schema_$(echo $endpoint | md5sum | cut -c1-8).json" 2>/dev/null || true
            
            # ── STEP 3: EXTRACT MUTATIONS ──
            log_step "Extracting mutations from schema..."
            
            local mutations=$(echo "$response" | jq -r '.data.__schema.mutationType.name // empty' 2>/dev/null)
            if [ -n "$mutations" ]; then
                # Extract all mutation fields
                echo "$response" | jq -r '.data.__schema.types[] | select(.name == "Mutation") | .fields[]?.name' 2>/dev/null > "$OUT_DIR/.temp/gql_mutations.txt" || true
                
                local mut_count=$(wc -l < "$OUT_DIR/.temp/gql_mutations.txt" 2>/dev/null || echo 0)
                log_stat "Mutations discovered" "$mut_count"
                
                echo "  Mutations found:" >> "$OUT_DIR/vulns/graphql.txt"
                cat "$OUT_DIR/.temp/gql_mutations.txt" | sed 's/^/    - /' >> "$OUT_DIR/vulns/graphql.txt"
                
                # Flag dangerous mutations
                local dangerous_muts=$(grep -iE "delete|remove|drop|destroy|update.*role|create.*admin|reset.*password|change.*email|elevate|grant|revoke|impersonate|sudo" \
                    "$OUT_DIR/.temp/gql_mutations.txt" 2>/dev/null || true)
                
                if [ -n "$dangerous_muts" ]; then
                    echo "  [HIGH] DANGEROUS MUTATIONS FOUND:" >> "$OUT_DIR/vulns/graphql.txt"
                    echo "$dangerous_muts" | sed 's/^/    [!] /' >> "$OUT_DIR/vulns/graphql.txt"
                    finding_count=$((finding_count + 1))
                fi
            fi
            
            # Extract all types
            echo "$response" | jq -r '.data.__schema.types[] | select(.kind == "OBJECT") | .name' 2>/dev/null | \
                grep -vE "^__" | sort > "$OUT_DIR/.temp/gql_types.txt" || true
            
            local type_count=$(wc -l < "$OUT_DIR/.temp/gql_types.txt" 2>/dev/null || echo 0)
            log_stat "Object types discovered" "$type_count"
            
            # Flag sensitive types
            local sensitive_types=$(grep -iE "user|admin|account|credential|secret|token|password|payment|card|ssn|role|permission" \
                "$OUT_DIR/.temp/gql_types.txt" 2>/dev/null || true)
            
            if [ -n "$sensitive_types" ]; then
                echo "  [MEDIUM] SENSITIVE TYPES EXPOSED:" >> "$OUT_DIR/vulns/graphql.txt"
                echo "$sensitive_types" | sed 's/^/    - /' >> "$OUT_DIR/vulns/graphql.txt"
            fi
            
        elif echo "$response" | grep -qi "introspection.*disabled\|not.*allowed\|forbidden"; then
            echo "[INFO] Introspection DISABLED: $endpoint (good security)" >> "$OUT_DIR/vulns/graphql.txt"
        fi
        
        # ── STEP 4: QUERY BATCHING TEST ──
        local batch_query='[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
        local batch_resp=$(curl -s --max-time 5 \
            -H "Content-Type: application/json" \
            -d "$batch_query" \
            "$endpoint" 2>/dev/null || echo "")
        
        if echo "$batch_resp" | grep -q "__typename"; then
            echo "[MEDIUM] QUERY BATCHING ENABLED: $endpoint (DoS + brute-force risk)" >> "$OUT_DIR/vulns/graphql.txt"
            finding_count=$((finding_count + 1))
        fi
        
        # ── STEP 5: FIELD SUGGESTION TEST ──
        local typo_query='{"query":"{ usre { id } }"}'
        local suggest_resp=$(curl -s --max-time 5 \
            -H "Content-Type: application/json" \
            -d "$typo_query" \
            "$endpoint" 2>/dev/null || echo "")
        
        if echo "$suggest_resp" | grep -qiE "did you mean|suggestion"; then
            echo "[LOW] FIELD SUGGESTIONS ENABLED: $endpoint (schema enumeration via typos)" >> "$OUT_DIR/vulns/graphql.txt"
            finding_count=$((finding_count + 1))
        fi
        
        echo "" >> "$OUT_DIR/vulns/graphql.txt"
    done < "$OUT_DIR/.temp/graphql_endpoints.txt"
    
    # ── STEP 6: NUCLEI SUPPLEMENTARY ──
    log_step "Nuclei: Running GraphQL templates..."
    nuclei -l "$OUT_DIR/.temp/graphql_endpoints.txt" \
        -tags graphql,introspection \
        -c 20 -rl 50 \
        -o "$OUT_DIR/.temp/nuclei_gql.txt" -dr -duc 2>/dev/null || true
    
    if [ -s "$OUT_DIR/.temp/nuclei_gql.txt" ]; then
        cat "$OUT_DIR/.temp/nuclei_gql.txt" >> "$OUT_DIR/vulns/graphql.txt"
        finding_count=$((finding_count + $(wc -l < "$OUT_DIR/.temp/nuclei_gql.txt")))
    fi
    
    log_stat "GraphQL Security Findings" "$finding_count"
    log_success "GraphQL Inspector v2 completed."
}

