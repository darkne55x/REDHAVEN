#!/usr/bin/env python3
"""
DARKNE55 AI HUNTER V2.0 - GEMINI-POWERED BUG BOUNTY ASSISTANT
Enhanced with: JSON parsing, deduplication, PoC generation, cost tracking
"""

import os
import sys
import yaml
import json
import hashlib
from google import genai
from pathlib import Path
from typing import Dict, List, Set
from dataclasses import dataclass, asdict

# COLORES
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

CONFIG_FILE = "/data/provider-config.yaml"

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class VulnFinding:
    """Estructura para hallazgos normalizados"""
    vuln_type: str
    url: str
    param: str
    severity: str
    details: str
    raw_data: str
    fingerprint: str  # Hash para deduplicación
    
    def to_dict(self):
        return asdict(self)

@dataclass
class AnalysisStats:
    """Tracking de costos y métricas"""
    total_tokens_used: int = 0
    api_calls_made: int = 0
    duplicates_removed: int = 0
    findings_analyzed: int = 0
    true_positives: int = 0
    false_positives: int = 0
    estimated_cost_usd: float = 0.0

# ============================================================================
# CONFIGURACIÓN & CLIENTE
# ============================================================================

def load_config():
    """Carga configuración desde YAML"""
    if not os.path.exists(CONFIG_FILE):
        print(f"{Colors.RED}[!] Error: No se encontró {CONFIG_FILE}{Colors.RESET}")
        print(f"{Colors.YELLOW}Crea el archivo con tu API KEY de Gemini.{Colors.RESET}")
        sys.exit(1)
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
            return config.get('gemini', {})
    except Exception as e:
        print(f"{Colors.RED}[!] Error leyendo YAML: {str(e)}{Colors.RESET}")
        sys.exit(1)

def setup_gemini_client(config):
    """Inicializa cliente de Gemini"""
    api_key = config.get('api_key')
    if not api_key or api_key == "TU_CLAVE_API_AQUI":
        print(f"{Colors.RED}[!] Error: API Key no configurada en provider-config.yaml{Colors.RESET}")
        sys.exit(1)
    
    return genai.Client(api_key=api_key)

# ============================================================================
# PARSERS INTELIGENTES
# ============================================================================

def parse_nuclei_json(file_path: Path) -> List[VulnFinding]:
    """Parser para outputs JSON de Nuclei"""
    findings = []
    
    if not file_path.exists():
        return findings
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Extracción de datos críticos
                    vuln_type = data.get('info', {}).get('name', 'Unknown')
                    severity = data.get('info', {}).get('severity', 'info').upper()
                    url = data.get('host', data.get('matched-at', ''))
                    
                    # Generar fingerprint único
                    fingerprint_str = f"{vuln_type}{url}{severity}"
                    fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
                    
                    finding = VulnFinding(
                        vuln_type=vuln_type,
                        url=url,
                        param=data.get('extracted-results', [''])[0] if 'extracted-results' in data else '',
                        severity=severity,
                        details=json.dumps(data.get('info', {}), indent=2),
                        raw_data=json.dumps(data, indent=2),
                        fingerprint=fingerprint
                    )
                    
                    findings.append(finding)
                    
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error parseando {file_path.name}: {e}{Colors.RESET}")
    
    return findings

def parse_text_output(file_path: Path, vuln_type: str) -> List[VulnFinding]:
    """Parser para outputs de texto plano"""
    findings = []
    
    if not file_path.exists() or file_path.stat().st_size == 0:
        return findings
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if l.strip()]
        
        for line in lines:
            # Extraer URL base
            url = line.split()[0] if ' ' in line else line
            
            # Generar fingerprint
            fingerprint_str = f"{vuln_type}{url}{line}"
            fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
            
            finding = VulnFinding(
                vuln_type=vuln_type,
                url=url,
                param='',
                severity='MEDIUM',  # Default
                details=line,
                raw_data=line,
                fingerprint=fingerprint
            )
            
            findings.append(finding)
            
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error parseando {file_path.name}: {e}{Colors.RESET}")
    
    return findings

# ============================================================================
# DEDUPLICACIÓN
# ============================================================================

def deduplicate_findings(findings: List[VulnFinding]) -> tuple[List[VulnFinding], int]:
    """Elimina duplicados basándose en fingerprint"""
    seen: Set[str] = set()
    unique_findings = []
    duplicates = 0
    
    for finding in findings:
        if finding.fingerprint not in seen:
            seen.add(finding.fingerprint)
            unique_findings.append(finding)
        else:
            duplicates += 1
    
    return unique_findings, duplicates

# ============================================================================
# SCOPE CHECKING
# ============================================================================

def is_in_scope(url: str, scope_file: Path) -> bool:
    """Verifica si la URL está en scope (si existe archivo .scope)"""
    if not scope_file.exists():
        return True  # Si no hay scope definido, todo es válido
    
    try:
        with open(scope_file, 'r') as f:
            scope_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        for domain in scope_domains:
            if domain in url:
                return True
        
        return False
    except:
        return True  # En caso de error, asumir que está en scope

# ============================================================================
# ANÁLISIS CON GEMINI (MEJORADO)
# ============================================================================

def analyze_chunk_with_ai(
    client, 
    model_name: str, 
    vuln_type: str, 
    findings_chunk: List[VulnFinding],
    stats: AnalysisStats
) -> str:
    """Analiza un chunk de vulnerabilidades con Gemini"""
    
    # Preparar contexto
    findings_text = "\n\n".join([
        f"[{i+1}] URL: {f.url}\n    Type: {f.vuln_type}\n    Severity: {f.severity}\n    Details: {f.details[:300]}"
        for i, f in enumerate(findings_chunk)
    ])
    
    prompt = f"""
You are a SENIOR BUG BOUNTY HUNTER analyzing security findings for {vuln_type}.

OBJECTIVE: Filter false positives and assess real vulnerabilities.

FINDINGS TO ANALYZE:
{findings_text}

INSTRUCTIONS:
1. Identify TRUE POSITIVES vs FALSE POSITIVES
2. For each TRUE POSITIVE:
   - Assign Confidence Score (0-100)
   - Determine Business Impact (LOW/MEDIUM/HIGH/CRITICAL)
   - Suggest one-line remediation
   - Note if it can chain with other vulns

3. For FALSE POSITIVES, briefly explain why

OUTPUT FORMAT (Markdown):

### {vuln_type} Analysis

#### TRUE POSITIVES:
- **Finding #X**: [URL]
  - Confidence: [0-100]%
  - Impact: [CRITICAL/HIGH/MEDIUM/LOW]
  - Why Valid: [Brief explanation]
  - Chain Potential: [Yes/No - describe if yes]
  - Fix: [One-line remediation]

#### FALSE POSITIVES:
- **Finding #X**: [Brief reason for FP]

#### SUMMARY:
- True Positives: X
- False Positives: Y
- Highest Priority: [Finding #]
"""
    
    try:
        response = client.models.generate_content(
            model=model_name,
            contents=prompt
        )
        
        # Tracking de costos (Gemini 2.0 Flash pricing)
        # Input: ~$0.075 per 1M tokens, Output: ~$0.30 per 1M tokens
        estimated_input_tokens = len(prompt.split()) * 1.3  # Aproximación
        estimated_output_tokens = len(response.text.split()) * 1.3
        
        stats.total_tokens_used += int(estimated_input_tokens + estimated_output_tokens)
        stats.api_calls_made += 1
        
        # Costo estimado (muy aproximado)
        input_cost = (estimated_input_tokens / 1_000_000) * 0.075
        output_cost = (estimated_output_tokens / 1_000_000) * 0.30
        stats.estimated_cost_usd += (input_cost + output_cost)
        
        return response.text
        
    except Exception as e:
        return f"❌ Error consultando Gemini: {str(e)}"

# ============================================================================
# POC GENERATOR
# ============================================================================

def generate_poc(vuln_type: str, finding: VulnFinding) -> str:
    """Genera PoC básico según el tipo de vulnerabilidad"""
    
    poc_templates = {
        "SQL_Injection": f"""
```bash
# SQLi PoC for {finding.url}
curl -X POST "{finding.url}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "{finding.param}=1' OR '1'='1"
```
**Expected**: Database error or auth bypass
""",
        "IDOR": f"""
```bash
# IDOR PoC for {finding.url}
# 1. Login as User A, capture request with ID parameter
# 2. Change ID to User B's ID (increment/decrement)
curl -X GET "{finding.url}" \\
  -H "Cookie: session=USER_A_SESSION" \\
  -H "Authorization: Bearer USER_A_TOKEN"
# 3. Observe if User B's data is returned
```
""",
        "XSS": f"""
```bash
# XSS PoC for {finding.url}
curl -X GET "{finding.url}?{finding.param}=<script>alert(document.domain)</script>"
# Check response for unescaped script tag
```
""",
        "SSRF": f"""
```bash
# SSRF PoC for {finding.url}
# Use Burp Collaborator or interact.sh
curl -X POST "{finding.url}" \\
  -d "url=http://burp-collaborator-subdomain.com"
# Check for DNS/HTTP callback
```
""",
        "default": f"""
```bash
# Generic PoC for {vuln_type}
curl -v -X GET "{finding.url}"
# Manual verification required
```
"""
    }
    
    return poc_templates.get(vuln_type.replace(" ", "_"), poc_templates["default"])

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main(target_dir: str):
    print(f"{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║  AI-POWERED BUG BOUNTY HUNTER V2.0 (GEMINI INTEGRATION)  ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    # Setup
    config = load_config()
    client = setup_gemini_client(config)
    model_name = config.get('model', 'gemini-2.0-flash-exp')
    
    base_path = Path(target_dir)
    reports_dir = base_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Scope checking
    scope_file = base_path / ".scope.txt"
    
    # Stats tracking
    stats = AnalysisStats()
    
    # Mapeo COMPLETO de archivos críticos (FIXED syntax error)
    targets = {
        "SQL_Injection": base_path / "vulns" / "sqli_confirmed.txt",
        "High_Risk_IDOR": base_path / "vulns" / "idor_candidates.txt",
        "Sensitive_Secrets": base_path / "secrets" / "nuclei_secrets.txt",
        "XSS_Reflected": base_path / "vulns" / "xss.txt",
        "SSRF": base_path / "vulns" / "ssrf.txt",
        "403_Bypass_Success": base_path / "vulns" / "bypass_403.txt",
        "CRLF_Injection": base_path / "vulns" / "crlf.txt",
        "Open_Redirect": base_path / "vulns" / "open_redirect.txt",
        "Prototype_Pollution": base_path / "vulns" / "prototype_pollution.txt",
        "GraphQL": base_path / "vulns" / "graphql.txt",
        "OAuth_Misconfig": base_path / "vulns" / "oauth.txt",
        "JWT_Vulns": base_path / "vulns" / "jwt.txt",
        "CSRF": base_path / "vulns" / "csrf.txt",
        "Logic_Flaws": base_path / "vulns" / "logic.txt",
        "Subdomain_Takeover": base_path / "vulns" / "subdomain_takeover.txt",
    }
    
    final_report = f"""# 🎯 DARKNE55 AI SECURITY REPORT
**Generated by:** Gemini ({model_name})  
**Date:** {Path(target_dir).name}  
**Target:** {base_path.name}

---

"""
    
    all_findings: List[VulnFinding] = []
    
    # 1. CARGA Y PARSEO
    print(f"{Colors.CYAN}[*] Fase 1: Cargando y parseando hallazgos...{Colors.RESET}")
    for v_type, path in targets.items():
        if path.exists() and path.stat().st_size > 0:
            # Intentar parsear como JSON primero (Nuclei output)
            if path.suffix == '.json':
                findings = parse_nuclei_json(path)
            else:
                findings = parse_text_output(path, v_type)
            
            if findings:
                all_findings.extend(findings)
                print(f"  {Colors.GREEN}✓{Colors.RESET} {v_type}: {len(findings)} hallazgos cargados")
    
    if not all_findings:
        print(f"\n{Colors.YELLOW}[!] No se encontraron vulnerabilidades para analizar.{Colors.RESET}")
        return
    
    stats.findings_analyzed = len(all_findings)
    
    # 2. DEDUPLICACIÓN
    print(f"\n{Colors.CYAN}[*] Fase 2: Eliminando duplicados...{Colors.RESET}")
    unique_findings, duplicates = deduplicate_findings(all_findings)
    stats.duplicates_removed = duplicates
    print(f"  {Colors.GREEN}✓{Colors.RESET} Duplicados removidos: {duplicates}")
    print(f"  {Colors.GREEN}✓{Colors.RESET} Hallazgos únicos: {len(unique_findings)}")
    
    # 3. SCOPE FILTERING
    print(f"\n{Colors.CYAN}[*] Fase 3: Verificando scope...{Colors.RESET}")
    in_scope_findings = [f for f in unique_findings if is_in_scope(f.url, scope_file)]
    out_of_scope = len(unique_findings) - len(in_scope_findings)
    if out_of_scope > 0:
        print(f"  {Colors.YELLOW}⚠{Colors.RESET} Excluidos por scope: {out_of_scope}")
    print(f"  {Colors.GREEN}✓{Colors.RESET} En scope: {len(in_scope_findings)}")
    
    # 4. ANÁLISIS CON AI (CHUNKING INTELIGENTE)
    print(f"\n{Colors.CYAN}[*] Fase 4: Análisis con Gemini AI...{Colors.RESET}")
    
    # Agrupar por tipo de vulnerabilidad
    vuln_groups: Dict[str, List[VulnFinding]] = {}
    for finding in in_scope_findings:
        if finding.vuln_type not in vuln_groups:
            vuln_groups[finding.vuln_type] = []
        vuln_groups[finding.vuln_type].append(finding)
    
    # Analizar por chunks (máximo 10 hallazgos por llamada para no saturar)
    chunk_size = 10
    
    for v_type, findings in vuln_groups.items():
        print(f"\n  {Colors.BOLD}Analizando: {v_type}{Colors.RESET}")
        
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i+chunk_size]
            chunk_num = (i // chunk_size) + 1
            total_chunks = (len(findings) + chunk_size - 1) // chunk_size
            
            print(f"    Chunk {chunk_num}/{total_chunks} ({len(chunk)} items)... ", end='')
            
            analysis = analyze_chunk_with_ai(client, model_name, v_type, chunk, stats)
            
            final_report += f"\n## 🔍 {v_type} (Chunk {chunk_num}/{total_chunks})\n\n"
            final_report += analysis + "\n\n"
            
            # Generar PoCs para los primeros 3 hallazgos de cada tipo
            if i == 0:
                final_report += "### 🛠️ Proof of Concept Examples\n\n"
                for j, finding in enumerate(chunk[:3], 1):
                    poc = generate_poc(v_type, finding)
                    final_report += poc + "\n"
            
            final_report += "---\n\n"
            print(f"{Colors.GREEN}✓{Colors.RESET}")
    
    # 5. ESTADÍSTICAS FINALES
    final_report += f"""
---

## 📊 EXECUTION STATISTICS

| Metric | Value |
|--------|-------|
| Total Findings Scanned | {stats.findings_analyzed} |
| Duplicates Removed | {stats.duplicates_removed} |
| Unique Findings | {len(unique_findings)} |
| In-Scope Findings | {len(in_scope_findings)} |
| API Calls Made | {stats.api_calls_made} |
| Total Tokens Used | {stats.total_tokens_used:,} |
| **Estimated Cost** | **${stats.estimated_cost_usd:.4f} USD** |

---

## 💡 NEXT STEPS

1. **Validate High-Confidence Findings** - Manually verify each TRUE POSITIVE
2. **Create Chain Exploits** - Combine findings marked with "Chain Potential: Yes"
3. **Submit Reports** - Prioritize CRITICAL/HIGH severity items
4. **Monitor Scope Changes** - Update `.scope.txt` if target expands

---

*Generated by DARKNE55 AI Hunter V2.0 powered by Google Gemini*
"""
    
    # 6. GUARDAR REPORTE
    report_path = reports_dir / "ai_analysis_report.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(final_report)
    
    # 7. GUARDAR JSON ESTRUCTURADO
    json_data = {
        "metadata": {
            "target": base_path.name,
            "model_used": model_name,
            "scan_date": str(Path(target_dir).name)
        },
        "statistics": asdict(stats),
        "findings": [f.to_dict() for f in in_scope_findings]
    }
    
    json_path = reports_dir / "ai_analysis_data.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)
    
    # RESUMEN FINAL
    print(f"\n{Colors.GREEN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}║                  ANÁLISIS COMPLETADO                      ║{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    print(f"  📄 Reporte Markdown: {Colors.CYAN}{report_path}{Colors.RESET}")
    print(f"  📊 Datos JSON: {Colors.CYAN}{json_path}{Colors.RESET}")
    print(f"  💰 Costo estimado: {Colors.YELLOW}${stats.estimated_cost_usd:.4f} USD{Colors.RESET}")
    print(f"  🎯 Hallazgos analizados: {Colors.GREEN}{len(in_scope_findings)}{Colors.RESET}")
    print(f"  🔥 Llamadas a API: {Colors.CYAN}{stats.api_calls_made}{Colors.RESET}")
    print(f"  ⚡ Tokens usados: {Colors.CYAN}{stats.total_tokens_used:,}{Colors.RESET}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Uso: ai_hunter.py <directorio_target>{Colors.RESET}")
        print(f"{Colors.DIM}Ejemplo: ai_hunter.py /resultados/target.com{Colors.RESET}")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    if not os.path.isdir(target_dir):
        print(f"{Colors.RED}[!] Error: '{target_dir}' no es un directorio válido{Colors.RESET}")
        sys.exit(1)
    
    main(target_dir)
