## v1.2.0 - The Modular Evolution (Stability & Performance)

### Framework Modularity

- **Monolith Decomposition**: Ported 4000+ lines into 28 independent bash modules.
- **Improved Isolation**: Modules now run in their own scope, preventing environment contamination.
- **Dependency Guards**: Added `check_dependency` logic to all asynchronous handlers to prevent redundant executions.

### Reliability Fixes

- **Subshell Context Persistence**: Fixed a major bug where finding counts were lost in piped subshells for Logic, BOLA, and OAuth scans.
- **Directory Context Safety**: Protected orchestrator workspace by wrapping tool-specific `cd` operations (like `nomore403`) in subshells.
- **Strict POSIX Compatibility**: Removed non-standard shell extensions (like `\d` or GNU sed `\U`) to ensure reliability across generic Linux environments.

### Optimized Tooling

- **Parallel Probing**: Integrated `parallel` execution for high-volume SSRF and CORS scanning.
- **Single-Pass Intelligence**: Optimized URL scoring (ai_hunter) with `awk` for nearly instant processing on large datasets.

## Últimas Actualizaciones (Phase 2B - Intelligent Fuzzing)

### Herramientas de Fuzzing Inteligente

- **Commix**: Detección y explotación automática de Command Injection.
- **DSSS (Damn Small SQLi Scanner)**: Scanner ligero y potente para SQL Injection.
- **Tplmap**: Detección y explotación de Server-Side Template Injection (SSTI).

### Herramientas de Reconocimiento Avanzado (Go)

- **github-subdomains**: Busca subdominios en GitHub (necesita tokens).
- **gitlab-subdomains**: Busca subdominios en GitLab.
- **jsluice**: Análisis estático avanzado de Javascript (BishopFox).

### Scripts Personalizados (ELITE)

- **race_cond.py**: Scanner asíncrono de Race Conditions (usa `aiohttp`).
- **ws_scanner.py**: Descubridor y fuzzer de WebSockets (usa `websockets`).
