# 1. BASE: Ubuntu 24.04 (Python 3.12)
FROM ubuntu:24.04

LABEL maintainer="Franco Andino (darkne55)"
LABEL description="REDHAVEN 1.0.3"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:$PATH"
ENV GOPROXY=https://proxy.golang.org,direct
ENV GIT_TERMINAL_PROMPT=0

# 2. Dependencias Base del Sistema
RUN apt-get update && apt-get install -y \
    wget curl git build-essential \
    python3 python3-pip python3-venv jq \
    dnsutils nmap \
    libpcap-dev libssl-dev libffi-dev python3-dev \
    python3-setuptools python3-wheel \
    software-properties-common \
    default-jdk apksigner \
    unzip \
    parallel \
    libimage-exiftool-perl \
    fonts-liberation libu2f-udev xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# --- GOOGLE CHROME STABLE (SOLUCIÓN AL ERROR DE SNAP) ---
RUN wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
    apt-get update && \
    apt-get install -y ./google-chrome-stable_current_amd64.deb && \
    rm google-chrome-stable_current_amd64.deb

# Creamos el shim para que Gowitness lo encuentre
RUN echo '#!/bin/bash\n/usr/bin/google-chrome --no-sandbox --headless --disable-gpu "$@"' > /usr/bin/chromium-shim && \
    chmod +x /usr/bin/chromium-shim && \
    ln -sf /usr/bin/google-chrome /usr/bin/chromium-browser

# Instalación manual de Apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool && \
    wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# 3. Instalación de Go
RUN wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz && \
    rm go1.23.4.linux-amd64.tar.gz

# 4. Herramientas Go
RUN mkdir -p /usr/local/bin
RUN go install github.com/Emoe/kxss@latest && \
    ln -sf /root/go/bin/kxss /usr/local/bin/kxss

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    mv /root/go/bin/httpx /usr/local/bin/httpx-pd    
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest
RUN go install -v github.com/hahwul/dalfox/v2@latest
RUN go install -v github.com/visma-prodsec/confused@latest
RUN go install -v github.com/tomnomnom/waybackurls@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
RUN go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest && \
    ln -sf /root/go/bin/urlfinder /usr/local/bin/urlfinder
RUN go install -v github.com/tomnomnom/qsreplace@latest
RUN go install -v github.com/gwen001/github-subdomains@latest
RUN go install -v github.com/gwen001/gitlab-subdomains@latest
RUN go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest


# Creamos los enlaces simbólicos en un paso separado para evitar errores de sintaxis
RUN ln -sf /root/go/bin/* /usr/local/bin/

# Herramientas Pro
RUN go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# Advanced Security Tools
# Subzy - Subdomain takeover detection (detects dangling CNAMEs to S3, Azure, GitHub Pages)
RUN go install -v github.com/PentestPad/subzy@latest

RUN git clone --depth 1 https://github.com/devploit/nomore403 /tools/nomore403 && \
    cd /tools/nomore403 && \
    go build main.go && \
    mv main /usr/local/bin/nomore403 && \
    chmod +x /usr/local/bin/nomore403 && \
    chmod -R 755 /tools/nomore403


# 5. Binarios Directos
RUN wget -q https://github.com/sensepost/gowitness/releases/download/2.5.1/gowitness-2.5.1-linux-amd64 && \
    mv gowitness-2.5.1-linux-amd64 /usr/local/bin/gowitness && \
    chmod +x /usr/local/bin/gowitness && \
    wget -q https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz && \
    gunzip x86_64-linux-x8.gz && \
    mv x86_64-linux-x8 /usr/local/bin/x8 && \
    chmod +x /usr/local/bin/x8 && \
    wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.18.2_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks_8.18.2_linux_x64.tar.gz

# --- v1.0.3: TruffleHog for GitHub Deep Recon ---
RUN wget -q https://github.com/trufflesecurity/trufflehog/releases/download/v3.87.1/trufflehog_3.87.1_linux_amd64.tar.gz && \
    tar -xzf trufflehog_3.87.1_linux_amd64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm trufflehog_3.87.1_linux_amd64.tar.gz

# 5b. Feroxbuster (CORREGIDO: NOMBRE DEL ZIP EXACTO)
# El nombre correcto en releases es x86_64-linux-feroxbuster.zip
RUN wget -q https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -O ferox.zip && \
    unzip ferox.zip && \
    mv feroxbuster /usr/local/bin/feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm ferox.zip

# 6. Herramientas Python
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed \
    requests colorama pyyaml google-genai mobsfscan \
    pycryptodomex termcolor jsbeautifier urllib3 bs4
RUN pip3 install --no-cache-dir --break-system-packages uro dnsgen aiohttp websockets

# Advanced Analysis Tools
# BFAC - Backup File Artifact Checker (finds .bak, .old, config.php~)
RUN git clone --depth 1 https://github.com/mazen160/bfac.git /tools/bfac && \
    cd /tools/bfac && \
    pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
    chmod +x bfac && \
    ln -sf /tools/bfac/bfac /usr/local/bin/bfac

# apkleaks - APK secret extraction (complements mobsfscan)
RUN pip3 install --no-cache-dir --break-system-packages apkleaks

# 6b. Herramientas Simples
RUN git clone --depth 1 https://github.com/MrEmpy/Mantra.git /tools/Mantra && \
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /tools/LinkFinder && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /tools/jwt_tool

# 6c. Arjun & ParamSpider
RUN pip3 install --break-system-packages --ignore-installed git+https://github.com/s0md3v/Arjun.git && \
    git clone https://github.com/devanshbatham/ParamSpider /tools/ParamSpider && \
    cd /tools/ParamSpider && \
    pip3 install --break-system-packages .

# Wrappers de seguridad
RUN echo '#!/bin/bash\npython3 -m arjun "$@"' > /usr/local/bin/arjun && chmod +x /usr/local/bin/arjun

# 6d. Dirsearch
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /tools/dirsearch && \
    chmod +x /tools/dirsearch/dirsearch.py && \
    ln -sf /tools/dirsearch/dirsearch.py /usr/local/bin/dirsearch

# 6e. Intelligent Fuzzing Tools (Phase 2B)
# Commix (Command Injection)
RUN git clone --depth 1 https://github.com/commixproject/commix.git /tools/commix && \
    chmod +x /tools/commix/commix.py && \
    ln -sf /tools/commix/commix.py /usr/local/bin/commix

# DSSS (Damn Small SQLi Scanner)
RUN wget -q https://raw.githubusercontent.com/stamparm/DSSS/master/dsss.py -O /usr/local/bin/dsss && \
    chmod +x /usr/local/bin/dsss

# Tplmap (SSTI) - Using a maintained fork/version if possible, or standard
RUN git clone --depth 1 https://github.com/epinna/tplmap.git /tools/tplmap && \
    pip3 install --no-cache-dir --break-system-packages -r /tools/tplmap/requirements.txt || true && \
    chmod +x /tools/tplmap/tplmap.py && \
    ln -sf /tools/tplmap/tplmap.py /usr/local/bin/tplmap

# 7. Diccionarios & Wordlists
RUN mkdir -p /tools/SecLists /tools/PayloadsAllTheThings && \
    curl -fSL https://github.com/danielmiessler/SecLists/archive/master.tar.gz -o /tmp/seclists.tar.gz && \
    tar -xzf /tmp/seclists.tar.gz -C /tools/SecLists --strip-components=1 && \
    curl -fSL https://github.com/swisskyrepo/PayloadsAllTheThings/archive/master.tar.gz -o /tmp/payloads.tar.gz && \
    tar -xzf /tmp/payloads.tar.gz -C /tools/PayloadsAllTheThings --strip-components=1 && \
    rm /tmp/*.tar.gz

RUN mkdir -p /tools/Assetnote && \
    ln -s /tools/SecLists/Discovery/Web-Content/raft-medium-directories.txt /tools/Assetnote/best_directories.txt && \
    ln -s /tools/SecLists/Discovery/Web-Content/api/api-endpoints.txt /tools/Assetnote/best_api.txt && \
    ln -s /tools/SecLists/Discovery/Web-Content/web-all-content-extract.txt /tools/Assetnote/best_php.txt

RUN mkdir -p /resultados
RUN ln -s /tools/nomore403/payloads /resultados/payloads

# 8. Finalización
RUN nuclei -update-templates
RUN mkdir -p /resultados /tools /root/.config/subfinder /root/.config/nuclei

# Custom Nuclei Templates for Advanced Detection
COPY templates/custom-nuclei/ /root/nuclei-templates/custom/
RUN nuclei -validate -t /root/nuclei-templates/custom/ || true

COPY modules/correlator.py /usr/local/bin/correlator
COPY scanner.sh /usr/local/bin/scanner
COPY modules/ai_hunter.py /usr/local/bin/ai_hunter

# Phase 2B: Advanced Detection Scripts
COPY modules/race_cond.py /usr/local/bin/race_cond
COPY modules/ws_scanner.py /usr/local/bin/ws_scanner
COPY modules/blind_xss.py /usr/local/bin/blind_xss
COPY modules/postmessage_analyzer.py /usr/local/bin/postmessage_analyzer
COPY modules/twofa_bypass.py /usr/local/bin/twofa_bypass
COPY modules/swagger_discovery.py /usr/local/bin/swagger_discovery

# Phase 2C: Elite Security Testing
COPY modules/bola_bfla.py /usr/local/bin/bola_bfla
COPY modules/smuggler.py /usr/local/bin/smuggler
COPY modules/cors_tester.py /usr/local/bin/cors_tester
COPY modules/cache_poison.py /usr/local/bin/cache_poison

# Phase 2C Extension: Methodological Gaps
COPY modules/hunter_toolkit.py /usr/local/bin/hunter_toolkit

# v1.0.3: Critical Bug Bounty Features
COPY modules/cve_matcher.py /usr/local/bin/cve_matcher
COPY modules/s3_bruteforce.py /usr/local/bin/s3_bruteforce

RUN chmod +x /usr/local/bin/correlator /usr/local/bin/scanner /usr/local/bin/ai_hunter /usr/local/bin/race_cond /usr/local/bin/ws_scanner /usr/local/bin/blind_xss /usr/local/bin/postmessage_analyzer /usr/local/bin/twofa_bypass /usr/local/bin/swagger_discovery /usr/local/bin/bola_bfla /usr/local/bin/smuggler /usr/local/bin/cors_tester /usr/local/bin/cache_poison /usr/local/bin/hunter_toolkit /usr/local/bin/cve_matcher /usr/local/bin/s3_bruteforce

ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
WORKDIR /resultados
ENTRYPOINT ["scanner"]
