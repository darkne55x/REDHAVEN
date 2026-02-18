# REDHAVEN v1.2.2 - Intelligent Offensive Framework

![Version](https://img.shields.io/badge/version-1.2.2-red?style=for-the-badge)
![License](https://img.shields.io/badge/license-GPLv3-green?style=for-the-badge)
![Status](https://img.shields.io/badge/status-Toolchain_Update_Edition-black?style=for-the-badge)

> **The Modular Evolution: 16 Elite Upgrades & Independent Module Engine.**

---

## 🚀 Getting Started

### 1. Installation

Clone the repository:

```bash
git clone https://github.com/darkne55/REDHAVEN.git
cd REDHAVEN
```

### 2. Build or Update

Build the Docker container (this installs all tools and updates templates):

```bash
docker build -t darkne55-redhaven:latest .
```

> **Pro Tip**: Use the **[98] Update Toolchain** menu option inside the tool to refresh everything later.

### 3. Launch

Run the guided wizard:

```bash
./start.sh
```

Follow the interactive steps to target a domain and select a mission.

---

## 🛡️ v1.2.2: Toolchain & Stability Update

Version 1.2.2 introduces self-awareness and easier maintenance:

- **Auto-Update Check**: Alerts you if a new framework version is available.
- **Toolchain Manager**: New menu option to rebuild your environment with fresh tools and signatures.
- **Documentation Overhaul**: Streamlined guides for faster onboarding.

### ⚡ Key Features

- **Smart Caching**: Intelligent dependency checks prevent redundant re-scans (Amass, Subfinder).
- **Parallel Execution**: Rewrote core engines (SSRF) to use `parallel` for 20x speed gains.
- **Single-Pass Analysis**: Optimized Intelligence scoring from expensive sequential loops to single-pass `awk` processing.
- **Subshell Bug Resolution**: Fixed critical bugs in Logic, BOLA, Rate Limit, and OAuth modules.

---

## 📜 License

Educational and authorized bug bounty use only. Respect the target's scope and legal requirements.

---

## 🏆 Special Thanks & Acknowledgments

The development of REDHAVEN is supported by a global community of security researchers and developers.

- **[Nelux1](https://github.com/Nelux1)**: To contributions and advanced reconnaissance integration (thanks Mark for your help!).
- **[darkne55](https://github.com/darkne55)**: Project lead and module orchestration.
- **[Community Contributors]**: To all the hackers and bug bounty hunters providing feedback and testing on the front lines.

**Ready to find critical vulnerabilities? Launch REDHAVEN v1.2.2 now.**
