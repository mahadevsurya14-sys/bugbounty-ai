# 🛡️ MAHADU — BugBounty-AI

**AI-Assisted Bug Bounty Recon & Security Research Platform**

Created by **Mahadev Suryavanshi (MAHADU)**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-25%20Passing-brightgreen?style=flat-square)
![Version](https://img.shields.io/badge/Version-0.1.0-cyan?style=flat-square)

---

```
███╗   ███╗ █████╗ ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗
████╗ ████║██╔══██╗██║  ██║██╔══██╗██╔══██╗██║   ██║
██╔████╔██║███████║███████║███████║██║  ██║██║   ██║
██║╚██╔╝██║██╔══██║██╔══██║██╔══██║██║  ██║██║   ██║
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██║██████╔╝╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝

             MAHADU • BugBounty-AI
  Recon • Attack Surface • OWASP • AI Analysis • Evidence • Reporting
```

> **For authorized security research, owned systems, labs, and explicitly in-scope bug bounty programs only.**

---

## Overview

BugBounty-AI is a production-quality, modular cybersecurity research platform designed exclusively for authorized penetration testing, security labs, CTF environments, and authorized bug bounty programs.

The platform enforces a strict workflow:
```
Scope → Recon → Attack Surface → Hypothesis → Validation → Evidence → Human Review → Report
```

Every action passes through a mandatory authorization pipeline:
```
TARGET → SCOPE CHECK → EXCLUSION CHECK → POLICY CHECK → RATE LIMIT CHECK → TEST AUTHORIZATION CHECK → EXECUTION
```

If any check fails, the action is **immediately blocked** and recorded in an immutable audit trail.

---

## Key Features

- **Mandatory Scope & Authorization Engine** — strict wildcard domain matching, CIDR subnet validation, path/parameter exclusion lists, and prohibited test category enforcement.
- **Safe CommandRunner** — all external tools are executed via secure subprocess argument arrays (`shell=False`), with binary allowlists, timeout enforcement, and `--dry-run` simulation.
- **Security Redaction Layer** — automatically masks passwords, Bearer tokens, JWTs, API keys, and URL-embedded credentials in logs, evidence, and reports.
- **Multi-Tier Rate Limiting** — token-bucket rate limiter with requests/second, requests/minute, concurrency semaphores, per-target quotas, and target cooldowns.
- **OWASP Top 10:2025 Test Registry** — modular test plugin architecture mapped to OWASP 2025 categories and CWEs.
- **Immutable Audit Trail** — dual persistence to append-only JSONL log and SQLite database.
- **AI Engine Architecture** — clean interfaces for local rule-based analysis, with plug-in support for OpenAI, Gemini, and local LLM providers. Zero remote dependency for core operation.
- **Quality-Controlled Reporting** — generates verifiable Markdown and JSON reports with mandatory evidence linkage and human review gates.

---

## Installation

### Prerequisites
- Python 3.10+
- Linux / macOS / Kali Linux
- SQLite 3

### Setup
```bash
# Clone repository
git clone <repo-url>
cd tool

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install BugBounty-AI
pip install -e .

# Initialize workspace
bugbounty init
```

---

## Usage

### Register a Program
```bash
bugbounty program create \
  --id "example_prog" \
  --name "Example Bounty Program" \
  --domain "*.example.com" \
  --exclude-domain "internal.example.com" \
  --rps 2.0
```

### View Scope & Validate Targets
```bash
bugbounty scope show --program example_prog
bugbounty scope validate --program example_prog --target "api.example.com"
bugbounty scope validate --program example_prog --target "unauthorized.org"
```

### Import Program from YAML
```bash
bugbounty program import --file config/program.example.yaml
bugbounty program show --program example_bounty
```

### OWASP Top 10:2025 Categories
```bash
bugbounty owasp list
```

### View Audit Trail
```bash
bugbounty audit show --limit 20
```

### Safe Localhost Lab Demo
```bash
bugbounty lab demo
```

### About & Version
```bash
bugbounty about
bugbounty version
```

---

## Project Structure

```
bugbounty-ai/
├── app/
│   ├── core/
│   │   ├── banner.py           # MAHADU branding & banner module
│   │   ├── audit.py            # Immutable JSONL & database audit logger
│   │   ├── command_runner.py   # Safe subprocess execution & allowlist
│   │   ├── config.py           # Pydantic schemas & YAML loader
│   │   ├── enums.py            # Operating modes, scope statuses, OWASP 2025
│   │   ├── exceptions.py       # ScopeViolationError, RateLimitExceededError
│   │   ├── rate_limiter.py     # Token-bucket rate limiter & concurrency guard
│   │   └── redactor.py         # Regex secret & credential masking
│   ├── scope/                  # ScopeEngine, normalizer, importer
│   ├── database/               # SQLAlchemy 2.0 ORM schemas & sessions
│   ├── cli/                    # Click & Rich CLI interface
│   ├── scanners/               # External tool adapters (httpx, nmap, etc.)
│   ├── plugins/                # Extensible plugin architecture
│   ├── owasp/                  # OWASP Top 10:2025 test registry
│   ├── ai/                     # AI agent interfaces & hallucination guard
│   ├── evidence/               # Evidence collector & HTTP differential
│   ├── findings/               # Finding lifecycle state machine
│   └── reports/                # Report generator & quality control
├── config/                     # Program YAML configurations & lab profiles
├── tests/                      # Automated test suite
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

---

## Running Tests

```bash
pytest -v
```

---

## Author

**Mahadev Suryavanshi (MAHADU)**

Cybersecurity & Security Research

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>MAHADU // BugBounty-AI</strong><br>
  <em>Security Research • Recon • Web Application Security</em>
</p>
