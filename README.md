# Privacy Pipeline: A CI Security Framework

## Overview

This project implements a CI pipeline that integrates automated security and privacy scanning into both push and pull request workflows using GitHub Actions.

The goal is to demonstrate how multiple security layers can be applied early in the development lifecycle (shift-left security) using only open-source tools.

---

## What the Pipeline Detects

The pipeline automatically scans code for:

- Exposed secrets  
- Code-level vulnerabilities  
- Dependency vulnerabilities  
- Privacy-sensitive data (PII)  

---

## Architecture

Each security domain is handled by a separate scanner:

1. Secret Scanning  
2. Static Application Security Testing (SAST)  
3. Software Composition Analysis (SCA)  
4. PII (Privacy) Scanning  

Each scanner runs independently in GitHub Actions and contributes to the overall security assessment of the codebase.

---

## Tools Used

| Tool                | Purpose                                      |
|---------------------|----------------------------------------------|
| Gitleaks            | Secret Scanning                              |
| CodeQL              | Static Application Security Testing (SAST)   |
| Trivy               | Software Composition Analysis (SCA)          |
| Custom PII Scanner  | PII (Privacy) Scanning                       |

---

## Why These Tools?

- All tools are free and open-source  
- Easy integration with GitHub Actions  
- Cover distinct and complementary risk areas  
- Support a modular and extensible pipeline design  

---

## Security Approach

This pipeline follows a **shift-left security** approach, where security and privacy checks are applied early in the development process.

Each scan acts as an automated control, helping prevent insecure or sensitive data from being merged into the main codebase.
