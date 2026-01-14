# Web Application Vulnerability Detector with Fix Recommendations

## Overview
This project aims to analyse web application source code and identify **security vulnerabilities before deployment** and provides **remediation suggestions** to help developers fix issues early in the development process.

This tool is designed to operate on source code only and does not detect live attacks or monitor runtime behaviour.

This project is being developed as a **Final Year Project** (*UCC Computer Science*).

---

## The Goals of this Project
- Scan uploaded source code files
- Detect common web application vulnerabilities
- Assign a security score and grade
- Highlight vulnerable lines of code
- Suggest fixes for each finding
- Will be designed to run locally or in CI/CD pipelines

---

## Architecture

### Backend
- Language: **Go**
- Responsibilities:
  - Static code scanning
  - Rule evaluation
  - Vulnerability aggregation
  - Security score calculation
  - Suggest fixes for each finding
  - Will be designed to run locally or in CI/CD pipelines

### Frontend
- Framework: **Vue**
- Responsibilities:
  - Code/file input
  - Display scan results
  - Show security score and findings
- **Note:** Frontend is currently a placeholder UI

---

## Security Scoring
- Base score: **100**
- Penalties applied per finding:
  - **Critical**: -30
  - **Medium/High**: -20
  - **Low:** -10
  
- File output includes:
  - Numerical score
  - Letter grade (A-D)
  - Per-file vulnerability breakdown
  
---

## Current Status
- Basic backend scanner implemented
- Prototype rule set in place
- Simple scoring system implemented
- Basic frontend UI available (placeholder)

---

## To-Do

### Core Scanner
- Apply **all detection techniques** for each listed vulnerability
- Improve detection accuracy and reduce false positives
- Expand rule set and language coverage

### Remedies
- Add **simple, offline remdiation suggestions** for every vulnerability
- Ensure offline mode works without external services

### AI Integration (Online Mode)
- Integrate an **LLM API** for:
  - In-depth fix explanations
  - Context-aware remediation advice
  - Improved developer guidance
  
### CI/CD Deployment
- Convert backend scanner into a **GitHub Action**
- Enable scanning on pull requests and commits
- Fail CI based on security score thresholds

### Frontend
- Replace placeholder UI
- Improve usability and layout
- Add clear vulnerability visualisation and summaries

---

## Limitations
- Static analysis cannot detect al vulnerabilities
- Some findings will be heuristic-based
- Business logic and design flaws are out of scope
- The tool does not detect live attacks
