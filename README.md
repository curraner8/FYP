# Web Application Vulnerability Detector with Fix Recommendations

## Overview
This is a high-speed tool to analyse web application source code and identify **security vulnerabilities before deployment** while providing **remediation suggestions** to help developers fix issues early in the development process.

This tool is designed to operate on source code only and does not detect live attacks or monitor runtime behaviour. The tool should be used to create awareness for developers in the industry, and findings should be used as guidance.

The tool's main goal is to be performed as a **GitHub Action** when a Pull Request is made, however there is a *local web application sandbox* version available.

It bridges the gap between static analysis and develoepr remediation, providing a **Security Grade** (A-F) and implements LLM suggestions for context-aware code fixes.

This project is being developed as a **Final Year Project** (*UCC Computer Science*).

---

## Key Features and Goals
- **Class A-F Framework:** Categorizes findings from deterministic patterns, to supply chain risks, to design logic.
- **Supply Chain Security:** Automatically parses `requirements.txt` and queries the **Google OSV Database** for known vulnerabilities.
- **AI-Driven Remediation:** Integrated with **Groq (Llama 3)** to provide instant, context-aware secure code alternatives.
- **High Speed:** Quick scans prevent bottlenecks in the CI/CD pipeline, which is extremely important during rapid development.
- **GitHub Action:** Automated security grading directly within your Pull Requests.

---

## Architecture

### Backend (Go)
- **Engine:** Parallel file-system traversal using Goroutines.
- **Rules:** Modular `Detector` interface for multi-language support (Java, Go, Python, JS).
- **Scoring:** Dynamic algorithm with diminishing penalties to prevent alert fatigue.

### Frontend (Vue/Quasar)
- **Sandbox:** A web-based text input / file uploader for isolated code testing.
- **Visualization:** Interactive results showing score breakdown and grade.

---

## Security Scoring
- **Base Score:** 100
- **Penalty Weights:**
  - **Critical (-30):** Direct, provable exploits (SQLi, Eval).
  - **High (-20):** Dangerous API misuse or major misconfigurations.
  - **Medium (-10):** Heuristic findings and known CVE's.
  - **Low (-5):** Security hygiene (Debug code, sensitive comments).
- **Grading:** A (90-100), B (80-89), C (65-79), D (50-64), E (30-49), F (<30)
  
---

## Installation and Setup

### Local Sandbox
1. `cd cmd/server` and `go run main.go`
2. `cd frontend` and `npm install` and `quasar dev`

### GitHub Action Integration
1. Add `GROQ_API_KEY` to your repository secrets (get a free key at [console.groq.com](https://console.groq.com)).
2. Add the scanner to your workflow: `.github/workflows/security-scan.yml`

##### Recommended Workflow File for Best Output:
```
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run vulnerability scan
        id: scan
        uses: curraner8/FYP@main
        with:
          scan-path: "."
          fail-on-grade: "C"
          groq-api-key: ${{ secrets.GROQ_API_KEY }}

      - name: Post PR comment
        if: always() && github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const score = '${{ steps.scan.outputs.score }}';
            const grade = '${{ steps.scan.outputs.grade }}';
            const filesWithIssues = '${{ steps.scan.outputs.files_with_issues }}';
            const critical = '${{ steps.scan.outputs.critical }}';
            const high = '${{ steps.scan.outputs.high }}';
            const medium = '${{ steps.scan.outputs.medium }}';
            const low = '${{ steps.scan.outputs.low }}';
            const passed = ['A', 'B'].includes(grade);
            const status = passed ? '-->PASSED<--' : '-->FAILED<--';

            const body = [
              `## Security Scan Results`,
              ``,
              `| Status | Score | Grade |`,
              `|--------|-------|-------|`,
              `| ${status} | ${score}/100 | ${grade} |`,
              ``,
              `### Score Breakdown`,
              ``,
              `| Critical | High | Medium | Low |`,
              `|----------|------|--------|-----|`,
              `| ${Math.abs(critical)}pts | ${Math.abs(high)}pts | ${Math.abs(medium)}pts | ${Math.abs(low)}pts |`,
              ``,
              `## Remember to Check Action Logs for In-Depth Explanation and Fix Recommendations`
            ].join('\n');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

---

## Limitations
- **Trust Boundary:** Static Analysis cannot detect runtime-only flaws (Class F).
- **Heuristics:** Some findings require manual review to confirm intent.
- **Scope:** Focuses on code-level flaws, not live environment attacks.
