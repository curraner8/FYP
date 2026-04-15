## Running The Scanner

This tool is a multi-language security scanner that uses a Class A-F framework to detect vulnerabilities and suggest fixes (LLM-driven fixes optional). This is an informative tool that helps to make developers aware of vulnerabilities and how to remediate them.

**Languages Supported:** Go, Java, JavaScript, Python, (and requirements.txt files)

---

### 1. GitHub Action Integration
This allows you to automatically scan on every pull request. You can make a test repo to try it out by making new branches and creating pull requests.

#### **Step 1: Configure Groq LLM API (Optional but recommended)**
To receive AI-powered fix suggestions, you need a Groq API key:
1. Go to [console.groq.com](http://console.groq.com) and create a free account
2. Generate a free API key
3. In your GitHub repository, go to Settings > Secrets and Variables > Actions
4. Create a new repository secret named `GROQ_API_KEY` and paste your key

#### **Step 2: Create the Workflow File**
In your repository, create a folder structure `.github/workflows` and create a file named `security-scan.yml` (or whatever you want to name it). I recommend using this structure to get the best output:

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
- `fail-on-grade` : can be changed to whatever grade you want (this doesn’t prevent merging as this is an informative tool to help developers, but does fail the scan and outputs “FAIL” in the GitHub comment).
- The **script** above is for the GitHub comment to be formatted nicely, but developers can change it if they want it to look different.

---

### 2. Alternative: The Sandbox
If you don’t want to set up a test repo and configure the tool like above, you can use the local sandbox UI which uses the same backend engine.

**Prerequisites:**
- Go (v1.25.4)
- Node.js (v20 or higher)
- `npm install -g @quasar/cli`

#### **Quick Start**
1. Clone the repository
```
git clone [https://github.com/curraner8/FYP.git](https://github.com/curraner8/FYP.git)

cd FYP
```

2. Optional: Set up LLM API Key for AI-powered fix suggestions
```
$env:GROQ_API_KEY="yourkeyhere"
```

3. Start the backend
```
cd cmd/server
go run main.go
```

4. In a new terminal window, start the frontend
```
cd frontend
quasar dev
```

The web interface should then pop up in your browser.

---

### Observing you results
The detection strategy is split into an A-F classification:

| Class | Name                   | Detection Approach                                                                                                             |
| ----- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| A     | Direct Static Patterns | Sink-source regex matching: requires both dangerous function and user input                                                    |
| B     | API Misuse             | Flags dangerous API calls regardless of input source                                                                           |
| C     | Configuration Issues   | Hybrid approach: direct pattern matching for config values + absence detection for missing security controls (locate + verify) |
| D     | Heuristic Detection    | Pattern matching with context window analysis. Identifies suspicious patterns that cannot be definitely proven                 |
| E     | Supply Chain Security  | External API queries to Google OSV database: parses requirements.txt for pinned dependencies                                   |
| F     | Design/Runtime Logic   | Simple keyword matching: informational only (no impact on score)                                                               |

The scanner starts with a base score of 100 and applies penalties based on findings. The final score determines your security grade (A-F).

Weights are applied to each vulnerability penalty depending on confidence level, multiple detections of the same vulnerability, and the class they belong to, and severity caps are implemented. This is an attempt to prevent alert fatigue.

---

### Important Notes
The scanner does not use LLM calls for detection. This is because speed was prioritized for this project, and an LLM API call for each detection takes too much time.

Failed scans do not block Pull Request merges. This is because the scanner is designed as an informative tool, false positives are possible and overall context is missing.
