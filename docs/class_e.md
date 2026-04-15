# Class E

---

### E1. Unpinned Dependency

Specifying a library name without a specific version is dangerous because a future update to that library could break the code or a compromised version could be automatically installed.

**Detection Logic:**
```
func checkPyPI(class, content string) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "==") {
```

- The code parses `requirements.txt` line by line, checking for the absence of the `==` operator. If a dependency is listed without an exact version, it flags it as a risk.

---

### E2. Known Vulnerability / CVE

Using a specific version of a library that has a known documented security flaw.

**Detection Logic:**
- When the detector finds a pinned dependency, it extracts the name and version and sends a POST request to the OSV API.
	- **OSV Query:** Asks the database to check if this version has any recorded vulnerabilities.
	- **Results:** If the API returns a list of vulnerability IDs, the detector groups them and flags the line.
