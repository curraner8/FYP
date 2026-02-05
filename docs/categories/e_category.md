These vulnerabilities cannot be directly statically analysed, such as third-party dependencies or runtime behaviours.
This category identifies *risk indicators* related to dependency management, versioning, and integrity.
The findings are advisory and will be warnings to check for confirmation.

---

### 1. Vulnerable Dependencies (Known CVEs)

| **Danger**                             |
| -------------------------------------- |
| Exploitable third-party libraries.     |
| *Remote code execution, data breaches* |

**Detection (Partial):**
- Parse dependency manifests:
	- `package.json`
	- `requirements.txt`
	- `pom.xml`
- Potentially compare dependency names and versions against a CVE database.

**Why This Is Partial:**
- Requires external vulnerability intelligence.
- Version resolution can be complex.

**Remedy:**
- Upgrade affected dependencies.
- Use dependency scanning tools.

| **Security Score:** | Critical (-30)                                |
| ------------------- | --------------------------------------------- |
| **Why:**            | High-impact exploits outside application code |

---

### 2. Obsolete or Outdated Dependencies

| **Danger**                                   |
| -------------------------------------------- |
| Use of unsupported or end-of-life libraries. |
| *Unpatched vulnerabilities*                  |

**Detection (Partial):**
- Flag:
	- Very old version numbers
	- No updates for extended periods
```
"[a-zA-Z0-9_-]+":\s*"0\.[0-9]+\."
```

**Why This Works:**
- Stagnant versioning strongly correlates with unpatched flaws.

**Remedy:**
- Upgrade to maintained versions.
- Replace abandoned libraries.

| **Security Score:** | High (-20)                         |
| ------------------- | ---------------------------------- |
| **Why:**            | Increased attack surface over time |

---

### 3. Missing Dependency Lockfiles

| **Danger**                    |
| ----------------------------- |
| Non-heuristic builds          |
| *Supply-chain poisoning risk* |

**Detection:**
- Detect absence of:
	- `package-lock.json`
	- `yarn.lock`
	- `poetry.lock`
	- `pipfile.lock`

**Why This Works:**
- Without lockfiles, dependency versions can change silently.

**Remedy:**
- Commit lockfiles.
- Enforce reproducible builds.

| **Security Score:** | Medium (-15)                |
| ------------------- | --------------------------- |
| **Why:**            | Indirect but realistic risk |

---

### 4. Unmaintained or Unknown Dependencies

| **Danger**                                 |
| ------------------------------------------ |
| Reliance on abandoned or obscure packages. |
| *Hidden vulnerabilities*                   |

**Detection (Partial):**
- Heuristics:
	- Very low version numbers.
	- No lockfile + obscure package names.
	- Known risky packages list (documented only).

**Why This Is Partial:**
- Maintenance status requires external metadata.

**Remedy:**
- Prefer well-maintained, widely used libraries.
- Audit critical dependencies manually.

| **Security Score:** | Medium (-15)             |
| ------------------- | ------------------------ |
| **Why:**            | Reduced patch likelihood |

---

### 5. Downloaded Code Without Integrity Checks

| **Danger**                            |
| ------------------------------------- |
| Tampered or malicious code execution. |
| *Supply-chain compromise*             |

**Detection (Partial):**
```
curl\s+.*\|\s*(bash|sh)
```

**Why This Works:**
- Piping remote code directly into interpreters is a known risky pattern.

**Remedy:**
- Verify checksums or signatures.
- Vendor dependencies securely.

| **Security Score:** | Critical (-30)         |
| ------------------- | ---------------------- |
| **Why:**            | Direct compromise risk |

---
Findings should be clearly labelled as advisory.
