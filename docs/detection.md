### **Detection Classes**

| Class                         | Can I detect it? | How?                   |
| ----------------------------- | ---------------- | ---------------------- |
| **A. Direct Static Pattern**  | ==Yes==          | Regex/AST              |
| **B. API Misuse**             | ==Yes==          | Function name matching |
| **C. Configuration / Flags**  | ==Yes==          | Config scanning        |
| **D. Heuristic / Smell**      | *Partial*        | Risk indicators        |
| **E. Dependency / External**  | *Partial*        | Manifest + CVE DB      |
| **F. Design / Runtime Logic** | No               | Document only          |

#### **Class A - Direct Static Pattern Detection**
==Covers:==
- SQL Injection
- XSS (all variants)
- Command Injection
- LDAP Injection
- XPath Injection
- CRLF Injection
- Eval Injection
- Static Code Injection
- OS Command Injection
- PHP RFI
- Path Traversal
- Hard-coded credentials
- Sensitive info in comments
- Debug code left enabled
- Logging secrets
- Stack traces
- Null pointer dereferences (limited)

==Example detection:==
```
(SELECT|INSERT|UPDATE|DELETE).*\\+.*(input|request|params)
```
==Remedy:==
- Parameterized queries
- Escaping/encoding
- Safe APIs
==Severity:==
**Critical (-30)**

#### **Class B - API Misuse Detection**
Detect *dangerous functions*, not intent.
==Covers:==
- `eval()`
- `exec()`, `system()`, `popen()`
- `pickle.loads`
- `ObjectInputStream`
- `yaml.load`
- `subprocess.call(shell=True)`
- Weak crypto APIs (`md5`, `sha1`)
- Insecure PRNG (`Math.random`)
- XML parsers without secure flags
==Example:==
```
(eval|exec|system|pickle.loads|ObjectInputStream)
```
==Remedy:==
- Safe alternatives
- Disable dangerous flags
==Severity:==
**High-Critical (-20 to -30)**

False positives possible

#### **Class C - Configuration/Header/Flag Issues**
These are *very strong for SAST*.
==Covers:==
- Debug mode enabled
- Missing HTTPS
- Cookies missing `Secure`, `HttpOnly`, `SameSite`
- Directory listing
- Error pages exposing data
- Passwords in config files
- Insecure environment variables
==Example:==
```
Set-Cookie:(?!.*HttpOnly)(?!.*Secure)
```
==Remedy:==
- Harden configuration
- Secure defaults
==Severity:==
**Medium-High (-20)**

#### **Class D - Heuristic/Smell Detection**
These *can't be proven*, but *can be warned about*.
==Covers:==
- Missing authorization
- IDOR
- Forced browsing
- CSRF
- Open Redirect
- SSRF
- Missing authentication on endpoints
- Direct use of user IDs in queries
- Client-side enforcement of security
- GET request with sensitive data
==Example (heuristic):==
```
WHERE\\s+id\\s*=\\s*(request|params|user)
```
==UI Should Say:==
*Potential issue - manual view required/dismiss*
==Severity:==
**High (-20)**

This is the industry standard.

#### **Class E - Dependency/Supply Chain**
Static code *cannot* fully detect this.
==Covers:==
- Vulnerable dependencies
- Obsolete libraries
- Unmaintained components
- Downloaded code without integrity checks
==Possible Approach:==
- Parse `package.json`, `requirements.txt`
- Flag:
	- No lockfile
	- Very old version
	- Known risky packages
==Remedy:==
- Suggest checks and upgrades
==Severity:==
**Critical (-30)**

Document these, but do not fully implement.

#### **Class F - Design/Runtime/Logic**
These *cannot be detected statically*.
==Covers:==
- Insecure design
- Race conditions
- Business logic flaws
- Privilege escalation logic
- Trust boundary violations
- Workflow enforcement
- Authentication correctness
- Authorization correctness
- Session fixation correctness
- Failing open
- Excessive attack surface
- UI misrepresentation
- Confused deputy
- Improper compartmentalization
==What To Do:==
- Acknowledge these weaknesses and warn user.

### **Vulnerability Mapping:**

| OWASP Category                | Covered?    | How?      |
| ----------------------------- | ----------- | --------- |
| **Injection**                 | ==Yes==     | Class A+B |
| **Cryptographic Failures**    | *Partially* | Class B+C |
| **Security Misconfiguration** | ==Yes==     | Class C   |
| **Broken Access Control**     | *Partially* | Class D   |
| **Authentication Failures**   | *Partially* | Class D   |
| **Software Supply Chain**     | *Partially* | Class E   |
| **Integrity Failures**        | *Partially* | Class B+E |
| **Logging and Alerting**      | ==Yes==     | Class A+C |
| **Exceptional Conditions**    | ==Yes==     | Class A   |
| **Insecure Design**           | No          | Class F   |
