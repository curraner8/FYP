These vulnerabilities come from *unsafe application configuration, insecure defaults*, or *missing security flags*. They are explicitly declared in code/config files, making them ideal for static analysis.

---

### 1. Debug Mode Enabled

| **Danger**                                         |
| -------------------------------------------------- |
| Exposes stack traces, internal logic, and secrets. |
| *Information disclosure*                           |

**Detection Technique:**
```
(DEBUG\s*=\s*True|debug\s*=\s*true|app\.debug\s*=\s*True)
```

**Why This Works:**
- Debug flags are explicitly defined.
- No runtime behaviour analysis required.

**Vulnerable Example:**
```
app.debug = True
```

**Remedy:**
```
app.debug = False
```

| **Why the Remedy Works**                     |
| -------------------------------------------- |
| Prevents verbose error output in production. |

| **Security Score:** | High (-20)             |
| ------------------- | ---------------------- |
| **Why:**            | Exposes internal state |

---

### 2. Missing HTTPS Enforcement

| **Danger**                                     |
| ---------------------------------------------- |
| Data transmitted in plaintext.                 |
| *Session hijacking, Man In The Middle Attacks* |

**Detection Technique:**
```
(http://|ssl\s*=\s*False)
```

**Why This Works:**
- The protocol usage is statically visible, and HTTPS enforcement is declarative.

**Vulnerable Example:**
```
fetch("http://example.com/api")
```

**Remedy:**
- Enforce HTTPS.
- Redirect HTTP -> HTTPS.

| **Security Score:** | High (-20)               |
| ------------------- | ------------------------ |
| **Why:**            | Credential exposure risk |

---

### 3. Cookies Missing Security Flags

| **Danger**                                           |
| ---------------------------------------------------- |
| Cookies accessible via JavaScript or sent over HTTP. |
| *Session theft*                                      |

**Detection Technique:**
```
Set-Cookie:(?!.*HttpOnly)(?!.*Secure)
```

**Why This Works:**
- Cookie flags are explicitly defined in headers.

**Vulnerable Example:**
```
Set-Cookie: session=abc123
```

**Remedy:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict
```

| **Security Score:** | High (-20)         |
| ------------------- | ------------------ |
| **Why:**            | Session compromise |

---

### 4. Directory Listing Enabled

| **Danger**                                |
| ----------------------------------------- |
| Exposure of internal files and structure. |
| *Information leakage*                     |

**Detection Technique:**
```
Options\s+Indexes
```

**Why This Works:**
- Directory listing is explicitly enabled via config.

**Vulnerable Example:**
```
Options Indexes
```

**Remedy:**
```
Options -Indexes
```

| **Security Score:** | Medium (-15)       |
| ------------------- | ------------------ |
| **Why:**            | Reconnaissance aid |

---

### 5. Error Pages Exposing Stack Traces

| **Danger**                                   |
| -------------------------------------------- |
| Reveals file paths, code structure, secrets. |
| *Targeted attacks*                           |

**Detection Techniques:**
```
(stacktrace|Traceback|Exception in thread)
```

**Why This Works:**
- Stack trace keywords are explicit and recognizable.

**Vulnerable Example:**
```
Traceback (most recent call last):
```

**Remedy:**
- Disable detailed errors.
- Use generic error pages.

| **Security Score:** | Medium (-15)           |
| ------------------- | ---------------------- |
| **Why:**            | Information disclosure |

---

### 6. Passwords in Configuration Files

| **Danger**                             |
| -------------------------------------- |
| Credential exposure via source access. |
| *Account compromise*                   |

**Detection Technique:**
```
(password|passwd|secret|api_key)\s*=\s*["'][^"']+["']
```

**Why This Works:**
- Secrets are typically hardcoded as literals.

**Vulnerable Example:**
```
DB_PASSWORD="admin123"
```

**Remedy:**
- Use environment variables.
- Secure secret managers.

| **Security Score:** | Critical (-30)             |
| ------------------- | -------------------------- |
| **Why:**            | Direct credential exposure |

---

### 7. Insecure Environment Variables

| **Danger**                                 |
| ------------------------------------------ |
| Secrets exposed via logs or shell history. |
| *Credential leakage*                       |

**Detection Technique:**
```
export\s+(SECRET|TOKEN|PASSWORD)=
```

**Why This Works:**
- Environment variable declarations are static.

**Vulnerable Example:**
```
export API_KEY=abcd1234
```

**Remedy:**
- Load secrets securely at runtime.
- Exclude from source control.

| **Security Score:** | High (-20)      |
| ------------------- | --------------- |
| **Why:**            | Secret exposure |

---

### 8. Missing Security Headers

| **Danger**                               |
| ---------------------------------------- |
| Increased exposure to XSS, clickjacking. |
| *Client-side attacks*                    |

**Detection Technique:**
```
(Content-Security-Policy|X-Frame-Options|X-Content-Type-Options)
```
*(absence detection)*

**Why This Works:**
- Security headers are explicitly configured.
- Absence is a know misconfiguration.

**Remedy:**
- Add CSP, CFO, XCTO headers.

| **Security Score:** | Medium (-15)             |
| ------------------- | ------------------------ |
| **Why:**            | Defense-in-depth failure |
