### 1. SQL Injection

| **Danger**                                  |
| ------------------------------------------- |
| Allows attackers to manipulate SQL queries. |
| *Data theft, auth bypass, DB deletion*      |

**Detection Technique:**
- Regex/AST detecting SQL keywords combined with string concatenation and user input.
```
(SELECT|INSERT|UPDATE|DELETE).*(\+|format\(|%s).*(request|input|params)
```

**Why This Works:**
- SQL injection requires *dynamic query construction*, which is visible in source code.

**Vulnerable Example:**
```
query = "SELECT * FROM users WHERE id = " + request.args["id"]
```

**Remedy:**
```
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

| **Why the Remedy Works**               |
| -------------------------------------- |
| Separates code from data.              |
| *Input cannot change query structure*. |

| **Security Score:** | Critical (-30)                    |
| ------------------- | --------------------------------- |
| **Why:**            | High impact, trivial exploitation |

---

### 2. XSS (Al Variants: Reflected, Stored, DOM)

| **Danger**                                        |
| ------------------------------------------------- |
| Attacker executes JavaScript in victim's browser. |
| *Session hijack, phishing*                        |
**Detection Technique:**
- Detect unsafe sinks:
```
(innerHTML|outerHTML|document.write|dangerouslySetInnerHTML)
```

**Why This Works:**
- XSS depends on *unsafe output APIs*, which are explicitly named.

**Vulnerable Example:**
```
element.innerHTML = userInput;
```

**Remedy:**
```
element.textContent = userInput;
```

| **Why the Remedy Works**                    |
| ------------------------------------------- |
| Prevents HTML parsing and script execution. |

| **Security Score:** | High (-20)                           |
| ------------------- | ------------------------------------ |
| **Why:**            | Affects other users, but client-side |

---

### 3. Command Injection

| **Danger**                                                  |
| ----------------------------------------------------------- |
| Attacker executes arbitrary commands via application logic. |
**Detection Technique:**
- Detect command execution APIs with user input:
```
(exec|system|popen|Runtime\.exec)
```

**Vulnerable Example:**
```
os.system("ping " + host)
```

**Remedy:**
```
subprocess.run(["ping", host], shell=False)
```


| **Security Score:** | Critical (-30)        |
| ------------------- | --------------------- |
| **Why:**            | Remote code execution |

---

### 4. LDAP Injection

| **Danger**            |
| --------------------- |
| Authentication bypass |
| Data exposure         |
**Detection Technique:**
- Regex detecting LDAP filter construction using user input.
```
ldap.*\+.*(request|input|params)
```

**Why This Works:**
- LDAP injection uses *string-based filter construction*, which is visible statically.

**Vulnerable Example:**
```
filter = "(uid=" + username + ")"
```

**Remedy:**
- Use parameterized LDAP queries.
- Escape special characters `(*()\\)`.

| **Security Score:** | High (-20)          |
| ------------------- | ------------------- |
| **Why:**            | Auth-related impact |

---

### 5. XPath Injection

| **Danger**                        |
| --------------------------------- |
| Attacker manipulates XML queries. |
| *Unauthorized data access*        |
**Detection Technique:**
```
(xpath|selectNodes|evaluate).*\+.*(input|params)
```

**Why This Works:**
- XPath queries are often built as strings.

**Vulnerable Example:**
```
xpath.evaluate("//user[name='" + input + "']", doc)
```

**Remedy:**
- Parameterized XPath.
- Input escaping.


| **Security Score:** | High (-20)    |
| ------------------- | ------------- |
| **Why:**            | Data exposure |

---

### 6. CRLF Injection

| **Danger**                          |
| ----------------------------------- |
| HTTP response splitting.            |
| *Header injection, cache poisoning* |
**Detection Technique:**
```
\\r\\n|%0d%0a
```

**Why This Works:**
- CRLF characters must be explicitly present.

**Vulnerable Example:**
```
response.setHeader("X-User", userInput)
```

**Remedy:**
- Strip CR/LF characters.
- Validate header values.

| **Security Score:** | High (-20)            |
| ------------------- | --------------------- |
| **Why:**            | Protocol-level attack |

---

### 7. Eval Injection

| **Danger**                |
| ------------------------- |
| Arbitrary code execution. |
**Detection Technique:**
```
\b(eval)\b
```

**Why This Works:**
- `eval` usage is explicit.

**Vulnerable Example:**
```
eval(userInput)
```

**Remedy:**
- Remove `eval`.
- Replace with safe logic.


| **Security Score:** | Critical (-30)           |
| ------------------- | ------------------------ |
| **Why:**            | Arbitrary code execution |

---

### 8. Static Code Injection

| **Danger**                          |
| ----------------------------------- |
| Attacker-controlled code execution. |
| *Remote code execution, backdoors*  |
**Detection Techniques:**
```
(include|require|require_once|importlib|loadFile).*(input|params|request)
```

**Why This Works:**
- Static code injection requires dynamic *inclusion of executable code*.
- Include/import statements are explicit language constructs.

**Vulnerable Example:**
```
include $_GET["page"]
```

**Remedy:**
- Strict whitelist of allowed modules/files.
- Disable dynamic loading.
```
$allowed = ["home.php", "about.php"];
include $allowed[$page];
```

| **Why the Remedy Works:**                     |
| --------------------------------------------- |
| Prevents attacker-controlled file resolution. |

| **Security Score:** | Critical (-30)                  |
| ------------------- | ------------------------------- |
| **Why:**            | Direct arbitrary code execution |

---

### 9. OS Command Injection

| **Danger**                              |
| --------------------------------------- |
| Execution of operating system commands. |
| *System compromise, data exfiltration*  |
**Detection Technique:**
```
(os\.system|subprocess|Runtime\.exec|ProcessBuilder).*(input|params)
```

**Why This Works:**
- OS command execution APIs are *well-defined and enumerable*.
- User input flowing into these APIs is statically visible.

**Vulnerable Example:**
```
os.system("ls " + userInput)
```

**Remedy:**
```
subprocess.run(["ls", userInput], shell=False)
```

| **Why the Remedy Works**       |
| ------------------------------ |
| Disables shell interpretation. |
| Prevents command chaining.     |

| **Security Score:** | Critical (-30)                      |
| ------------------- | ----------------------------------- |
| **Why:**            | Full system-level command execution |

---

### 10. PHP Remote File Inclusion (RFI)

| **Danger**                                 |
| ------------------------------------------ |
| Remote attacker-controlled code execution. |
| *Malware delivery, full compromise*        |
**Detection Technique:**
```
(include|require).*(http|https|ftp)
```

**Why This Works:**
- RFI requires remote URLS in include statements.
- These patterns are statically detectable.

**Vulnerable Example:**
```
include $_GET["url"];
```

**Remedy:**
- Disable `allow_url_include`.
- Enforce local file inclusion only.

| **Why the Remedy Works:**     |
| ----------------------------- |
| Prevents remote code loading. |

| **Security Score:** | Critical (-30)                     |
| ------------------- | ---------------------------------- |
| **Why:**            | Unrestricted remote code execution |

---

### 11. Path Traversal

| **Danger**                              |
| --------------------------------------- |
| Unauthorized file system access.        |
| *Credential leakage, source disclosure* |
**Detection Technique:**
```
(\.\./|\.\.\\).*(input|params)
```

**Why This Works:**
- Path traversal relies on *explicit traversal sequences*.
- These sequences are detectable without runtime context.

**Vulnerable Example:**
```
open("/files/" + filename)
```

**Remedy:**
- Normalize paths.
- Enforce directory whitelisting.
```
os.path.realpath(path).startswith(base_dir)
```

| **Why the Remedy Works:** |
| ------------------------- |
| Blocks directory escape.  |

| **Security Score:** | High (-20)                |
| ------------------- | ------------------------- |
| **Why:**            | Sensitive file disclosure |

---

### 12. Hard-Coded Credentials

| **Danger**                          |
| ----------------------------------- |
| Credential exposure in source code. |
| *Account compromise*                |
**Detection Technique:**
```
(password|secret|api_key)\s*=\s*["']
```

**Why This Works:**
- Secrets embedded in code are always written in plain text.
- Naming conventions are usually consistent.

**Vulnerable Example:**
```
DB_PASSWORD = "admin123"
```

**Remedy:**
- Use environment variables or secret managers.

| **Security Score:** | High (-20)                 |
| ------------------- | -------------------------- |
| **Why:**            | Direct credential exposure |

---

### 13. Sensitive Information in Comments

| **Danger**                                   |
| -------------------------------------------- |
| Disclosure of credentials or internal logic. |
| *Reconnaissance, lateral movement*           |
**Detection Technique:**
```
(comment).*(password|token|key)
```

**Why This Works:**
- Comments are static and human-readable.
- Sensitive keywords are easily identifiable.

**Vulnerable Example:**
```
// TODO: prod password = admin123
```

**Remedy:**
- Remove sensitive comments.

| **Security Score:** | Medium (-10)      |
| ------------------- | ----------------- |
| **Why:**            | Indirect exposure |

---

### 14. Debug Code Left Enabled

| **Danger**                                        |
| ------------------------------------------------- |
| Information leakage and attack surface expansion. |
| *Stack traces, secret exposure*                   |
**Detection Technique:**
```
(debug|DEBUG|console\.log|printStackTrace)
```

**Why This Works:**
- Debug flags are explicit config values.
- Logging calls are statically visible.

**Vulnerable Example:**
```
DEBUG = true
```

**Remedy:**
- Disable debug in production.
- Use environment-based configs.

| **Security Score:** | Medium (-10)            |
| ------------------- | ----------------------- |
| **Why:**            | Enables further attacks |

---

### 15. Logging Secrets

| **Danger**                       |
| -------------------------------- |
| Credentials stored in log files. |
| *Post-compromise escalation*     |
**Detection Technique:**
```
(log|print).*(password|token|secret)
```

**Why This Works:**
- Loggings APIs are explicit.
- Sensitive keywords are easily detectable.

**Vulnerable Example:**
```
logger.info("Password: %s", password)
```

**Remedy:**
- Remove sensitive fields.
- Log identifiers only.

| **Security Score:** | High (-20)                 |
| ------------------- | -------------------------- |
| **Why:**            | Persistent secret exposure |

---

### 16. Stack Traces Exposed

| **Danger**                                 |
| ------------------------------------------ |
| Internal application structure disclosure. |
| *Reconnaissance*                           |
**Detection Technique:**
```
printStackTrace|traceback\.print_exc
```

**Why This Works:**
- Stack trace functions are explicit API calls.

**Vulnerable Example:**
```
e.printStackTrace();
```

**Remedy:**
- Only log generic errors.
- Hide internal traces.

| **Security Score:** | Medium (-10)             |
| ------------------- | ------------------------ |
| **Why:**            | Enables targeted attacks |

---

### 17. Null Pointer Dereferences (Limited)

| **Danger**                   |
| ---------------------------- |
| Application crashes and DoS. |
**Detection Technique:**
```
variable\.method\(\)  // without prior null check
```

**Why This Works:**
- Absence of null checks is statically inferable in limited cases.

**Vulnerable Example:**
```
user.getName();
```

**Remedy:**
```
if (user != null) { user.getName(); }
```

| **Security Score:** | Low (-5)                 |
| ------------------- | ------------------------ |
| **Why:**            | Availability impact only |
