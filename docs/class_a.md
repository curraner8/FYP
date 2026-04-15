# Class A 

---

### A1. SQL Injection

Occurs when untrusted data is inserted directly into a database query, allowing attackers to manipulate or steal data.

**Pattern:**
```
`(?i)(` +
`SELECT\s+.+\s+FROM|` +
`INSERT\s+INTO|` +
`UPDATE\s+\w+\s+SET|` +
`DELETE\s+FROM|` +
`DROP\s+(TABLE|DATABASE)|` +
`UNION\s+(ALL\s+)?SELECT` +
`).*?(` +
`\+\s*\w|` +
`%[sd]\b|` +
`\.format\s*\(|` +
`f["']|` +
"`\\$\\{" +
`)`
```

- It looks for SQL keywords such as `SELECT` or `INSERT` followed by immediate signs of string concatenation.

---

### A2. Cross-Site Scripting (XSS)

Attackers inject malicious scripts into web pages viewed by other users.

**Pattern:**
```
`(?i)(` +
`innerHTML\s*=|` +
`outerHTML\s*=|` +
`document\.write\s*\(|` +
`document\.writeln\s*\(|` +
`insertAdjacentHTML\s*\(|` +
`dangerouslySetInnerHTML\s*=|` +
`\.html\s*\(|` +
`setAttribute\s*\(\s*["']on|` +
`setAttribute\s*\(\s*["']href` +
`).*?(` +
`request\.|req\.|` +
`params\[|query\[|` +
`input|userInput|` +
`location\.(search|hash)|` +
`document\.cookie` +
`)`
```

- It identifies dangerous functions such as `innerHTML` or `document.write` that are being fed from user input variables like `req.query` or `location.search`.

---

### A3. Command Injection

Allows an attacker to execute arbitrary system commands on the server host.

**Pattern:**
```
`(?i)(` +
`os\.system\s*\(|` +
`subprocess\.(call|run|Popen)\s*\(|` +
`exec\s*\(|` +
`popen\s*\(|` +
`Runtime\.getRuntime\(\)\.exec|` +
`ProcessBuilder\s*\(|` +
`child_process\.(exec|spawn|execSync|spawnSync)\s*\(|` +
`exec\.Command\s*\(` +
`).*?(` +
`\+|` +
`%s|%v|` +
`\$\{|` +
`f["']` +
`).*?(`+
`request|input|params|args|req\.|user|cmd|command|query` +
`)`
```

- Scans for system execution functions like `os.system` or `subprocess` that are being passed variables containing common user-input keywords joined by concatenation characters.

---

### A4. LDAP Injection

Similar to the SQL Injections, but targets LDAP queries used for authentication and searching.

**Pattern:**
```
`(?is)(` +
`ldap\.(search|bind|modify|add|delete)\s*\(|` +
`DirContext\.(search|bind)\s*\(|` +
`ldap_search\s*\(|` +
`\(\s*(uid|cn|mail|userPassword|sAMAccountName)` +
`[^)]{0,100}(\+|%s|%v|\.format\s*\(|f["'])` +
`).*?(request|input|params|user|username|req\.)`
```

- Searches for LDAP search or bind functions that include string formatting or concatenation involving common directory attributes like `uid` and user-provided variables.

---

### A5. XPath Injection

Manipulates XML data queries to bypass authentication or access restricted XML data.

**Pattern:**
```
`(?is)(` +
`xpath\.(evaluate|selectNodes|selectSingleNode|compile)\s*\(|` +
`\.evaluate\s*\([^)]*["']\/\/|` +
`XPath\.compile\s*\(|` +
`etree\.(xpath|findall|find)\s*\(|` +
`selectNodes\s*\(|` +
`["'](\/\/|\.\/).*\+.*["']` +
`).{0,200}?(` +
`request|input|params|user|req\.|body|data` +
`)`
```

- It flags `xpath.evaluate` or `selectNodes` calls where the query string contains both a path indicator and a concatenation operator alongside input-relates keywords.

---

### A6. CRLF Injection

Attackers inject "Carriage Return" and "Line Feed" characters into HTTP headers to split responses.

**Pattern:**
```
`(?is)(` +
`(setHeader|addHeader)\s*\(|` +
`writeHead\s*\(|` +
`response\.headers\s*\[|` +
`w\.Header\(\)\.(Set|Add)\s*\(|` +
`header\s*\(\s*["']Location|` +
`res\.redirect\s*\(` +
`).{0,200}?(` +
`\+\s*\w|%s|%v|f["']|\$\{|` +
`\\r\\n|\\n|%0[aAdD]|%0d%0a` +
`).*?(request|input|params|user|req\.)`
```

- Monitors header setting functions for the presence of newline characters or unsanitized user variables.

---

### A7. Eval Injection

The most dangerous form of injection where a string is executed as actual code.

**Pattern:**
```
`(?is)\b(eval|exec)\s*\(.{0,200}?(` +
`request|input|params|user|req\.|data|body|` +
`argv|stdin|os\.environ|getenv` +
`)`
```

- It targets the `eval()` or `exec()` functions directly if they are passed any data coming from `request`, or `input` etc. or environment variables.

---

### A8. Static Code Injection

Attackers control which file or module is loaded or included in the application.

**Pattern:**
```
`(?is)(` +
`include\s*\(|` +
`require\s*\(|` +
`require_once\s*\(|` +
`include_once\s*\(|` +
`importlib\.import_module\s*\(|` +
`__import__\s*\(|` +
`System\.loadLibrary\s*\(|` +
`Class\.forName\s*\(` +
`).{0,150}?(` +	`request|input|params|user|req\.|body|data|\$_(GET|POST|REQUEST)` +
`)`
```

- Looks for dynamic file inclusion statements where the path is being determined by user-controlled variables.

---

### A9. Path Traversal

Allows access to files and directories stored outside of the intended root folder.

**Password:**
```
`(?is)(` +
`open\s*\([^)]*["'][rwab]|` +
`os\.(Open|ReadFile|Create)\s*\(|` +
`fs\.(readFile|readFileSync|createReadStream)\s*(|`+
`res\.(sendFile|download)\s*\(|` +
`FileInputStream\s*\(|` +
`new\s+File\s*\(|` +
`filepath\.(Join|Abs)\s*\(` +
`).{0,200}?(` +
`\.\./|` +
`\.\.\\|` +
`/\.\.|` +
`\\\.\.|` +
`request\.|req\.|params|input|user|query` +
`)`
```

- Detects file opening functions being used with traversal sequences or user-input variables.

---

### A10. Hardcoded Credentials

Storing passwords or API keys in plaintext in the code.

**Pattern:**
```
`(?i)(` +
`password|passwd|secret|api_key|apikey|` +
`token|auth_token|access_token|` +
`aws_access_key_id|aws_secret_access_key|` +
`private_key|client_secret|db_password` +
`)\s*[:=]+\s*["'][^"'\s]{6,}["']`
```

- Checks for assignment patterns where common credential variable names are assigned a string value that is at least six characters long.

---

### A11. Sensitive Info in Comments

Developers leaving passwords or auth-bypass/hack notes in code comments.

**Pattern:**
```
`(?i)(//|#|/\*|--|\*)\s*.{0,50}?(` +
`password\s*[:=]|` +
`secret\s*[:=]|` +
`api[_-]?key\s*[:=]|` +
`token\s*[:=]|` +
`private[_-]?key|` +
`backdoor|bypass\s+auth|` +
`hardcoded|` +
`admin.*password|` +
`credentials?` +
`)`
```

- Checks comment blocks for high-risk keywords like `admin password`, `hardcoded`, `bypass auth`.

---

### A12. Debug Code Enabled

Debugging features can leak system internals if left on in production.

**Pattern:**
```
`(?i)(` +
`\b(debug|DEBUG)\s*(=|:=)\s*(True|true|1)|` +
`app\.(debug|config\[["']DEBUG["']\])\s*=\s*(True|true)|` +
`console\.(log|debug|trace)\s*\(|` +
`debugger\s*;|` +
`\bpprint\s*\(|` +
`fmt\.(Printf|Println)\s*\([^)]*("DEBUG|"debug|debug:)` +
`)`
```

- Looks for `DEBUG = True` flags, the `debugger` statement, or other general console logging/printing functions used for troubleshooting.

---

### A13. Logging Secrets

Accidentally writing sensitive data into system logs.

**Pattern:**
```
`(?i)(` +
`\b(print|println|printf)\s*\(|` +
`console\.(log|info|warn|error)\s*\(|` +
`(log|logger)\.(debug|info|warn|error|fatal|print|println)\s*\(|` +
`logging\.(debug|info|warning|error|critical)\s*\(|` +
`syslog\s*\(|` +
`fmt\.(Print|Printf|Println|Fprintf)\s*\(` +
`).{0,200}?(` +
`password|passwd|secret|` +
`api[_-]?key|access[_-]?token|` +
`auth[_-]?token|private[_-]?key|` +
`credit[_-]?card|ssn|cvv` +
`)`
```

- It identifies print or log statements that contain both a logging function and a sensitive keyword.

---

### A14. Stack Traces Exposed

Printing full error traces to the user can reveal the internal file structure and library versions.

**Pattern:**
```
`(?is)(` +
`printStackTrace\s*\(|` +
`traceback\.print_exc\s*\(|` +
`traceback\.print_tb\s*\(|` +
`traceback\.format_exc\s*\(\)|` +
`console\.(error|log)\s*\([^)]*\.(stack|trace)|` +
`res\.(send|json)\s*\([^)]*err(or)?\.stack|` +
`w\.Write\s*\([^)]*err\.Error\(\)|` +
`fmt\.(Fprintf|Println)\s*\(\s*w[^)]*err` +
`)`
```

- Detects calls to `printStackTrace` or writing `err.stack` etc. directly to the response object.

---

### A15. Null Pointer Risk

Attempting to access a property of an object that might be `null` or `undefined`, causing a crash.

**Pattern:**
```
`(?i)(` +
`getParameter\s*\([^)]+\)\s*\.\w+|` +
`getElementById\s*\([^)]+\)\s*\.\w+|` +
`querySelector\s*\([^)]+\)\s*\.\w+|` +
`json\.(loads|load)\s*\([^)]+\)\[` +
`)`
```

- Looks for common functions that often return null followed immediately by a property access without a visible safety check.
