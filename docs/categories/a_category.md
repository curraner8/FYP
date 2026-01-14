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
