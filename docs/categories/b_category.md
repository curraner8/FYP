The use of dangerous or insecure APIs, regardless of whether user input is present.
Detection focuses on *function names, flags, and parameters*.

---

### 1. Eval Usage (`eval`)

| **Danger**                              |
| --------------------------------------- |
| Execution of arbitrary code at runtime. |
| *Full application compromise*           |

**Detection Technique:**
```
\b(eval)\s*\(
```

**Why This Works:**
- `eval` is an *explicit language construct*.
- Its presence alone represents a security risk.

**Vulnerable Example:**
```
eval(userInput)
```

**Remedy:**
- Remove `eval`.
- Replace with structured logic (parsing, mapping, conditionals).

| **Why The Remedy Works:**                   |
| ------------------------------------------- |
| Eliminates dynamic code execution entirely. |

| **Security Score:** | Critical (-30)           |
| ------------------- | ------------------------ |
| **Why:**            | Arbitrary code execution |

---

### 2. OS Command Execution APIs (`exec`, `system`, `popen`)

| **Danger**                          |
| ----------------------------------- |
| Operating system command execution. |
| *System compromise*                 |

**Detection Technique:**
```
(exec|system|popen|Runtime\.exec)
```

**Why This Works:**
- OS execution of APIs are finite and *well-known*.
- Their usage is statically visible regardless of input source.

**Vulnerable Example:**
```
system("ls");
```

**Remedy:**
- Use non-shell APIs.
- Avoid command execution entirely when possible.


| **Why the Remedy Works:**                           |
| --------------------------------------------------- |
| Prevents shell interpretation and command chaining. |

| **Security Score:** | Critical (-30)                |
| ------------------- | ----------------------------- |
| **Why:**            | Direct system-level execution |

---

### 3. Python Deserialization (`pickle.loads`)

| **Danger**                      |
| ------------------------------- |
| Arbitrary object instantiation. |
| *Remote code execution*         |

**Detection Technique:**
```
pickle\.loads
```

**Why This Works:**
- `pickle.loads` is *inherently unsafe for untrusted data*.
- Risk exists even without visible user input.

**Vulnerable Example:**
```
pickle.loads(data)
```

**Remedy:**
- Use `json.loads`.
- Validate schema strictly.


| **Why the Remedy Works:**                 |
| ----------------------------------------- |
| JSON does not support executable objects. |

| **Security Score:** | Critical (-30)                        |
| ------------------- | ------------------------------------- |
| **Why:**            | Code execution during deserialization |

---

### 4. Java Deserialization (`ObjectInputStream`)

| **Danger**                            |
| ------------------------------------- |
| Gadget-chain deserialization attacks. |
| *Remote code execution*               |

**Detection Technique:**
```
ObjectInputStream
```

**Why This Works:**
- Java deserialization vulnerabilities are *API-level* flaws.
- Presence alone warrants warning.

**Vulnerable Example:**
```
ObjectInputStream ois = new ObjectInputStream(stream);
```

**Remedy:**
- Avoid Java serialization.
- Use safe formats (JSON, protobuf).
- Apply deserialization filters.

| **Security Score:** | Critical (-30)          |
| ------------------- | ----------------------- |
| **Why:**            | Known RCE attack vector |

---

### 5. Unsafe YAML Parsing (`yaml.load`)

| **Danger**                           |
| ------------------------------------ |
| Object instantiation during parsing. |
| *Code execution*                     |

**Detection Technique:**
```
yaml\.load\s*\(
```

**Why This Works:**
- `yaml.load` executes constructors by default.
- Unsafe regardless of input origin.

**Vulnerable Example:**
```
yaml.load(data)
```

**Remedy:**
```
yaml.safe_load(data)
```

| **Why the Remedy Works:**     |
| ----------------------------- |
| Disables object construction. |

| **Security Score:** | High (-20)           |
| ------------------- | -------------------- |
| **Why:**            | Deserialization risk |

---

### 6. Shell Invocation via `subprocess`

| **Danger**                       |
| -------------------------------- |
| Shell command injection surface. |
| *Command chaining*               |

**Detection Technique:**
```
subprocess\.(call|run|Popen).*shell\s*=\s*True
```

**Why This Works:**
- `shell=True` explicitly enables shell parsing.
- Risk exists even with constant commands.

**Vulnerable Example:**
```
subprocess.call(cmd, shell=True)
```

**Remedy:**
```
subprocess.run(["cmd", "arg"], shell=False)
```


| **Security Score:** | High (-20)                |
| ------------------- | ------------------------- |
| **Why:**            | Enables command injection |

---

### 7. Weak Cryptographic Hashes (`md5`, `sha1`)

| **Danger**                              |
| --------------------------------------- |
| Hash collision and brute-force attacks. |
| *Credential compromise*                 |

**Detection Technique:**
````
(md5|sha1)\s*\(
````

**Why This Works:**
- Weak algorithms are *cryptographically broken*.
- No contextual analysis required.

**Vulnerable Example:**
```
hashlib.md5(password)
```

**Remedy:**
- Use `bcrypt`, `argon2`, or `PBKDF2`.

| **Security Score:** | High (-20)         |
| ------------------- | ------------------ |
| **Why:**            | Predictable hashes |

---

### 8. Insecure Random Number Generator (`Math.random`)

| **Danger**                     |
| ------------------------------ |
| Predictable tokens or secrets. |
| *Session hijacking*            |

**Detection Technique:**
```
Math\.random
```

**Why This Works:**
- `Math.random` is *not cryptographically secure*.
- Any security-sensitive use is unsafe.

**Vulnerable Example:**
```
token = Math.random()
```

**Remedy:**
- Use `crypto.getRandomValues`.

| **Security Score:** | Medium (-10)        |
| ------------------- | ------------------- |
| **Why:**            | Predictable entropy |

---

### 9. Insecure XML Parsers

| **Danger**              |
| ----------------------- |
| XXE attacks.            |
| *File disclosure, SSRF* |

**Detection Technique:**
```
DocumentBuilderFactory\.newInstance
```

**Why This Works:**
- XML parsers are unsafe by default.
- Security depends on flags being disabled.

**Vulnerable Example:**
```
DocumentBuilderFactory.newInstance()
```

**Remedy:**
- Disable external entities.
- Enable secure processing.

| **Security Score:** | High (-20)              |
| ------------------- | ----------------------- |
| **Why:**            | File and network access |
