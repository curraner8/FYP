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
