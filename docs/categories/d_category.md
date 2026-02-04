These detections identify *potential vulnerabilities*, relying on risk indicators, not proof. False positives will be expected and acceptable. These vulnerability flags require human judgement.

---

### 1. Missing Authorization Checks

| **Danger**                                      |
| ----------------------------------------------- |
| Unauthorized access to protected functionality. |
| *Privilege escalation*                          |

**Detection:**
- Route/controller without auth middleware.
```
@app\.route\([^)]*\)(?![\s\S]*?(login_required|auth|authorize|permission|role))
```

**Why This Works:**
- Secure endpoints almost always contain explicit auth checks.
- Absence is a strong risk signal.

**Example:**
```
@app.route("/admin")
def admin():
    return render_template("admin.html")
```

**Remedy:**
- Enforce server-side authorization middleware.

| **Security Score:** | High (-20)                                      |
| ------------------- | ----------------------------------------------- |
| **Why:**            | Access control failure is a leading OWASP issue |

---

### 2. IDOR (Insecure Direct Object Reference)

| **Danger**                             |
| -------------------------------------- |
| Users access resources they don't own. |

**Detection:**
```
WHERE\s+id\s*=\s*(request|params|user)
```

**Why This Works:**
- Direct use of user-controlled IDs without ownership checks is a classic IDOR pattern.

**Example:**
```
SELECT * FROM orders WHERE id = request.args["id"]
```

**Remedy:**
- Validate ownership server-side.

| **Security Score:** | High (-20)           |
| ------------------- | -------------------- |
| **Why:**            | Direct data exposure |

---

### 3. Forced Browsing

| **Danger**                              |
| --------------------------------------- |
| Access to hidden or unlinked endpoints. |

**Detection:**
- Sensitive routes lacking authentication.

**Why This Works:**
- Sensitive functionality should never be publicly reachable.

**Example:**
```
@app.route("/internal/report")
def report():
    return generate_report()
```

**Remedy:**
- Restrict routes using authentication and authorization.

| **Security Score:** | Medium (-15)                    |
| ------------------- | ------------------------------- |
| **Why:**            | Limited but real attack surface |

---

### 4. CSRF Risk Indicators

| **Danger**                                             |
| ------------------------------------------------------ |
| Unauthorized actions executed via authenticated users. |

**Detection:**
```
<form[^>]*method=["']post["'](?![\s\S]*csrf)
```

**Why This Works:**
- Secure POST actions usually include CSRF tokens.

**Example:**
```
<form method="post" action="/change-email">
```

**Remedy:**
- Add CSRF tokens and server-side validation.

| **Security Score:** | High (-20)              |
| ------------------- | ----------------------- |
| **Why:**            | Account compromise risk |

---

### 5. Open Redirect

| **Danger**                                         |
| -------------------------------------------------- |
| Redirects to attacker-controlled sites (phishing). |

**Detection:**
```
redirect\((request|params|input)
```

**Why This Works:**
- Redirecting to user-controlled URLs is unsafe.

**Example:**
```
return redirect(request.args["next"])
```

**Remedy:**
- Potentially whitelist allowed redirect targets.

| **Security Score:** | Medium (-15)             |
| ------------------- | ------------------------ |
| **Why:**            | Indirect but exploitable |

---

### 6. SSRF (Server-Side Request Forgery) Indicators

| **Danger**                               |
| ---------------------------------------- |
| Internal services accessed by attackers. |

**Detection:**
```
(requests|get|fetch)\(.*(url|input|params)
```

**Why This Works:**
- User-controlled outbound requests are the core SSRF pattern.

**Example:**
```
requests.get(request.args["url"])
```

**Remedy:**
- Validate URLs.
- Block internal IP ranges.

| **Security Score:** | High (-20)                  |
| ------------------- | --------------------------- |
| **Why:**            | Infrastructure-level impact |

---

### 7. Client-Side Enforcement of Security

| **Danger**                              |
| --------------------------------------- |
| Security logic bypassable by attackers. |

**Detection:**
```
if\s*\(.*role.*\)
```

**Why This Works:**
- Client-side checks are visible but unenforceable.

**Example:**
```
if (user.role === "admin") {
    showAdminPanel();
}
```

**Remedy:**
- Enforce authorization server-side.

| **Security Score:** | High (-20)     |
| ------------------- | -------------- |
| **Why:**            | Trivial bypass |

---

### 8. Sensitive Data in GET Requests

| **Danger**                                 |
| ------------------------------------------ |
| Credentials leaked via URLs, logs, caches. |

**Detection:**
```
\?.*(password|token|secret)=
```

**Why This Works:**
- URLs are logged and cached by default.

**Example:**
```
/login?username=admin&password=1234
```

**Remedy:**
- Use POST for sensitive data.

| **Security Score:** | Medium (-15)        |
| ------------------- | ------------------- |
| **Why:**            | Information leakage |

---

### 9. Direct Use of User IDs in Queries

| **Danger**                                        |
| ------------------------------------------------- |
| Authorization bypass via identifier manipulation. |

**Detection:**
```
(user_id|account_id)\s*=\s*(request|params|input)
```

**Why This Works:**
- User identifiers should be derived from the authenticated session, not request data.
- This pattern leads to IDOR-style exploits.

**Example:**
```
SELECT * FROM users WHERE user_id = request.args["user_id"]
```

**Remedy:**
- Bind identifiers to the authenticated user context.
- Ignore user-supplied IDs for sensitive queries.

| **Security Score:** | High (-20)                |
| ------------------- | ------------------------- |
| **Why:**            | Privilege escalation risk |


---

These are risky patterns and not guaranteed exploits.
They will be labelled with warnings such as "Potential Issue - Manual Review Required", with a button to confirm that it is safe.
