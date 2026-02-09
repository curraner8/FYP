**Design/Runtime/Logic Vulnerabilities**

- These vulnerabilities come from application design decisions, runtime behaviour, or business logic, rather than unsafe syntax or configuration.
- They can't be reliably detected through static code analysis.
- This class is a limitation of the system.
- Findings in this category are *not automatically detected*, but users should be informed that these risks exist and should require manual review.

---

### 1. Insecure Design

| **Danger**                                              |
| ------------------------------------------------------- |
| Security weaknesses embedded in system architecture.    |
| *System may be fundamentally unsafe despite clean code* |

**Why it Can't be Detected:**
- Requires understanding of intended system behaviour.
- Static analysis cannot determine design intent.

**Example:**
- Sensitive operations exposed without layered validation.
- Trust placed in external systems without verification.

**Remedy:**
- Threat modelling.
- Security design reviews.
- Architecture validation.

| **Security Score:** | N/A                      |
| ------------------- | ------------------------ |
| **Why:**            | Requires human judgement |

---

### 2. Business Logic Flaws

| **Danger**                                          |
| --------------------------------------------------- |
| Legitimate functionality abused in unintended ways. |

**Why it Can't be Detected:**
- Code may behave exactly as written.
- Vulnerability exists in workflow logic, not implementation.

**Example:**
- Applying discounts repeatedly due to missing workflow checks.
- Skipping required steps in a transaction process.

**Remedy:**
- Manual testing.
- Abuse-case analysis.

| **Security Score:** | N/A                          |
| ------------------- | ---------------------------- |
| **Why:**            | Depends on application rules |

---

### 3. Race Conditions

| **Danger**                                                   |
| ------------------------------------------------------------ |
| Concurrent execution leads to inconsistent or unsafe states. |

**Why it Can't be Detected:**
- Requires runtime timing and concurrency conditions.
- Static code cannot predict execution order.

**Example:**
- Multiple withdrawals processed simultaneously.

**Remedy:**
- Locking mechanisms.
- Atomic operations.
- Transaction control.

| **Security Score:** | N/A                         |
| ------------------- | --------------------------- |
| **Why:**            | Runtime-dependent behaviour |

---

### 4. Authorization Logic Errors

| **Danger**                                              |
| ------------------------------------------------------- |
| Incorrect permission decisions despite existing checks. |

**Why it Can't be Detected:**
- Static analysis can see checks but not correctness.

**Example:**
```
if user.role != "admin":
    allow_access()
```

**Remedy:**
- Security testing.
- Role validation review.

| **Security Score:** | N/A                       |
| ------------------- | ------------------------- |
| **Why:**            | Logic correctness problem |

---

### 5. Authentication Flow Weaknesses

| **Danger**                                              |
| ------------------------------------------------------- |
| Improper session handling or authentication sequencing. |

**Why it Can't be Detected:**
- Requires runtime interaction and state tracking.

**Example:**
- Password reset usable without verification step.

**Remedy:**
- Authentication flow review.
- Penetration testing.

| **Security Score:** | N/A                          |
| ------------------- | ---------------------------- |
| **Why:**            | Depends on runtime behaviour |

---

### 6. Trust Boundary Violations

| **Danger**                                                  |
| ----------------------------------------------------------- |
| Untrusted data treated as trusted within system boundaries. |

**Why it Can't be Detected:**
- Requires architectural understanding of system components.

**Example:**
- Internal API trusted without authentication.

**Remedy:**
- Explicit trust boundary definitions.
- Zero-trust validation.

| **Security Score:** | N/A                 |
| ------------------- | ------------------- |
| **Why:**            | Architectural issue |

---

### 7. Failing Open

| **Danger**                              |
| --------------------------------------- |
| System grants access when error occurs. |

**Why it Can't be Detected:**
- Requires runtime error paths and execution context.

**Example:**
```
if auth_check_fails:
    allow_access()
```

**Remedy:**
- Default deny behaviour.
- Defensive error handling.

| **Security Score:** | N/A                       |
| ------------------- | ------------------------- |
| **Why:**            | Depends on execution flow |

---

### 8. Excessive Attach Surface

| **Danger**                                                     |
| -------------------------------------------------------------- |
| Unnecessary endpoints or functionality increase risk exposure. |

**Why it Can't be Detected:**
- Can't detect how necessary a feature is.

**Example:**
- Unused admin endpoints left accessible.

**Remedy:**
- Endpoint review.
- Feature minimisation.

| **Security Score:** | N/A             |
| ------------------- | --------------- |
| **Why:**            | Design decision |
