# Class F

---

### F1. Race Condition Risk

Also known as "Time-of-Check to Time-of-Use". This happens when an application checks a condition and then performs an action based on that check. The state could change between the check and the action, leading to unauthorized access or data corruption.

**Pattern:**
```
`(?i)(check.*then|if.*exists.*then|read.*then.*write|get.*then.*update)`
```

- Scans for logic-based phrases. It is looking for the double-check pattern in the code that suggests the developer is handling state-sensitive operations.

---

### F2. Trust Boundary Risk

A "Trust Boundary" is a point where data crosses from an untrusted source into the internal system. A common mistake is assuming that data coming from an "internal" API or a frontend that already performed validation is clean.

**Pattern:**
```
`(?i)(trust.*client|frontend.*validation|user.*input.*trusted|internal.*api|microservice.*call)`
```

- Looks for comments or variable names that imply a level of trust or a boundary crossing. This flags areas where the developer might be skipping strict server-side validation because they trust the source.

---

### F3. Auth Flow Complexity

Authentication flows are difficult to implement correctly. Small mistakes in how a token is validated or how a session is invalidated can lead to full account takeovers.

**Pattern:**
```
`(?i)(password.*reset|forgot.*password|login.*redirect|oauth.*callback|jwt.*refresh|session.*fixation)`
```

- Identifies code handling sensitive identity transitions. The presence of these keywords triggers a reminder that these specific files carry a higher architectural risk than standard business logic.
