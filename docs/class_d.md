# Class D

---

### D1. Missing Authorization

A web route or endpoint that is accessible to anyone because the developer forgot to add in a login or permission check.

**Pattern:**
```
var routePattern = regexp.MustCompile(`(?i)(` +
	`@app\.route\s*\([^)]+\)|` +
	`@router\.(get|post|put|delete)\s*\(|` +
	`router\.(get|post|put|delete)\s*\(|` +
	`app\.(get|post|put|delete)\s*\(` +
	`)`)
	
authKeywords := []string{
	"login_required", "jwt_required", "authenticate",
	"authorize", "permission", "middleware", "guard",
	"auth", "token", "bearer", "session",
}
```

- First identifies common route declarations, then scans the 5 lines below and above that declaration for keywords like `login_required` or `middleware`. If none are found, it flags the route as potentially unprotected.

---

### D2. IDOR Pattern

Insecure Direct Object Reference happens when an app fetches data based on an ID from the URL without checking if the current user actually owns that ID.

**Pattern:**
```
`(?i)(` +
`WHERE\s+(id|user_id|account_id|order_id)\s*=\s*(request|params|req\.|input|body|args)|` +
`\.get\s*\([^)]*request\.(GET|POST)|` +
`Model\.(find|findOne|findById)\s*\([^)]*req\.(params|body|query)|` +
`objects\.get\s*\(id\s*=\s*(request|params)` +
`)`
```

- Looks for database queries (e.g. `WHERE id = ...`) or model lookups that pull an ID directly from a user request in a single step.

---

### D3. Sensitive Route Exposed

Admin panels, debug consoles, or internal configuration pages that might be accidentally left accessible to the public.

**Pattern:**
```
`(?i)(` +
`["'](/admin|/internal|/debug|/test|/backup|/config|/console|/actuator|/swagger)` +
`)`
```

- It scans string literals for high-risk URL paths such as `/admin` or `/internal`, etc.

---

### D4. CSRF Risk

Cross-Site Request Forgery happens when state-changing actions (such as `POST` requests) don't verify a secret token and can therefore be triggered by malicious third-party websites.

**Pattern:**
```
var postRoutePattern = regexp.MustCompile(`(?i)(` +
	`@app\.route\s*\([^)]*methods\s*=\s*\[[^\]]*POST|` +
	`router\.post\s*\(|` +
	`app\.post\s*\(` +
	`)`)

csrfKeywords := []string{
	"csrf", "csrf_token", "_csrf", "csrfprotection",
	"csurf", "csrf_exempt", "samesite",
}	
```

- Identifies `POST` route definitions and checks the 10 surrounding lines for CSRF-related keywords. If no protection is visible it flags the endpoint.

---

### D5. Open Redirect

An attacker can use your trusted domain to redirect users to a malicious site.

**Pattern:**
```
`(?i)(` +
`res\.redirect\s*\([^)]*req\.(query|params|body)|` +
`redirect\s*\([^)]*request\.(args|form|values)|` +
`http\.Redirect\s*\([^)]*r\.(URL|FormValue|Header)|` +
`location\.href\s*=.*?(request|params|query|url|next)|` +
`window\.location\s*=.*?(request|params|query|url|next)` +
`)`
```

- Looks for redirection functions where the destination URL is being built using a parameter directly from the user's request.

---

### D6. SSRF Risk

Server-Side Request Forgery occurs when the server is tricked into making an internal request to a system that it shouldn't access.

**Pattern:**
```
`(?i)(` +
`requests\.(get|post|put|delete)\s*\(|` +
`urllib\.request\.(urlopen|Request)\s*\(|` +
`http\.(get|post|request)\s*\(|` +
`fetch\s*\(|` +
`axios\.(get|post|put|delete)\s*\(|` +
`new\s+URL\s*\(|` +
`HttpClient|WebClient|RestTemplate` +
`).{0,200}?(` +	`request\.|req\.|params|input|url|target|endpoint|host|domain` +
`)`
```

- It identifies HTTP client calls that contain variables with names like `target`, `url`, or `host` within a 200 character proximity.

---

### D7. Client-Side Security

Relying on the UI to hide buttons or fields based on permissions means that attackers can use browser dev tools to re-enable hidden elements if the server doesn't also check the permission.

**Pattern:**
```
`(?i)(` +
`(disabled|hidden|readOnly)\s*=\s*\{[^}]*(role|admin|permission|isAdmin)|` +
`v-if\s*=\s*["'][^"']*(role|admin|permission)|` +
`\*ngIf\s*=\s*["'][^"']*(role|admin|isAdmin)` +
`)`
```

- Looks for frontend framework directives (like `v-if`) that uses security-related keywords to toggle visibility.

---

### D8. Sensitive Data in GET

Passing passwords or tokens in the URL (GET parameters). These get saved in browser history, server logs, and "Referer" headers, exposing them to anyone with log access.

**Pattern:**
```
`(?i)(` +
`(\?|&)(password|token|secret|api_key|api-key|credit_card|ssn|cvv)=|` +
`params\s*=\s*\{[^}]*(password|token|secret)[^}]*\}.*?(get|GET)|` +
`requests\.get\s*\([^)]*params\s*=\s*\{[^}]*(password|token|secret)` +
`)`
```

- Checks for sensitive keys appearing inside URL query strings or within the `params` object of a GET request.
