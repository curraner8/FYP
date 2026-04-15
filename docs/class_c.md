# Class C

---

### C1. Debug Mode Enabled

Running an app in "development" or "debug" mode in a production environment often exposes detailed error messages and internal paths.

**Pattern:**
```
`(?i)(` +
`FLASK_ENV\s*=\s*["']development["']|` +
`NODE_ENV\s*=\s*["']development["']|` +
`enable_debug\s*\(\s*true\s*\)` +
`)`
```

- Searches for environment variables (like `FLASK_ENV` or `NODE_ENV`) being explicitly set to `"development"`, or function calls like `enable_debug(true)`.

---

### C2. Insecure Protocol / SSL Disabled

Disabling SSL/TKS verification allows man in the middle attacks where an attacker can intercept or modify encrypted traffic.

**Pattern:**
```
`(?i)(` +
`verify\s*=\s*(False|false)|` +
`ssl\s*=\s*(False|false|0)|` +
`rejectUnauthorized\s*:\s*false|` +
`InsecureSkipVerify\s*:\s*true|` +
`DISABLE_SSL\s*=\s*(true|True|1)` +
`)`
```

- It flags configuration flags that turn off security.

---

### C3. Insecure Cookies

Cookies without proper security flags are vulnerable to theft via XSS or sniffing over unencrypted connections.

**Pattern:**
```
`(?i)(res\.cookie|Set-Cookie|set_cookie|response\.set_cookie|setcookie)\s*[\(:]`

Keyword List:
"HttpOnly"
"Secure"
"SameSite"
```

- This uses a two step check, firstly finding cookie-setting functions and then checking the line for the absence of critical strings (in the keyword list).

---

### C4. Directory Listing

If the server is configured to list files in a directory it can leak source code, backup files, and sensitive data.

**Pattern:**
```
`(?i)(` +
`Options\s+(\+\s*)?Indexes|` +
`autoindex\s+on\s*;|` +
`directory_listing\s*[=:]\s*(true|on)|` +
`serveIndex\s*\(|` +
`http\.FileServer\s*\(|` +
`StaticFiles\s*\([^)]*html_dir` +
`)`
```

- It looks for server configuration strings or static files serving functions in Go and Node.js.

---

### C5. Verbose Error Leak

Application error handlers that propagate raw stack traces or internal exceptions directly to the user's browser.

**Pattern:**
```
`(?i)(` +
`app\.use\s*\(\s*errorhandler|` +
`DEBUG_PROPAGATE_EXCEPTIONS\s*=\s*True|` +
`PROPAGATE_EXCEPTIONS\s*=\s*True|` +
`app\.run\s*\([^)]*debug\s*=\s*True` +
`)`
```

- Targets the registration of "Error Handler" middleware or global flags like `PROPAGATE_EXCEPTIONS = True` that override standard safe error pages.

---

### C6. Config File Secrets

Hardcoding database passwords, JWT secrets, or could API keys directly into configuration files or scripts.

**Pattern:**
```
`(?i)(` + `(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*["'][^"']{4,}["']|` + `(SECRET_KEY|APP_SECRET|JWT_SECRET|FLASK_SECRET)\s*=\s*["'][^"']{4,}["']|` + `(AWS_SECRET|AZURE_CLIENT_SECRET|GCP_API_KEY)\s*=\s*["'][^"']{4,}["']|` + `(STRIPE_SECRET|SENDGRID_API_KEY|TWILIO_AUTH)\s*=\s*["'][^"']{4,}["']` +
`)`
```

- Scans for common secret variable names assigned to a string value that is at least 4 characters long.

---

### C7. Exposed Environment Variables

Defining secrets in Dockerfiles or using `export` in shell scripts. These secrets become part of the image history or process list, making them easily discoverable.

**Pattern:**
```
`(?i)(` +
`^\s*export\s+(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|AWS_SECRET)[^=]*=.+|` +
`ENV\s+(SECRET|TOKEN|PASSWORD|API_KEY)[^=\n]*=\s*\S+|` +
`os\.environ\s*\[\s*["'](SECRET|TOKEN|PASSWORD|API_KEY)["']\s*\]\s*=\s*["'][^"']{4,}["']` +
`)`
```

- Flags lines starting with `export` or `ENV` followed by sensitive keywords, as well as direct assignments to `os.environ` in code.

---

### C8. Missing Security Headers

Browsers rely on HTTP headers to enable built-in security features against clickjacking and injection.

**Pattern:**
```
mainAppFiles := map[string]bool{
	"app.js":    true,
	"app.py":    true,
	"server.js": true,
	"index.js":  true,
	"main.py":   true,
	"main.go":   true,
	"app.ts":    true,
	"server.ts": true,
}
	
securityHeaders := []struct {
		keyword     string
		description string
	}{
		{"helmet", "Helmet.js middleware not found"},
		{"X-Frame-Options", "X-Frame-Options header not set"},
		{"Content-Security-Policy", "Content-Security-Policy header not set"},
		{"X-Content-Type-Options", "X-Content-Type-Options header not set"},
	}	
```

- This doesn't use regex on every line, instead checking "main" application files to see if keywords are absent from the file entirely.

---

### C9. Permissive CORS

A CORS policy set to `*` allows any website on the internet to make requests to your API and read the responses.

**Pattern:**
```
`(?i)(` +
`Access-Control-Allow-Origin['":\s]+\*|` +
`cors\s*\(\s*\{[^}]*origin[^}]*\*|` +
`CORS_ORIGIN_ALLOW_ALL\s*=\s*True|` +
`CORS_ALLOWED_ORIGINS\s*=\s*\[["']\*|` +
`allow_origins\s*=\s*\[["']\*["']\]` +
`)`
```

- Identifies configuration where the "Origin" is set to a wildcard `*`, or flags like `CORS_ORIGIN_ALLOW_ALL` are set to `True`.
