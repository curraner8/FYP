package detectors

import (
	"FYP/backend/models"
	"path/filepath"
	"regexp"
	"strings"
)

type ClassCDetector struct {
	BaseDetector
	rules []PatternRule
}

func NewClassCDetector() *ClassCDetector {
	return &ClassCDetector{
		BaseDetector: BaseDetector{
			class:       "C",
			name:        "Configuration Issues",
			description: "Detects insecure configuration and missing security headers",
		},
		rules: []PatternRule{
			// Debug Mode
			{
				ID:          "C1",
				Type:        "DEBUG_MODE_ENABLED",
				Severity:    "high",
				Description: "Debug mode enabled in production",
				Pattern: regexp.MustCompile(`(?i)(` +
					`FLASK_ENV\s*=\s*["']development["']|` +
					`NODE_ENV\s*=\s*["']development["']|` +
					`enable_debug\s*\(\s*true\s*\)` +
					`)`),
				Recommendation: "Set DEBUG to false in production; use environment variables",
				Score:          -18,
			},
			// Insecure Protocol
			{
				ID:          "C2",
				Type:        "INSECURE_PROTOCOL",
				Severity:    "high",
				Description: "SSL/TLS verification disabled or insecure protocol configuration",
				Pattern: regexp.MustCompile(`(?i)(` +
					`verify\s*=\s*(False|false)|` +
					`ssl\s*=\s*(False|false|0)|` +
					`rejectUnauthorized\s*:\s*false|` +
					`InsecureSkipVerify\s*:\s*true|` +
					`DISABLE_SSL\s*=\s*(true|True|1)` +
					`)`),
				Recommendation: "Never disable SSL/TLS certificate verification in production. Use valid certificates and enforce HTTPS.",
				Score:          -19,
			},
			// Directory Listing
			{
				ID:          "C4",
				Type:        "DIRECTORY_LISTING",
				Severity:    "high",
				Description: "Directory listing enabled",
				Pattern: regexp.MustCompile(`(?i)(` +
					`Options\s+(\+\s*)?Indexes|` +
					`autoindex\s+on\s*;|` +
					`directory_listing\s*[=:]\s*(true|on)|` +
					`serveIndex\s*\(|` +
					`http\.FileServer\s*\(|` +
					`StaticFiles\s*\([^)]*html_dir` +
					`)`),
				Recommendation: "Disable directory listing",
				Score:          -15,
			},
			// Error page info leak
			{
				ID:          "C5",
				Type:        "VERBOSE_ERROR",
				Severity:    "medium",
				Description: "Verbose error messages enabled",
				Pattern: regexp.MustCompile(`(?i)(` +
					`app\.use\s*\(\s*errorhandler|` +
					`DEBUG_PROPAGATE_EXCEPTIONS\s*=\s*True|` +
					`PROPAGATE_EXCEPTIONS\s*=\s*True|` +
					`app\.run\s*\([^)]*debug\s*=\s*True` +
					`)`),
				Recommendation: "Use generic error pages; log details server-side only",
				Score:          -6,
			},
			// Config file secrects
			{
				ID:          "C6",
				Type:        "CONFIG_SECRETS",
				Severity:    "critical",
				Description: "Secrets in configuration files",
				Pattern: regexp.MustCompile(`(?i)(` +
					`(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*["'][^"']{4,}["']|` +
					`(SECRET_KEY|APP_SECRET|JWT_SECRET|FLASK_SECRET)\s*=\s*["'][^"']{4,}["']|` +
					`(AWS_SECRET|AZURE_CLIENT_SECRET|GCP_API_KEY)\s*=\s*["'][^"']{4,}["']|` +
					`(STRIPE_SECRET|SENDGRID_API_KEY|TWILIO_AUTH)\s*=\s*["'][^"']{4,}["']` +
					`)`),
				Recommendation: "Use environment variables or secret management systems",
				Score:          -28,
			},
			// Insecure environment variables
			{
				ID:          "C7",
				Type:        "EXPOSED_ENV_VAR",
				Severity:    "high",
				Description: "Secrets assigned to env variable in source code or Dockerfile",
				Pattern: regexp.MustCompile(`(?i)(` +
					`^\s*export\s+(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|AWS_SECRET)[^=]*=.+|` +
					`ENV\s+(SECRET|TOKEN|PASSWORD|API_KEY)[^=\n]*=\s*\S+|` +
					`os\.environ\s*\[\s*["'](SECRET|TOKEN|PASSWORD|API_KEY)["']\s*\]\s*=\s*["'][^"']{4,}["']` +
					`)`),
				Recommendation: "Load secrets at runtime from secure storage; never export in scripts or Dockerfiles",
				Score:          -18,
			},
			// Missing security headers
			// {
			// 	ID:             "C8",
			// 	Type:           "MISSING_SECURITY_HEADERS",
			// 	Severity:       "medium",
			// 	Description:    "Security headers not configured",
			// 	Pattern:        regexp.MustCompile(`(?i)(app\.use\s*\(\s*helmet|app\.use\s*\(\s*security|header\s*\(\s*["']X-Frame-Options|Content-Security-Policy)`),
			// 	Recommendation: "Implement CSP, X-Frame-Options, X-Content-Type-Options, HSTS headers",
			// 	Score:          -10,
			// },
			// Permissive CORS
			{
				ID:          "C9",
				Type:        "PERMISSIVE_CORS",
				Severity:    "medium",
				Description: "Overly permissive CORS policy",
				Pattern: regexp.MustCompile(`(?i)(` +
					`Access-Control-Allow-Origin['":\s]+\*|` +
					`cors\s*\(\s*\{[^}]*origin[^}]*\*|` +
					`CORS_ORIGIN_ALLOW_ALL\s*=\s*True|` +
					`CORS_ALLOWED_ORIGINS\s*=\s*\[["']\*|` +
					`allow_origins\s*=\s*\[["']\*["']\]` +
					`)`),
				Recommendation: "Restrict CORS to specific trusted domains",
				Score:          -12,
			},
		},
	}
}

func (d *ClassCDetector) Detect(filename, content string) []models.Finding {
	var findings []models.Finding
	lines := getLines(content)

	for _, rule := range d.rules {
		for lineNum, line := range lines {
			if rule.Pattern.MatchString(line) {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 100 {
					snippet = snippet[:100] + "..."
				}

				findings = append(findings, models.Finding{
					ID:             rule.ID,
					Class:          d.class,
					Type:           rule.Type,
					Description:    rule.Description,
					Line:           lineNum + 1,
					Snippet:        snippet,
					Recommendation: rule.Recommendation,
					Severity:       rule.Severity,
					Confidence:     "high",
					ScoreImpact:    rule.Score,
				})
			}
		}
	}

	// C3: Insecure Cookies check
	findings = append(findings, d.checkInsecureCookies(lines)...)

	// C8: Missing Security Headers check
	findings = append(findings, d.checkMissingSecurityHeaders(filename, content)...)

	return findings
}

// detects cookie declarations that are missing the security flags
func (d *ClassCDetector) checkInsecureCookies(lines []string) []models.Finding {
	var findings []models.Finding

	cookiePattern := regexp.MustCompile(`(?i)(res\.cookie|Set-Cookie|set_cookie|response\.set_cookie|setcookie)\s*[\(:]`)

	for lineNum, line := range lines {
		if cookiePattern.MatchString(line) {
			lower := strings.ToLower(line)
			missingFlags := []string{}

			if !strings.Contains(lower, "httponly") {
				missingFlags = append(missingFlags, "HttpOnly")
			}
			if !strings.Contains(lower, "secure") {
				missingFlags = append(missingFlags, "Secure")
			}
			if !strings.Contains(lower, "samesite") {
				missingFlags = append(missingFlags, "SameSite")
			}

			if len(missingFlags) > 0 {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 100 {
					snippet = snippet[:100] + "..."
				}
				findings = append(findings, models.Finding{
					ID:             "C3",
					Class:          d.class,
					Type:           "INSECURE_COOKIE",
					Description:    "Cookie set without security flags: " + strings.Join(missingFlags, ", "),
					Line:           lineNum + 1,
					Snippet:        snippet,
					Recommendation: "Add HttpOnly, Secure, and SameSite=Strict flags to all cookies. HttpOnly prevents JavaScript access, Secure enforces HTTPS, SameSite prevents CSRF.",
					Severity:       "high",
					Confidence:     "high",
					ScoreImpact:    -17,
				})
			}
		}
	}

	return findings
}

// detects main application files that are missing key security headers
func (d *ClassCDetector) checkMissingSecurityHeaders(filename, content string) []models.Finding {
	var findings []models.Finding

	base := filepath.Base(filename)
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

	if !mainAppFiles[base] {
		return findings
	}

	// each entry is the string to look for and the description if absent
	securityHeaders := []struct {
		keyword     string
		description string
	}{
		{"helmet", "Helmet.js middleware not found"},
		{"X-Frame-Options", "X-Frame-Options header not set"},
		{"Content-Security-Policy", "Content-Security-Policy header not set"},
		{"X-Content-Type-Options", "X-Content-Type-Options header not set"},
	}

	for _, header := range securityHeaders {
		if !strings.Contains(content, header.keyword) {
			findings = append(findings, models.Finding{
				ID:             "C8",
				Class:          d.class,
				Type:           "MISSING_SECURITY_HEADERS",
				Description:    header.description,
				Line:           1,
				Snippet:        base,
				Recommendation: "Configure security headers.",
				Severity:       "medium",
				Confidence:     "medium",
				ScoreImpact:    -10,
			})
		}
	}

	return findings
}
