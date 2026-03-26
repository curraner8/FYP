package detectors

import (
	"FYP/backend/models"
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
				ID:             "C1",
				Type:           "DEBUG_MODE_ENABLED",
				Severity:       "high",
				Description:    "Debug mode enabled in production",
				Pattern:        regexp.MustCompile(`(?i)(DEBUG\s*=\s*True|debug\s*:\s*true|app\.debug\s*=\s*true|APP_DEBUG\s*=\s*true|enable_debug\s*\(\s*true\s*\))`),
				Recommendation: "Set DEBUG to false in production; use environment variables",
				Score:          -18,
			},
			// Missing HTTPS
			// ****CAUSES ERROR****
			// {
			// 	ID:             "C2",
			// 	Type:           "INSECURE_PROTOCOL",
			// 	Severity:       "high",
			// 	Description:    "HTTP used instead of HTTPS",
			// 	Pattern:        regexp.MustCompile(`(?i)(http://(?!localhost|127\.0\.0\.1)|ssl\s*=\s*False|verify\s*=\s*False|rejectUnauthorized\s*:\s*false)`),
			// 	Recommendation: "Enforce HTTPS; set ssl to true and verify certificate",
			// 	Score:          -19,
			// },
			// Insecure Cookies
			// ****CAUSES ERROR****
			// {
			// 	ID:             "C3",
			// 	Type:           "INSECURE_COOKIE",
			// 	Severity:       "high",
			// 	Description:    "Cookie missing security flags",
			// 	Pattern:        regexp.MustCompile(`(?i)(Set-Cookie|res\.cookie|response\.setCookie).*(?![\s\S]*?(HttpOnly))(?![\s\S]*?(Secure))`),
			// 	Recommendation: "Add HttpOnly, Secure, and SameSite=Strict flags to cookies",
			// 	Score:          -17,
			// },
			// Directory Listing
			{
				ID:             "C4",
				Type:           "DIRECTORY_LISTING",
				Severity:       "high",
				Description:    "Directory listing enabled",
				Pattern:        regexp.MustCompile(`(?i)(Options\s+Indexes|autoindex\s+on|directory_listing\s+true)`),
				Recommendation: "Disable directory listing",
				Score:          -15,
			},
			// Error page info leak
			{
				ID:             "C5",
				Type:           "VERBOSE_ERROR",
				Severity:       "medium",
				Description:    "Verbose error messages enabled",
				Pattern:        regexp.MustCompile(`(?i)(app\.use\s*\(\s*errorhandler|error_reporting\s*\(\s*E_ALL|display_errors\s*=\s*On|app\.config\['DEBUG'\]\s*=\s*True)`),
				Recommendation: "Use generic error pages; log details server-side only",
				Score:          -6,
			},
			// Config file secrects
			{
				ID:             "C6",
				Type:           "CONFIG_SECRETS",
				Severity:       "critical",
				Description:    "Secrets in configuration files",
				Pattern:        regexp.MustCompile(`(?i)(config|settings|\.env|\.ini|\.conf).*(password|secret|key|token)\s*[:=]\s*["'][^"']+["']`),
				Recommendation: "Use environment variables or secret management systems",
				Score:          -28,
			},
			// Insecure environment variables
			{
				ID:             "C7",
				Type:           "EXPOSED_ENV_VAR",
				Severity:       "high",
				Description:    "Secrets exported in shell scripts",
				Pattern:        regexp.MustCompile(`(?i)^\s*export\s+(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|AWS_SECRET)`),
				Recommendation: "Load secrets at runtime from secure storage; never export in scripts",
				Score:          -18,
			},
			// Missing security headers
			{
				ID:             "C8",
				Type:           "MISSING_SECURITY_HEADERS",
				Severity:       "medium",
				Description:    "Security headers not configured",
				Pattern:        regexp.MustCompile(`(?i)(app\.use\s*\(\s*helmet|app\.use\s*\(\s*security|header\s*\(\s*["']X-Frame-Options|Content-Security-Policy)`),
				Recommendation: "Implement CSP, X-Frame-Options, X-Content-Type-Options, HSTS headers",
				Score:          -10,
			},
			// CORS wildcard
			{
				ID:             "C9",
				Type:           "PERMISSIVE_CORS",
				Severity:       "medium",
				Description:    "Overly permissive CORS policy",
				Pattern:        regexp.MustCompile(`(?i)(Access-Control-Allow-Origin.*\*|cors\s*\(\s*\{.*origin.*\*|res\.header\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\s*\))`),
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

	return findings
}
