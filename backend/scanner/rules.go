package scanner

import (
	"regexp"
)

type Rule struct {
	ID             string
	Type           string
	Severity       string
	Description    string
	Pattern        *regexp.Regexp
	Recommendation string
}

var Rules = []Rule{
	{
		ID:             "S001",
		Type:           "SQL_INJECTION",
		Severity:       "critical",
		Description:    "Potential SQL injection vulnerability",
		Pattern:        regexp.MustCompile(`(?i)(SELECT|UPDATE|DELETE|INSERT).*['"].*\+.*['"]`),
		Recommendation: "Use parameterized queries or ORM query binding.",
	},
	{
		ID:             "X001",
		Type:           "XSS",
		Severity:       "medium",
		Description:    "Potential XSS vulnerability",
		Pattern:        regexp.MustCompile(`(?i)(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|eval\()`),
		Recommendation: "Sanitize user input before rendering in HTML.",
	},
	{
		ID:             "H001",
		Type:           "HARD_CODED_SECRET",
		Severity:       "critical",
		Description:    "Hard-coded secret detected",
		Pattern:        regexp.MustCompile(`(?i)(api_key|apikey|secret|password|passwd|aws_access_key_id|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['""][A-Za-z0-9\-_]{8,}['"]`),
		Recommendation: "Store secrets in environment variables or secure vault.",
	},
}
