package detectors

import (
	"FYP/backend/models"
	"regexp"
	"strings"
)

type ClassDDetector struct {
	BaseDetector
	rules []PatternRule
}

func NewClassDDetector() *ClassDDetector {
	return &ClassDDetector{
		BaseDetector: BaseDetector{
			class:       "D",
			name:        "Heuristic Detection",
			description: "Detects potential issues requiring manual review",
		},
		rules: []PatternRule{
			// Missing Auth Check
			// ****CAUSES ERROR****
			// {
			// 	ID:             "D1",
			// 	Type:           "MISSING_AUTHORIZATION",
			// 	Severity:       "high",
			// 	Description:    "Rout without explicit aithorization check",
			// 	Pattern:        regexp.MustCompile(`(?i)(@app\.route|router\.(get|post|put|delete)|app\.(get|post|put|delete)|server\.(get|post)).{0,100}(?![\s\S]{0,500}?(login_required|auth|authorize|permission|jwt|verify|check.*auth|require.*auth))`),
			// 	Recommendation: "Add authentication middleware",
			// 	Score:          -18,
			// },
			// IDOR Pattern
			{
				ID:             "D2",
				Type:           "IDOR_PATTERN",
				Severity:       "high",
				Description:    "Direct object reference without ownership check",
				Pattern:        regexp.MustCompile(`(?i)(WHERE\s+(id|user_id|account_id|order_id)\s*=\s*(request|params|req\.|input|body|args))`),
				Recommendation: "Verify the user owns the resource before accessing",
				Score:          -15,
			},
			// Forced Browsing
			// ****CAUSES ERROR****
			// {
			// 	ID:             "D3",
			// 	Type:           "SENSITIVE_ROUTE_EXPOSED",
			// 	Severity:       "medium",
			// 	Description:    "Sensitive endpoint may lack protection",
			// 	Pattern:        regexp.MustCompile(`(?i)(@app\.route|router\.|app\.(get|post)).*(admin|internal|debug|test|backup|config|secret|api/v[0-9]+)`),
			// 	Recommendation: "Verify authentication and authorization on sensitive routes",
			// 	Score:          -12,
			// },
			// CSRF risk
			// ****CAUSES ERROR****
			// {
			// 	ID:             "D4",
			// 	Type:           "CSRF_RISK",
			// 	Severity:       "high",
			// 	Description:    "State-changing operation without CSRF protection",
			// 	Pattern:        regexp.MustCompile(`(?i)(@app\.route.*methods.*POST|router\.post|app\.post).{0,200}(?![\s\S]{0,200}?(csrf|csrf_token|csrf_exempt|sameSite|_csrf))`),
			// 	Recommendation: "Add CSRF tokens",
			// 	Score:          -16,
			// },
			// Open redirect
			{
				ID:             "D5",
				Type:           "OPEN_REDIRECT",
				Severity:       "medium",
				Description:    "Potential open redirect",
				Pattern:        regexp.MustCompile(`(?i)(redirect|res\.redirect|location\.href|window\.location).*\(.*(request|params|req\.|query|input|next|url|return_url)`),
				Recommendation: "Validate redirect URLs against whitelist",
				Score:          -7,
			},
			// SSRF Indicator
			{
				ID:             "D6",
				Type:           "SSRF_RISK",
				Severity:       "high",
				Description:    "Server-side request with user-controlled URL",
				Pattern:        regexp.MustCompile(`(?i)(requests\.(get|post)|http\.(get|request)|fetch|axios\.(get|post)|urllib\.request).*\(.*(request|params|req\.|input|url|target|endpoint)`),
				Recommendation: "Validate URL scheme and host; block internal IP ranges",
				Score:          -16,
			},
			// Client-side security
			// ****CAUSES ERROR****
			// {
			// 	ID:             "D7",
			// 	Type:           "CLIENT_SIDE_SECURITY",
			// 	Severity:       "high",
			// 	Description:    "Security check performed client-side only",
			// 	Pattern:        regexp.MustCompile(`(?i)(if\s*\(.*(role|admin|permission|auth).*\)|disabled\s*=\s*{(?!.*server).*|hidden\s*=\s*{).*(show|display|enable|render|visible)`),
			// 	Recommendation: "Move all security checks to server-side; client-side is bypassable",
			// 	Score:          -18,
			// },
			// Sensitive data in GET
			{
				ID:             "D8",
				Type:           "SENSITIVE_IN_GET",
				Severity:       "medium",
				Description:    "Sensitive data in GET request",
				Pattern:        regexp.MustCompile(`(?i)(\?|&)(password|token|secret|api_key|credit_card|ssn)=`),
				Recommendation: "Use POST requests with body for sensitive data",
				Score:          -6,
			},
			// Direct user ID usage
			{
				ID:             "D9",
				Type:           "DIRECT_USER_ID",
				Severity:       "high",
				Description:    "User ID from request used directly in query",
				Pattern:        regexp.MustCompile(`(?i)(user_id|account_id|owner_id)\s*=\s*(request|params|req\.|args|input|body)\[`),
				Recommendation: "Use session-derived user_id instead of request params",
				Score:          -15,
			},
		},
	}
}

func (d *ClassDDetector) Detect(filename, content string) []models.Finding {
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
					Confidence:     "medium", // lower for heuristics
					ScoreImpact:    rule.Score,
				})
			}
		}
	}

	return findings
}
