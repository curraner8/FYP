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

// used by D1 for checks in Detect
var routePattern = regexp.MustCompile(`(?i)(` +
	`@app\.route\s*\([^)]+\)|` +
	`@router\.(get|post|put|delete)\s*\(|` +
	`router\.(get|post|put|delete)\s*\(|` +
	`app\.(get|post|put|delete)\s*\(` +
	`)`)

// used by D4 to identify POST endpoints
var postRoutePattern = regexp.MustCompile(`(?i)(` +
	`@app\.route\s*\([^)]*methods\s*=\s*\[[^\]]*POST|` +
	`router\.post\s*\(|` +
	`app\.post\s*\(` +
	`)`)

func NewClassDDetector() *ClassDDetector {
	return &ClassDDetector{
		BaseDetector: BaseDetector{
			class:       "D",
			name:        "Heuristic Detection",
			description: "Detects potential issues requiring manual review",
		},
		rules: []PatternRule{
			// IDOR Pattern
			{
				ID:          "D2",
				Type:        "IDOR_PATTERN",
				Severity:    "high",
				Description: "Direct object reference without ownership check",
				Pattern: regexp.MustCompile(`(?i)(` +
					`WHERE\s+(id|user_id|account_id|order_id)\s*=\s*(request|params|req\.|input|body|args)|` +
					`\.get\s*\([^)]*request\.(GET|POST)|` +
					`Model\.(find|findOne|findById)\s*\([^)]*req\.(params|body|query)|` +
					`objects\.get\s*\(id\s*=\s*(request|params)` +
					`)`),
				Recommendation: "MANUAL REVIEW: Verify the user owns the resource before accessing",
				Score:          -15,
			},
			// Sensitive Route Exposed
			{
				ID:          "D3",
				Type:        "SENSITIVE_ROUTE_EXPOSED",
				Severity:    "medium",
				Description: "Sensitive endpoint path may lack access control",
				Pattern: regexp.MustCompile(`(?i)(` +
					`["'](/admin|/internal|/debug|/test|/backup|/config|/console|/actuator|/swagger)` +
					`)`),
				Recommendation: "MANUAL REVIEW: Ensure sensitive routes require authentication and authorisation. /actuator, /swagger, and /console should never be publicly accessible in production.",
				Score:          -8,
			},
			// Open redirect
			{
				ID:          "D5",
				Type:        "OPEN_REDIRECT",
				Severity:    "medium",
				Description: "Potential open redirect",
				Pattern: regexp.MustCompile(`(?i)(` +
					`res\.redirect\s*\([^)]*req\.(query|params|body)|` +
					`redirect\s*\([^)]*request\.(args|form|values)|` +
					`http\.Redirect\s*\([^)]*r\.(URL|FormValue|Header)|` +
					`location\.href\s*=.*?(request|params|query|url|next)|` +
					`window\.location\s*=.*?(request|params|query|url|next)` +
					`)`),
				Recommendation: "MANUAL REVIEW: Validate redirect URLs against whitelist",
				Score:          -7,
			},
			// SSRF Indicator
			{
				ID:          "D6",
				Type:        "SSRF_RISK",
				Severity:    "high",
				Description: "Server-side request with user-controlled URL or host",
				Pattern: regexp.MustCompile(`(?i)(` +
					`requests\.(get|post|put|delete)\s*\(|` +
					`urllib\.request\.(urlopen|Request)\s*\(|` +
					`http\.(get|post|request)\s*\(|` +
					`fetch\s*\(|` +
					`axios\.(get|post|put|delete)\s*\(|` +
					`new\s+URL\s*\(|` +
					`HttpClient|WebClient|RestTemplate` +
					`).{0,200}?(` +
					`request\.|req\.|params|input|url|target|endpoint|host|domain` +
					`)`),
				Recommendation: "MANUAL REVIEW: Validate URL scheme and host; block internal IP ranges",
				Score:          -16,
			},
			// Client-side security
			{
				ID:          "D7",
				Type:        "CLIENT_SIDE_SECURITY",
				Severity:    "high",
				Description: "Security enforcement appears to be client-side only",
				Pattern: regexp.MustCompile(`(?i)(` +
					`(disabled|hidden|readOnly)\s*=\s*\{[^}]*(role|admin|permission|isAdmin)|` +
					`v-if\s*=\s*["'][^"']*(role|admin|permission)|` +
					`\*ngIf\s*=\s*["'][^"']*(role|admin|isAdmin)` +
					`)`),
				Recommendation: "MANUAL REVIEW: Client-side security checks are bypassable by any user with browser dev tools. All authorisation checks must be enforced server-side.",
				Score:          -12,
			},
			// Sensitive data in GET
			{
				ID:          "D8",
				Type:        "SENSITIVE_IN_GET",
				Severity:    "medium",
				Description: "Sensitive data in GET request",
				Pattern: regexp.MustCompile(`(?i)(` +
					`(\?|&)(password|token|secret|api_key|api-key|credit_card|ssn|cvv)=|` +
					`params\s*=\s*\{[^}]*(password|token|secret)[^}]*\}.*?(get|GET)|` +
					`requests\.get\s*\([^)]*params\s*=\s*\{[^}]*(password|token|secret)` +
					`)`),
				Recommendation: "Use POST requests with body for sensitive data",
				Score:          -6,
			},
			// Direct user ID usage
			{
				ID:          "D9",
				Type:        "DIRECT_USER_ID",
				Severity:    "high",
				Description: "User ID from request used directly in query",
				Pattern: regexp.MustCompile(`(?i)(user_id|account_id|owner_id|userId|accountId)\s*=\s*(` +
					`(request|params|req|args|input|body)\s*[\[.]|` +
					`request\.(GET|POST|args|form)\.get\s*\([^)]*user_id|` +
					`req\.(params|body|query)\.(user_id|userId|account_id)` +
					`)`),
				Recommendation: "MANUAL REVIEW: Use session-derived user id instead of request params",
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

	// D1: Missing Auth Check
	findings = append(findings, d.checkMissingAuth(lines)...)

	// D4: CSRF Risk Check
	findings = append(findings, d.checkCSRFRisk(lines)...)

	return findings
}

// detects route definitions that have no visible auth keywords in the surrounding 5 lines on each side of the route declaration
func (d *ClassDDetector) checkMissingAuth(lines []string) []models.Finding {
	var findings []models.Finding

	authKeywords := []string{
		"login_required", "jwt_required", "authenticate",
		"authorize", "permission", "middleware", "guard",
		"auth", "token", "bearer", "session",
	}

	for lineNum, line := range lines {
		if !routePattern.MatchString(line) {
			continue
		}

		// check the 5 lines before and after for auth keywords
		start := lineNum - 5
		if start < 0 {
			start = 0
		}
		end := lineNum + 5
		if end >= len(lines) {
			end = len(lines) - 1
		}

		context := strings.ToLower(strings.Join(lines[start:end], "\n"))

		hasAuth := false
		for _, keyword := range authKeywords {
			if strings.Contains(context, keyword) {
				hasAuth = true
				break
			}
		}

		if !hasAuth {
			snippet := strings.TrimSpace(line)
			if len(snippet) > 100 {
				snippet = snippet[:100] + "..."
			}
			findings = append(findings, models.Finding{
				ID:             "D1",
				Class:          d.class,
				Type:           "MISSING_AUTHORIZATION",
				Description:    "Route definition with no visible authentication keyword in surrounding context",
				Line:           lineNum + 1,
				Snippet:        snippet,
				Recommendation: "MANUAL REVIEW: Verify authentication middleware is applied to this route.",
				Severity:       "high",
				Confidence:     "medium",
				ScoreImpact:    -10,
			})
		}
	}

	return findings
}

// detect POST route definitions with no CSRF protection keywords visible
func (d *ClassDDetector) checkCSRFRisk(lines []string) []models.Finding {
	var findings []models.Finding

	csrfKeywords := []string{
		"csrf", "csrf_token", "_csrf", "csrfprotection",
		"csurf", "csrf_exempt", "samesite",
	}

	for lineNum, line := range lines {
		if !postRoutePattern.MatchString(line) {
			continue
		}

		// check lines before and after for CSRF keywords
		// 10 lines because middleware could be a few more lines away from route definition
		start := lineNum - 10
		if start < 0 {
			start = 0
		}
		end := lineNum + 10
		if end >= len(lines) {
			end = len(lines) - 1
		}

		context := strings.ToLower(strings.Join(lines[start:end], "\n"))

		hasCSRF := false
		for _, keyword := range csrfKeywords {
			if strings.Contains(context, keyword) {
				hasCSRF = true
				break
			}
		}

		if !hasCSRF {
			snippet := strings.TrimSpace(line)
			if len(snippet) > 100 {
				snippet = snippet[:100] + "..."
			}
			findings = append(findings, models.Finding{
				ID:             "D4",
				Class:          d.class,
				Type:           "CSRF_RISK",
				Description:    "POST endpoint with no visible CSRF protection in surrounding context",
				Line:           lineNum + 1,
				Snippet:        snippet,
				Recommendation: "MANUAL REVIEW: Verify CSRF token validation is applied to this endpoint.",
				Severity:       "high",
				Confidence:     "medium",
				ScoreImpact:    -10,
			})
		}
	}

	return findings
}
