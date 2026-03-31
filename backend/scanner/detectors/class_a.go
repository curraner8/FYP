package detectors

import (
	"FYP/backend/models"
	"regexp"
	"strings"
)

type ClassADetector struct {
	BaseDetector
	rules []PatternRule
}

func NewClassADetector() *ClassADetector {
	return &ClassADetector{
		BaseDetector: BaseDetector{
			class:       "A",
			name:        "Direct Static Pattern",
			description: "Detects direct dangerous static patterns.",
		},
		rules: []PatternRule{
			// SQL Injection
			{
				ID:          "A1",
				Type:        "SQL_INJECTION",
				Severity:    "critical",
				Description: "SQL injection via string concatenation/format",
				// Pattern:        regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE).*(%s|%d|\+)`),
				Pattern:        regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE).*(['"]).*(%|\.format\(|\+|f['"])`),
				Recommendation: "Use parameterized queries",
				Score:          -30,
			},
			// XSS (all variants)
			{
				ID:             "A2",
				Type:           "XSS",
				Severity:       "high",
				Description:    "XSS via unsafe DOM manipulation",
				Pattern:        regexp.MustCompile(`(?i)(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|eval\(|setAttribute.*href).*(request|input|params|user|req\.|query)`),
				Recommendation: "Use textContent instead of innerHTML, or sanitize.",
				Score:          -19,
			},
			// Command Injection
			{
				ID:          "A3",
				Type:        "COMMAND_INJECTION",
				Severity:    "critical",
				Description: "Command injection via shell execution",
				// Pattern:        regexp.MustCompile(`(?i)(os\.system|subprocess\.call|subprocess\.run|exec|popen|Runtime\.exec|ProcessBuilder).*[\+|%s].*(request|input|params|args|req\.|user)`),
				Pattern:        regexp.MustCompile(`(?is)(os\.system|subprocess\.call|subprocess\.run|exec|popen|Runtime\.exec|ProcessBuilder).*[\+|%s].*(request|input|params|args|req\.|user)`),
				Recommendation: "Use subprocess.run(['cmd', 'arg'], shell=False) with argument list",
				Score:          -28,
			},
			// LDAP Injection
			{
				ID:          "A4",
				Type:        "LDAP_INJECTION",
				Severity:    "high",
				Description: "LDAP injection via string concatenation",
				// Pattern:        regexp.MustCompile(`(?i)(ldap|LDAP).*[\+|%s].*(request|input|params|user|req\.|username)`),
				Pattern:        regexp.MustCompile(`(?i)\((uid|cn|mail|userpassword)[^)]*\+[^)]*(request|input|params|user|username)`),
				Recommendation: "Use parameterized LDAP queries and escape special characters",
				Score:          -17,
			},
			// XPath Injection
			{
				ID:          "A5",
				Type:        "XPATH_INJECTION",
				Severity:    "high",
				Description: "XPath injection via string concatenation",
				// Pattern:        regexp.MustCompile(`(?i)(xpath|selectNodes|evaluate|selectSingleNode).*[\+|%s|'"].*(request|input|params|user|req\.)`),
				// Pattern:        regexp.MustCompile(`(?is)(xpath|selectNodes|evaluate|selectSingleNode).*?(\+|%s|['"]).*?(request|input|params|user|req\.)`),
				Pattern:        regexp.MustCompile(`(?is)(["'].*\+.*(request|input|params|user|req\.|body|data).*["']|xpath\.(evaluate|selectNodes|selectSingleNode|compile))`),
				Recommendation: "Use parameterized XPath queries or XPath variable bindings",
				Score:          -16,
			},
			// CRLF Injection
			{
				ID:          "A6",
				Type:        "CRLF_INJECTION",
				Severity:    "high",
				Description: "CRLF injection in HTTP headers",
				// Pattern:        regexp.MustCompile(`(?i)(setHeader|addHeader|writeHead).*[\+|%s].*(request|input|params|user|req\.)`),
				Pattern:        regexp.MustCompile(`(?is)(setHeader|addHeader|writeHead).*?(\+|%s).*?(request|input|params|user|req\.)`),
				Recommendation: "Strip '\\r\\n' characters and validate header values",
				Score:          -15,
			},
			// Eval Injection
			{
				ID:             "A7",
				Type:           "EVAL_INJECTION",
				Severity:       "critical",
				Description:    "Dangerous use of eval() with user input",
				Pattern:        regexp.MustCompile(`(?i)\beval\s*\(.*(request|input|params|user|req\.|data|body)`),
				Recommendation: "Remove eval() entirely and use JSON.parse or structured logic",
				Score:          -30,
			},
			// Static Code Injection
			{
				ID:          "A8",
				Type:        "STATIC_CODE_INJECTION",
				Severity:    "critical",
				Description: "Dynamic code inclusion with user input",
				// Pattern:        regexp.MustCompile(`(?i)(include|require|require_once|import|importlib|load|include_once).*\$_(GET|POST|REQUEST|input|params|req\.)`),
				Pattern:        regexp.MustCompile(`(?is)(include|require|require_once|include_once|import|importlib\.import_module|load|System\.load|Class\.forName|Runtime\.exec)\s*\(?.*(request|input|params|user|req\.|body|data|\$_(GET|POST|REQUEST))`),
				Recommendation: "Use strict whitelisting of allowed modules and files",
				Score:          -26,
			},
			// PHP RFI
			{
				ID:             "A9",
				Type:           "REMOTE_FILE_INCLUSION",
				Severity:       "critical",
				Description:    "Remote file inclusion detected",
				Pattern:        regexp.MustCompile(`(?i)(include|require).*(http://|https://|ftp://)`),
				Recommendation: "Use local files only",
				Score:          -25,
			},
			// Path Traversal
			{
				ID:          "A10",
				Type:        "PATH_TRAVERSAL",
				Severity:    "high",
				Description: "Path traversal vulnerability",
				//Pattern:        regexp.MustCompile(`(?i)(open|readFile|sendFile|createReadStream|cat|type).*(\+|%s).*(\.\./|\.\.\\|/\.\.|\\\.\.)`),
				Pattern:        regexp.MustCompile(`(?is)(open|readFile|sendFile|createReadStream|cat|type)\s*\(?.*(\+|%s)?.*(\.\./|\.\.\\|/\.\.|\\\.\.|request|input|params|user|req\.)`),
				Recommendation: "Normalize paths and validate input",
				Score:          -18,
			},
			// Hardcoded Credentials
			{
				ID:             "A11",
				Type:           "HARDCODED_CREDENTIALS",
				Severity:       "high",
				Description:    "Hardcoded credentials in source code",
				Pattern:        regexp.MustCompile(`(?i)(password|passwd|secret|api_key|apikey|token|auth_token|aws_access_key_id|aws_secret_access_key|private_key)\s*[:=]\s*["'][^"']{4,}["']`),
				Recommendation: "Use environment variables or secret management",
				Score:          -16,
			},
			// Sensitive Info in Comments
			{
				ID:             "A12",
				Type:           "SENSITIVE_COMMENT",
				Severity:       "medium",
				Description:    "Sensitive information disclosed in comments",
				Pattern:        regexp.MustCompile(`(?i)(//|#|/\*|\*).*?(password|secret|key|token|todo|fixme|hack|bypass|backdoor|admin|root)`),
				Recommendation: "Remove sensitive information from comments before committing",
				Score:          -8,
			},
			// Debug Code Enabled
			{
				ID:          "A13",
				Type:        "DEBUG_ENABLED",
				Severity:    "medium",
				Description: "Debug mode or code left enabled",
				// Pattern:        regexp.MustCompile(`(?i)(DEBUG\s*=\s*True|debug\s*=\s*true|app\.debug\s*=\s*true|console\.log\(|printStackTrace|debugger;)`),
				Pattern:        regexp.MustCompile(`(?i)(\b\w*debug\w*\b\s*(:=|=)\s*true|console\.log\s*\(|fmt\.Println\s*\(|printStackTrace\s*\(|debugger;)`),
				Recommendation: "Disable debug mode in production. Remove console.log statements",
				Score:          -9,
			},
			// Logging Secrets
			{
				ID:          "A14",
				Type:        "LOGGED_SECRETS",
				Severity:    "high",
				Description: "Sensitive information logged",
				// Pattern:        regexp.MustCompile(`(?i)(log|logger|console\.log|print|printf|syslog).*(password|secret|token|key|credential|auth)`),
				Pattern:        regexp.MustCompile(`(?i)(\b(log|logger|console\.log|print|printf|syslog)\b).*?(password|secret|token|api[_-]?key|auth[_-]?token|credential)`),
				Recommendation: "Log identifiers only, Never credentials or secrets",
				Score:          -15,
			},
			// Stack Traces Exposed
			{
				ID:          "A15",
				Type:        "STACK_TRACE_EXPOSED",
				Severity:    "medium",
				Description: "Stack trace printing in production code",
				// Pattern:        regexp.MustCompile(`(?i)(printStackTrace|traceback\.print_exc|traceback\.format_exc|console\.error\(.*error.*stack)`),
				Pattern:        regexp.MustCompile(`(?is)(printStackTrace|traceback\.print_exc|traceback\.format_exc|console\.error\s*\(.*?stack|error\.stack)`),
				Recommendation: "Use generic error messages and log details server-side only",
				Score:          -10,
			},
			// Null Pointer Risk (limited detection)
			// {
			// 	ID:             "A16",
			// 	Type:           "NULL_POINTER_RISK",
			// 	Severity:       "low",
			// 	Description:    "Potential null pointer dereference",
			// 	Pattern:        regexp.MustCompile(`(?i)(\.[a-zA-Z_]+\(\))(?![\s\S]*?(if\s*\(|!=\s*null|!==\s*null|is\s+not\s+None|is\s+None))`),
			// 	Recommendation: "Add null checks before method invocation",
			// 	Score:          -5,
			// },
		},
	}
}

func (d *ClassADetector) Detect(filename, content string) []models.Finding {
	var findings []models.Finding

	for _, rule := range d.rules {

		// find all matches across the entire file
		matches := rule.Pattern.FindAllStringIndex(content, -1)

		for _, match := range matches {

			start := match[0]
			end := match[1]

			// calculate line number from character position
			lineNum := strings.Count(content[:start], "\n") + 1

			snippet := strings.TrimSpace(content[start:end])
			if len(snippet) > 100 {
				snippet = snippet[:100] + "..."
			}

			findings = append(findings, models.Finding{
				ID:             rule.ID,
				Class:          d.class,
				Type:           rule.Type,
				Description:    rule.Description,
				Line:           lineNum,
				Snippet:        snippet,
				Recommendation: rule.Recommendation,
				Severity:       rule.Severity,
				Confidence:     "high",
				ScoreImpact:    rule.Score,
			})
		}
	}

	return findings
}
