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
				Pattern: regexp.MustCompile(`(?i)(` +
					`SELECT\s+.+\s+FROM|` +
					`INSERT\s+INTO|` +
					`UPDATE\s+\w+\s+SET|` +
					`DELETE\s+FROM|` +
					`DROP\s+(TABLE|DATABASE)|` +
					`UNION\s+(ALL\s+)?SELECT` +
					`).*?(` +
					`\+\s*\w|` +
					`%[sd]\b|` +
					`\.format\s*\(|` +
					`f["']|` +
					"`\\$\\{" +
					`)`),
				Recommendation: "Use parameterized queries",
				Score:          -30,
			},
			// XSS (all variants)
			{
				ID:          "A2",
				Type:        "XSS",
				Severity:    "high",
				Description: "XSS via unsafe DOM manipulation",
				Pattern: regexp.MustCompile(`(?i)(` +
					`innerHTML\s*=|` +
					`outerHTML\s*=|` +
					`document\.write\s*\(|` +
					`document\.writeln\s*\(|` +
					`insertAdjacentHTML\s*\(|` +
					`dangerouslySetInnerHTML\s*=|` +
					`\.html\s*\(|` +
					`setAttribute\s*\(\s*["']on|` +
					`setAttribute\s*\(\s*["']href` +
					`).*?(` +
					`request\.|req\.|` +
					`params\[|query\[|` +
					`input|userInput|` +
					`location\.(search|hash)|` +
					`document\.cookie` +
					`)`),
				Recommendation: "Use textContent instead of innerHTML, or sanitize.",
				Score:          -19,
			},
			// Command Injection
			{
				ID:          "A3",
				Type:        "COMMAND_INJECTION",
				Severity:    "critical",
				Description: "Command injection via shell execution",
				Pattern: regexp.MustCompile(`(?i)(` +
					`os\.system\s*\(|` +
					`subprocess\.(call|run|Popen)\s*\(|` +
					`exec\s*\(|` +
					`popen\s*\(|` +
					`Runtime\.getRuntime\(\)\.exec|` +
					`ProcessBuilder\s*\(|` +
					`child_process\.(exec|spawn|execSync|spawnSync)\s*\(|` +
					`exec\.Command\s*\(` +
					`).*?(` +
					`\+|` +
					`%s|%v|` +
					`\$\{|` +
					`f["']` +
					`).*?(` +
					`request|input|params|args|req\.|user|cmd|command|query` +
					`)`),
				Recommendation: "Use subprocess.run(['cmd', 'arg'], shell=False) with argument list",
				Score:          -28,
			},
			// LDAP Injection
			{
				ID:          "A4",
				Type:        "LDAP_INJECTION",
				Severity:    "high",
				Description: "LDAP injection via string concatenation",
				Pattern: regexp.MustCompile(`(?is)(` +
					`ldap\.(search|bind|modify|add|delete)\s*\(|` +
					`DirContext\.(search|bind)\s*\(|` +
					`ldap_search\s*\(|` +
					`\(\s*(uid|cn|mail|userPassword|sAMAccountName)` +
					`[^)]{0,100}(\+|%s|%v|\.format\s*\(|f["'])` +
					`).*?(request|input|params|user|username|req\.)`),
				Recommendation: "Use parameterized LDAP queries and escape special characters",
				Score:          -17,
			},
			// XPath Injection
			{
				ID:          "A5",
				Type:        "XPATH_INJECTION",
				Severity:    "high",
				Description: "XPath injection via string concatenation",
				Pattern: regexp.MustCompile(`(?is)(` +
					`xpath\.(evaluate|selectNodes|selectSingleNode|compile)\s*\(|` +
					`\.evaluate\s*\([^)]*["']\/\/|` +
					`XPath\.compile\s*\(|` +
					`etree\.(xpath|findall|find)\s*\(|` +
					`selectNodes\s*\(|` +
					`["'](\/\/|\.\/).*\+.*["']` +
					`).{0,200}?(` +
					`request|input|params|user|req\.|body|data` +
					`)`),
				Recommendation: "Use parameterized XPath queries or XPath variable bindings",
				Score:          -16,
			},
			// CRLF Injection
			{
				ID:          "A6",
				Type:        "CRLF_INJECTION",
				Severity:    "high",
				Description: "CRLF injection in HTTP headers",
				Pattern: regexp.MustCompile(`(?is)(` +
					`(setHeader|addHeader)\s*\(|` +
					`writeHead\s*\(|` +
					`response\.headers\s*\[|` +
					`w\.Header\(\)\.(Set|Add)\s*\(|` +
					`header\s*\(\s*["']Location|` +
					`res\.redirect\s*\(` +
					`).{0,200}?(` +
					`\+\s*\w|%s|%v|f["']|\$\{|` +
					`\\r\\n|\\n|%0[aAdD]|%0d%0a` +
					`).*?(request|input|params|user|req\.)`),
				Recommendation: "Strip '\\r\\n' characters and validate header values",
				Score:          -15,
			},
			// Eval Injection
			{
				ID:          "A7",
				Type:        "EVAL_INJECTION",
				Severity:    "critical",
				Description: "Dangerous use of eval() with user input",
				Pattern: regexp.MustCompile(`(?is)\b(eval|exec)\s*\(.{0,200}?(` +
					`request|input|params|user|req\.|data|body|` +
					`argv|stdin|os\.environ|getenv` +
					`)`),
				Recommendation: "Remove eval() entirely and use JSON.parse or structured logic",
				Score:          -30,
			},
			// Static Code Injection
			{
				ID:          "A8",
				Type:        "STATIC_CODE_INJECTION",
				Severity:    "critical",
				Description: "Dynamic code inclusion with user input",
				Pattern: regexp.MustCompile(`(?is)(` +
					`include\s*\(|` +
					`require\s*\(|` +
					`require_once\s*\(|` +
					`include_once\s*\(|` +
					`importlib\.import_module\s*\(|` +
					`__import__\s*\(|` +
					`System\.loadLibrary\s*\(|` +
					`Class\.forName\s*\(` +
					`).{0,150}?(` +
					`request|input|params|user|req\.|body|data|\$_(GET|POST|REQUEST)` +
					`)`),
				Recommendation: "Use strict whitelisting of allowed modules and files",
				Score:          -26,
			},
			// Path Traversal
			{
				ID:          "A9",
				Type:        "PATH_TRAVERSAL",
				Severity:    "high",
				Description: "Path traversal vulnerability",
				Pattern: regexp.MustCompile(`(?is)(` +
					`open\s*\([^)]*["'][rwab]|` +
					`os\.(Open|ReadFile|Create)\s*\(|` +
					`fs\.(readFile|readFileSync|createReadStream)\s*\(|` +
					`res\.(sendFile|download)\s*\(|` +
					`FileInputStream\s*\(|` +
					`new\s+File\s*\(|` +
					`filepath\.(Join|Abs)\s*\(` +
					`).{0,200}?(` +
					`\.\./|` +
					`\.\.\\|` +
					`/\.\.|` +
					`\\\.\.|` +
					`request\.|req\.|params|input|user|query` +
					`)`),
				Recommendation: "Normalize paths and validate input",
				Score:          -18,
			},
			// Hardcoded Credentials
			{
				ID:          "A10",
				Type:        "HARDCODED_CREDENTIALS",
				Severity:    "high",
				Description: "Hardcoded credentials in source code",
				Pattern: regexp.MustCompile(`(?i)(` +
					`password|passwd|secret|api_key|apikey|` +
					`token|auth_token|access_token|` +
					`aws_access_key_id|aws_secret_access_key|` +
					`private_key|client_secret|db_password` +
					`)\s*[:=]+\s*["'][^"'\s]{6,}["']`),
				Recommendation: "Use environment variables or secret management",
				Score:          -16,
			},
			// Sensitive Info in Comments
			{
				ID:          "A11",
				Type:        "SENSITIVE_COMMENT",
				Severity:    "medium",
				Description: "Sensitive information disclosed in comments",
				Pattern: regexp.MustCompile(`(?i)(//|#|/\*|--|\*)\s*.{0,50}?(` +
					`password\s*[:=]|` +
					`secret\s*[:=]|` +
					`api[_-]?key\s*[:=]|` +
					`token\s*[:=]|` +
					`private[_-]?key|` +
					`backdoor|bypass\s+auth|` +
					`hardcoded|` +
					`admin.*password|` +
					`credentials?` +
					`)`),
				Recommendation: "Remove sensitive information from comments before committing",
				Score:          -8,
			},
			// Debug Code Enabled
			{
				ID:          "A12",
				Type:        "DEBUG_ENABLED",
				Severity:    "medium",
				Description: "Debug mode or code left enabled",
				Pattern: regexp.MustCompile(`(?i)(` +
					`\b(debug|DEBUG)\s*(=|:=)\s*(True|true|1)|` +
					`app\.(debug|config\[["']DEBUG["']\])\s*=\s*(True|true)|` +
					`console\.(log|debug|trace)\s*\(|` +
					`debugger\s*;|` +
					`\bpprint\s*\(|` +
					`fmt\.(Printf|Println)\s*\([^)]*("DEBUG|"debug|debug:)` +
					`)`),
				Recommendation: "Disable debug mode in production. Remove console.log statements",
				Score:          -9,
			},
			// Logging Secrets
			{
				ID:          "A13",
				Type:        "LOGGED_SECRETS",
				Severity:    "high",
				Description: "Sensitive information logged",
				Pattern: regexp.MustCompile(`(?i)(` +
					`\b(print|println|printf)\s*\(|` +
					`console\.(log|info|warn|error)\s*\(|` +
					`(log|logger)\.(debug|info|warn|error|fatal|print|println)\s*\(|` +
					`logging\.(debug|info|warning|error|critical)\s*\(|` +
					`syslog\s*\(|` +
					`fmt\.(Print|Printf|Println|Fprintf)\s*\(` +
					`).{0,200}?(` +
					`password|passwd|secret|` +
					`api[_-]?key|access[_-]?token|` +
					`auth[_-]?token|private[_-]?key|` +
					`credit[_-]?card|ssn|cvv` +
					`)`),
				Recommendation: "Log identifiers only, Never credentials or secrets",
				Score:          -15,
			},
			// Stack Traces Exposed
			{
				ID:          "A14",
				Type:        "STACK_TRACE_EXPOSED",
				Severity:    "medium",
				Description: "Stack trace printing in production code",
				Pattern: regexp.MustCompile(`(?is)(` +
					`printStackTrace\s*\(|` +
					`traceback\.print_exc\s*\(|` +
					`traceback\.print_tb\s*\(|` +
					`traceback\.format_exc\s*\(\)|` +
					`console\.(error|log)\s*\([^)]*\.(stack|trace)|` +
					`res\.(send|json)\s*\([^)]*err(or)?\.stack|` +
					`w\.Write\s*\([^)]*err\.Error\(\)|` +
					`fmt\.(Fprintf|Println)\s*\(\s*w[^)]*err` +
					`)`),
				Recommendation: "Use generic error messages and log details server-side only",
				Score:          -10,
			},
			// Null Pointer Risk (limited detection)
			{
				ID:          "A15",
				Type:        "NULL_POINTER_RISK",
				Severity:    "low",
				Description: "Potential null or nil dereference without prior null check",
				Pattern: regexp.MustCompile(`(?i)(` +
					`getParameter\s*\([^)]+\)\s*\.\w+|` +
					`getElementById\s*\([^)]+\)\s*\.\w+|` +
					`querySelector\s*\([^)]+\)\s*\.\w+|` +
					`json\.(loads|load)\s*\([^)]+\)\[` +
					`)`),
				Recommendation: "Check for null or nil before dereferencing. Use optional chaining or explicit null checks.",
				Score:          -5,
			},
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

			context := getContext(content, lineNum, 10)

			findings = append(findings, models.Finding{
				ID:             rule.ID,
				Class:          d.class,
				Type:           rule.Type,
				Description:    rule.Description,
				Line:           lineNum,
				Snippet:        snippet,
				Recommendation: rule.Recommendation,
				Severity:       rule.Severity,
				Context:        context,
				Confidence:     "high",
				ScoreImpact:    rule.Score,
			})
		}
	}

	return findings
}
