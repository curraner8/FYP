package detectors

import (
	"FYP/backend/models"
	"regexp"
	"strings"
)

type ClassBDetector struct {
	BaseDetector
	rules []PatternRule
}

func NewClassBDetector() *ClassBDetector {
	return &ClassBDetector{
		BaseDetector: BaseDetector{
			class:       "B",
			name:        "API Misuse",
			description: "Detects dangerous API usage regardless of input source",
		},
		rules: []PatternRule{
			// Eval usage (any)
			{
				ID:             "B1",
				Type:           "DANGEROUS_EVAL",
				Severity:       "critical",
				Description:    "Dangerous eval() usage detected",
				Pattern:        regexp.MustCompile(`(?i)\beval\s*\(`),
				Recommendation: "Remove eval() entirely. Use JSON.parse or safe alternatives",
				Score:          -30,
			},
			// OS Command Execution
			{
				ID:             "B2",
				Type:           "OS_COMMAND_EXECUTION",
				Severity:       "critical",
				Description:    "OS command execution API used",
				Pattern:        regexp.MustCompile(`(?i)\b(exec|system|popen|os\.system|subprocess\.call|subprocess\.run|Runtime\.exec|ProcessBuilder)\s*\(`),
				Recommendation: "Avoid shell commands. Use native language APIs",
				Score:          -30,
			},
			// Python Pickle
			{
				ID:             "B3",
				Type:           "INSECURE_DESERIALIZATION_PICKLE",
				Severity:       "critical",
				Description:    "Insecure pickle deserialization",
				Pattern:        regexp.MustCompile(`(?i)pickle\.loads?\s*\(`),
				Recommendation: "Use json.loads instead. Pickle is unsafe for trusted data",
				Score:          -30,
			},
			// Java Deserialization
			{
				ID:             "B4",
				Type:           "JAVA_DESERIALIZATION",
				Severity:       "critical",
				Description:    "Java ObjectInputStream deserialization",
				Pattern:        regexp.MustCompile(`(?i)new\s+ObjectInputStream|ObjectInputStream\.readObject`),
				Recommendation: "Avoid Java serialization. Use JSON or protobuf with validation",
				Score:          -30,
			},
			// Unsafe YAML
			// ****CAUSES ERROR****
			// {
			// 	ID:             "B5",
			// 	Type:           "UNSAFE_YAML",
			// 	Severity:       "high",
			// 	Description:    "Unsafe yaml.load usage",
			// 	Pattern:        regexp.MustCompile(`(?i)yaml\.load\s*\((?!.*Loader\s*=\s*(SafeLoader|BaseLoader))`),
			// 	Recommendation: "Use yaml.safe_load() instead of yaml.load()",
			// 	Score:          -20,
			// },
			// Shell=True
			{
				ID:             "B6",
				Type:           "SHELL_INJECTION_RISK",
				Severity:       "high",
				Description:    "subprocess with shell=True",
				Pattern:        regexp.MustCompile(`(?i)subprocess\.(call|run|Popen).*(shell\s*=\s*True)`),
				Recommendation: "Use shell=False and pass command as list of arguments",
				Score:          -20,
			},
			// Weak Crypto Hashes
			{
				ID:             "B7",
				Type:           "WEAK_CRYPTO_HASH",
				Severity:       "high",
				Description:    "Weak cryptographic hash algorithm",
				Pattern:        regexp.MustCompile(`(?i)(md5|sha1)\s*\(|hashlib\.(md5|sha1)|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']\s*\)`),
				Recommendation: "Use SHA-256, SHA-3 or bycrypt/Argon2 for passwords",
				Score:          -20,
			},
			// Insecure Random
			{
				ID:             "B8",
				Type:           "INSECURE_RANDOM",
				Severity:       "medium",
				Description:    "Insecure random number generator",
				Pattern:        regexp.MustCompile(`(?i)Math\.random\s*\(|random\.randint|random\.random\s*\(|java\.util\.Random|rand\(\)`),
				Recommendation: "Use crypto.getRandomValues, secrets, or SecureRandom for security purposes",
				Score:          -10,
			},
			// Insecure XML Parser
			// ****CAUSES ERROR****
			// {
			// 	ID:             "B9",
			// 	Type:           "XXE_RISK",
			// 	Severity:       "high",
			// 	Description:    "XML parser vulnerable to XXE",
			// 	Pattern:        regexp.MustCompile(`(?i)(DocumentBuilderFactory|SAXParserFactory|XMLReader|XmlDocument|lxml\.etree\.parse|xml\.etree\.ElementTree\.parse)(?!.*setFeature.*http://apache.org/xml/features/disallow-doctype-decl)`),
			// 	Recommendation: "Disable external entities: setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
			// 	Score:          -20,
			// },
			// Dangerous Functions (PHP)
			{
				ID:             "B10",
				Type:           "DANGEROUS_FUNCTION",
				Severity:       "critical",
				Description:    "Dangerous PHP function usage",
				Pattern:        regexp.MustCompile(`(?i)\b(passthru|shell_exec|proc_open|pcntl_exec|assert|create_function)\s*\(`),
				Recommendation: "Avoid these dangerous functions; use safer alternatives",
				Score:          -30,
			},
		},
	}
}

func (d *ClassBDetector) Detect(filename, content string) []models.Finding {
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
