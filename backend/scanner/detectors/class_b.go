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
			// Eval usage
			{
				ID:             "B1",
				Type:           "DANGEROUS_EVAL",
				Severity:       "critical",
				Description:    "Dangerous eval() usage detected",
				Pattern:        regexp.MustCompile(`(?i)^[^#//]*\beval\s*\(`),
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
				Score:          -28,
			},
			// Python Pickle
			{
				ID:             "B3",
				Type:           "INSECURE_DESERIALIZATION_PICKLE",
				Severity:       "critical",
				Description:    "Insecure pickle deserialization",
				Pattern:        regexp.MustCompile(`(?i)pickle\.loads?\s*\(`),
				Recommendation: "Use json.loads instead. Pickle is unsafe for trusted data",
				Score:          -27,
			},
			// Java Deserialization
			{
				ID:             "B4",
				Type:           "JAVA_DESERIALIZATION",
				Severity:       "critical",
				Description:    "Java ObjectInputStream deserialization",
				Pattern:        regexp.MustCompile(`(?i)new\s+ObjectInputStream|ObjectInputStream\.readObject`),
				Recommendation: "Avoid Java serialization. Use JSON or protobuf with validation",
				Score:          -27,
			},
			// Unsafe YAML
			{
				ID:          "B5",
				Type:        "UNSAFE_YAML",
				Severity:    "high",
				Description: "Unsafe YAML deserialization using load instead of safe_load",
				Pattern: regexp.MustCompile(`(?i)(` +
					`yaml\.(load|full_load)\s*\(|` +
					`Yaml\.(load|loadAll)\s*\(` +
					`)`),
				Recommendation: "Use yaml.safe_load() in Python. Use SafeConstructor in Java SnakeYAML. Never use yaml.load() with untrusted input.",
				Score:          -15,
			},
			// Shell=True
			{
				ID:             "B6",
				Type:           "SHELL_INJECTION_RISK",
				Severity:       "high",
				Description:    "subprocess with shell=True",
				Pattern:        regexp.MustCompile(`(?is)subprocess\.(call|run|Popen)\s*\([^)]{0,300}shell\s*=\s*True`),
				Recommendation: "Use shell=False and pass command as list of arguments",
				Score:          -18,
			},
			// Weak Crypto Hashes
			{
				ID:          "B7",
				Type:        "WEAK_CRYPTO_HASH",
				Severity:    "high",
				Description: "Weak cryptographic hash algorithm",
				Pattern: regexp.MustCompile(`(?i)(` +
					`hashlib\.(md5|sha1)\s*\(|` +
					`\bmd5\s*\(|\bsha1\s*\(|` +
					`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']|` +
					`crypto\.createHash\s*\(\s*["'](md5|sha1)["']|` +
					`md5\.New\(\)|sha1\.New\(\)` +
					`)`),
				Recommendation: "Use SHA-256, SHA-3 or bycrypt/Argon2 for passwords",
				Score:          -17,
			},
			// Insecure Random
			{
				ID:             "B8",
				Type:           "INSECURE_RANDOM",
				Severity:       "medium",
				Description:    "Insecure random number generator",
				Pattern:        regexp.MustCompile(`(?i)Math\.random\s*\(|random\.randint|random\.random\s*\(|java\.util\.Random|rand\(\)`),
				Recommendation: "Use crypto.getRandomValues, secrets, or SecureRandom for security purposes",
				Score:          -5,
			},
			// Insecure XML Parser
			{
				ID:          "B9",
				Type:        "XXE_RISK",
				Severity:    "high",
				Description: "XML parser used that may be vulnerable to XXE by default",
				Pattern: regexp.MustCompile(`(?i)(` +
					`DocumentBuilderFactory\.newInstance\s*\(|` +
					`SAXParserFactory\.newInstance\s*\(|` +
					`new\s+XMLReader|` +
					`lxml\.etree\.(parse|fromstring)\s*\(|` +
					`xml\.etree\.ElementTree\.(parse|fromstring)\s*\(|` +
					`XmlDocument\s*\(\s*\)|` +
					`new\s+XmlTextReader\s*\(` +
					`)`),
				Recommendation: "Disable external entities and DTDs explicitly.",
				Score:          -18,
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

				context := getContext(content, lineNum, 10)

				findings = append(findings, models.Finding{
					ID:             rule.ID,
					Class:          d.class,
					Type:           rule.Type,
					Description:    rule.Description,
					Line:           lineNum + 1,
					Snippet:        snippet,
					Context:        context,
					Recommendation: rule.Recommendation,
					Severity:       rule.Severity,
					Confidence:     "high",
					ScoreImpact:    rule.Score,
				})
			}
		}
	}

	for i := range findings {
		if findings[i].ID == "B9" {
			findings[i].Confidence = "medium"
		}
	}

	return findings
}
