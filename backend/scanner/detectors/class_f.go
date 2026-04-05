package detectors

import (
	"FYP/backend/models"
	"regexp"
	"strings"
)

type ClassFDetector struct {
	BaseDetector
}

func NewClassFDetector() *ClassFDetector {
	return &ClassFDetector{
		BaseDetector: BaseDetector{
			class:       "F",
			name:        "Design/Runtime Logic",
			description: "Informative Warnings for design-level patterns requiring manual review (cannot be satically proven)",
		},
	}
}

func (d *ClassFDetector) Detect(filename, content string) []models.Finding {
	var findings []models.Finding
	lines := getLines(content)

	rules := []struct {
		id          string
		vulnType    string
		description string
		pattern     *regexp.Regexp
		recommend   string
	}{
		{
			id:          "F1",
			vulnType:    "RACE_CONDITION_RISK",
			description: "Potential race condition based on pattern detected",
			pattern:     regexp.MustCompile(`(?i)(check.*then|if.*exists.*then|read.*then.*write|get.*then.*update)`),
			recommend:   "MANUAL REVIEW: Try to prevent 'time of check' to 'time of use' issues",
		},
		{
			id:          "F2",
			vulnType:    "TRUST_BOUNDARY_RISK",
			description: "Potential trust boundary issue based on pattern detected",
			pattern:     regexp.MustCompile(`(?i)(trust.*client|frontend.*validation|user.*input.*trusted|internal.*api|microservice.*call)`),
			recommend:   "MANUAL REVIEW: Validate inputs at trust boundaries. Never rely on client-side validation alone",
		},
		{
			id:          "F3",
			vulnType:    "AUTH_FLOW_COMPLEXITY",
			description: "Auth flow pattern warants a careful security review",
			pattern:     regexp.MustCompile(`(?i)(password.*reset|forgot.*password|login.*redirect|oauth.*callback|jwt.*refresh|session.*fixation)`),
			recommend:   "MANUAL REVIEW: Verify everything here is secure (token validation, secure session handling, correct auth flow)",
		},
	}

	for _, rule := range rules {
		for lineNum, line := range lines {
			if rule.pattern.MatchString(line) {
				findings = append(findings, models.Finding{
					ID:             rule.id,
					Class:          d.class,
					Type:           rule.vulnType,
					Description:    rule.description,
					Line:           lineNum + 1,
					Snippet:        strings.TrimSpace(line),
					Recommendation: rule.recommend,
					Severity:       "info",
					Confidence:     "low",
					ScoreImpact:    0,
				})
			}
		}
	}

	return findings
}
