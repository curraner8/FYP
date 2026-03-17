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
			description: "Warnings for design-level issues requiring manual review (cannot be satically proven)",
		},
	}
}

func (d *ClassFDetector) Detect(filename, content string) []models.Finding {
	var findings []models.Finding
	lines := getLines(content)

	// Race condition indicators
	racePattern := regexp.MustCompile(`(?i)(check.*then|if.*exists.*then|read.*then.*write|get.*then.*update)`)
	for lineNum, line := range lines {
		if racePattern.MatchString(line) {
			findings = append(findings, models.Finding{
				ID:             "F1",
				Class:          d.class,
				Type:           "RACE_CONDITION_RISK",
				Description:    "Potential race condition detected",
				Line:           lineNum + 1,
				Snippet:        strings.TrimSpace(line),
				Recommendation: "MANUAL REVIEW: use atomic operations or database transactions",
				Severity:       "medium",
				Confidence:     "low",
				ScoreImpact:    -10,
			})
		}
	}

	// Business logic complexity
	businessPattern := regexp.MustCompile(`(?i)(transfer|withdraw|purchase|refund|payment|checkout|admin.*delete|bulk.*update)`)
	for lineNum, line := range lines {
		if businessPattern.MatchString(line) {
			findings = append(findings, models.Finding{
				ID:             "F2",
				Class:          d.class,
				Type:           "BUSINESS_LOGIC_COMPLEXITY",
				Description:    "Complex business logic requires security review",
				Line:           lineNum + 1,
				Snippet:        strings.TrimSpace(line),
				Recommendation: "MANUAL REVIEW: Verify authorization, validation, and workflow enforcement",
				Severity:       "medium",
				Confidence:     "low",
				ScoreImpact:    -10,
			})
		}
	}

	// Trust boundary indicators
	trustPattern := regexp.MustCompile(`(?i)(trust.*client|frontend.*validation|user.*input.*trusted|internal.*api|microservice.*call)`)
	for lineNum, line := range lines {
		if trustPattern.MatchString(line) {
			findings = append(findings, models.Finding{
				ID:             "F3",
				Class:          d.class,
				Type:           "TRUST_BOUNDARY_RISK",
				Description:    "Potential trust boundary violation",
				Line:           lineNum + 1,
				Snippet:        strings.TrimSpace(line),
				Recommendation: "MANUAL REVIEW: Verify zero-trust architecture. Validate all inputs at boundaries",
				Severity:       "high",
				Confidence:     "low",
				ScoreImpact:    -15,
			})
		}
	}

	// Authentication flow complexity
	authPattern := regexp.MustCompile(`(?i)(password.*reset|forgot.*password|login.*redirect|oauth.*callback|jwt.*refresh|session.*fixation)`)
	for lineNum, line := range lines {
		if authPattern.MatchString(line) {
			findings = append(findings, models.Finding{
				ID:             "F4",
				Class:          d.class,
				Type:           "AUTH_FLOW_COMPLEXITY",
				Description:    "Authentication flow requires security audit",
				Line:           lineNum + 1,
				Snippet:        strings.TrimSpace(line),
				Recommendation: "MANUAL REVIEW: Verify secure session handling, token validation, and flow correctness",
				Severity:       "high",
				Confidence:     "low",
				ScoreImpact:    -15,
			})
		}
	}

	return findings
}
