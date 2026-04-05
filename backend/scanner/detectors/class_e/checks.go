package class_e

import (
	"FYP/backend/models"
	"fmt"
	"strings"
)

// parse requirements.txt against osv for each pinned dependency
// only pinned version get queried
func checkPyPI(class, content string) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "==") {
			// unpinned dependency
			findings = append(findings, models.Finding{
				ID:             "E1",
				Class:          class,
				Type:           "UNPINNED_DEPENDENCY",
				Description:    "Unpinned dependency means any version can be installed",
				Line:           lineNum + 1,
				Snippet:        line,
				Recommendation: "Pin to exact version using ==",
				Severity:       "low",
				Confidence:     "medium",
				ScoreImpact:    -5,
			})
			continue
		}

		// exact version
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])

		result, err := queryOSV("PyPI", name, version)
		if err != nil || result == nil {
			continue
		}

		if len(result.Vulnerabilities) > 0 {
			// group into one finding to prevent alert fatigue
			var ids []string
			for _, v := range result.Vulnerabilities {
				if v.ID != "" {
					ids = append(ids, v.ID)
				}
			}

			findings = append(findings, models.Finding{
				ID:             "E2",
				Class:          class,
				Type:           "KNOWN_VULNERABILITY",
				Description:    fmt.Sprintf("%s v(%s) has %d known vulnerabilities: %s", name, version, len(ids), strings.Join(ids, ", ")),
				Line:           lineNum + 1,
				Snippet:        line,
				Recommendation: "Upgrade to a fixed version",
				Severity:       "medium",
				Confidence:     "medium",
				ScoreImpact:    -10,
			})
		}

	}
	return findings
}
