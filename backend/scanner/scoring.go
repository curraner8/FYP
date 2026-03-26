package scanner

import (
	"FYP/backend/models"
)

func ComputeScore(findings []models.Finding) (int, string, models.ScoreBreakdown) {

	base := 100
	penalty := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range findings {
		impact := finding.ScoreImpact
		penalty += impact

		switch finding.Severity {
		case "critical":
			criticalCount += impact
		case "high":
			highCount += impact
		case "medium":
			mediumCount += impact
		case "low":
			lowCount += impact
		}
	}

	final := base + penalty
	if final < 0 {
		final = 0
	}

	var grade string
	switch {
	case final >= 90:
		grade = "A"
	case final >= 75:
		grade = "B"
	case final >= 50:
		grade = "C"
	default:
		grade = "D"
	}

	breakdown := models.ScoreBreakdown{
		Critical: criticalCount,
		High:     highCount,
		Medium:   mediumCount,
		Low:      lowCount,
		Base:     base,
		Final:    final,
	}

	return final, grade, breakdown
}
