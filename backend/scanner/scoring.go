package scanner

import (
	"FYP/backend/models"
)

func ComputeScore(findings []models.Finding) (int, string, models.ScoreBreakdown) {
	weights := map[string]int{
		"critical": -30,
		"medium": -20,
		"low": -10,
	}

	base := 100
	penalty := 0
	criticalCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range findings {
		weight := weights[finding.Severity]
		penalty += weight

		switch finding.Severity {
		case "critical":
			criticalCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
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
		Critical: criticalCount * weights["critical"],
		Medium: mediumCount * weights["medium"],
		Low: lowCount * weights["low"],
		Base: base,
		Final: final,
	}

	return final, grade, breakdown
}
