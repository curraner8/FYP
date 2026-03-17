package scanner

import (
	"FYP/backend/models"
)

func ComputeScore(findings []models.Finding) (int, string, models.ScoreBreakdown) {
	weights := map[string]int{
		"critical": -30,
		"high": -20,
		"medium": -10,
		"low": -5,
	}

	base := 100
	penalty := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, finding := range findings {
		weight, exists := weights[finding.Severity]
		if !exists {
			continue
		}

		penalty += weight

		switch finding.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
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
		High: highCount * weights["high"],
		Medium: mediumCount * weights["medium"],
		Low: lowCount * weights["low"],
		Base: base,
		Final: final,
	}

	return final, grade, breakdown
}
