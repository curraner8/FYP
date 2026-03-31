package scanner

import (
	"FYP/backend/models"
	"math"
)

// weight helpers:
func diminishingFactor(n int) float64 {
	switch n {
	case 1:
		return 1.0
	case 2:
		return 0.5
	case 3:
		return 0.25
	default:
		return 0.1
	}
}

// confidence weights
func confidenceWeight(c string) float64 {
	switch c {
	case "high":
		return 1.0
	case "medium":
		return 0.6
	default:
		return 0.3
	}
}

// class weights
func classWeight(class string) float64 {
	switch class {
	case "A":
		return 1.0
	case "B":
		return 0.9
	case "C":
		return 0.7
	case "D":
		return 0.5
	case "E":
		return 0.4
	default:
		return 0.3
	}
}

func ComputeScore(findings []models.Finding, totalFiles int) (int, string, models.ScoreBreakdown) {

	base := 100.0

	// group the findings by type
	groupedFindings := make(map[string][]models.Finding)
	for _, f := range findings {
		key := f.Type
		groupedFindings[key] = append(groupedFindings[key], f)
	}

	// severity caps
	severityCaps := map[string]float64{
		"critical": 60,
		"high":     50,
		"medium":   30,
		"low":      15,
	}

	severityTotals := map[string]float64{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	totalPenalty := 0.0

	// process each group
	for _, group := range groupedFindings {
		for i, f := range group {
			baseImpact := math.Abs(float64(f.ScoreImpact)) //ensure positive
			dFactor := diminishingFactor(i + 1)
			cWeight := confidenceWeight(f.Confidence)
			clWeight := classWeight(f.Class)

			penalty := baseImpact * dFactor * cWeight * clWeight

			sev := f.Severity

			// apply severity cap
			if severityTotals[sev] < severityCaps[sev] {
				remaining := severityCaps[sev] - severityTotals[sev]

				if penalty > remaining {
					penalty = remaining
				}

				severityTotals[sev] += penalty
				totalPenalty += penalty
			}
		}
	}

	// final score
	finalScore := int(math.Round(base - totalPenalty))
	if finalScore < 0 {
		finalScore = 0
	}

	// grade
	var grade string
	switch {
	case finalScore >= 90:
		grade = "A"
	case finalScore >= 80:
		grade = "B"
	case finalScore >= 65:
		grade = "C"
	case finalScore >= 50:
		grade = "D"
	case finalScore >= 30:
		grade = "E"
	default:
		grade = "F"
	}

	breakdown := models.ScoreBreakdown{
		Critical: int(severityTotals["critical"]),
		High:     int(severityTotals["high"]),
		Medium:   int(severityTotals["medium"]),
		Low:      int(severityTotals["low"]),
		Base:     int(base),
		Final:    finalScore,
	}

	return finalScore, grade, breakdown
}

// func ComputeScore(findings []models.Finding) (int, string, models.ScoreBreakdown) {

// 	base := 100
// 	penalty := 0
// 	criticalCount := 0
// 	highCount := 0
// 	mediumCount := 0
// 	lowCount := 0

// 	for _, finding := range findings {
// 		impact := finding.ScoreImpact
// 		penalty += impact

// 		switch finding.Severity {
// 		case "critical":
// 			criticalCount += impact
// 		case "high":
// 			highCount += impact
// 		case "medium":
// 			mediumCount += impact
// 		case "low":
// 			lowCount += impact
// 		}
// 	}

// 	final := base + penalty
// 	if final < 0 {
// 		final = 0
// 	}

// 	var grade string
// 	switch {
// 	case final >= 90:
// 		grade = "A"
// 	case final >= 75:
// 		grade = "B"
// 	case final >= 50:
// 		grade = "C"
// 	default:
// 		grade = "D"
// 	}

// 	breakdown := models.ScoreBreakdown{
// 		Critical: criticalCount,
// 		High:     highCount,
// 		Medium:   mediumCount,
// 		Low:      lowCount,
// 		Base:     base,
// 		Final:    final,
// 	}

// 	return final, grade, breakdown
// }
