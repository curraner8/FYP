package scanner

import (
	"FYP/backend/models"
	"FYP/backend/scanner/detectors"
	"FYP/backend/scanner/detectors/class_e"
	"path/filepath"
)

var SupportedExtensions = map[string]bool{
	".py":   true,
	".js":   true,
	".jsx":  true,
	".ts":   true,
	".tsx":  true,
	".html": true,
	".java": true,
	".go":   true,
	".txt":  true,
}

var Detectors = []detectors.Detector{
	detectors.NewClassADetector(),
	detectors.NewClassBDetector(),
	detectors.NewClassCDetector(),
	detectors.NewClassDDetector(),
	class_e.NewClassEDetector(),
	detectors.NewClassFDetector(),
}

func ScanContent(filename, content string) []models.Finding {
	var findings []models.Finding

	ext := filepath.Ext(filename)
	if !SupportedExtensions[ext] {
		return findings
	}

	for _, detector := range Detectors {
		results := detector.Detect(filename, content)
		findings = append(findings, results...)
	}
	return findings
}

func ScanFiles(files []struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}) models.ScanResult {

	var allFindings []models.Finding
	var fileResults []models.FileResult

	for _, file := range files {
		findings := ScanContent(file.Path, file.Content)

		for i := range findings {
			ext := filepath.Ext(file.Path)

			// call Groq API
			fix, explanation := GetLLMSuggestion(findings[i], ext)

			// attach AI results to the finding
			findings[i].LLMFix = fix
			findings[i].LLMExplanation = explanation
		}

		if len(findings) > 0 {
			fileResults = append(fileResults, models.FileResult{
				File:     file.Path,
				Findings: findings,
			})
			allFindings = append(allFindings, findings...)
		}
	}

	score, grade, breakdown := ComputeScore(allFindings, len(files))

	return models.ScanResult{
		Files: fileResults,
		Score: score,
		Grade: grade,
		Summary: models.Summary{
			TotalFiles:      len(files),
			FilesWithIssues: len(allFindings),
			ScoreBreakdown:  breakdown,
		},
	}
}
