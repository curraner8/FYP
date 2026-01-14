package scanner

import (
	"FYP/backend/models"
	"path/filepath"
	"strings"
)

var SupportedExtensions = map[string]bool{
	".py":   true,
	".js":   true,
	".jsx":  true,
	".ts":   true,
	".tsx":  true,
	".html": true,
}

func ScanContent(filename, content string) []models.Finding {
	var findings []models.Finding

	ext := filepath.Ext(filename)
	if !SupportedExtensions[ext] {
		return findings
	}

	lines := strings.Split(content, "\n")

	for _, rule := range Rules {
		for lineNum, line := range lines {
			if rule.Pattern.MatchString(line) {
				findings = append(findings, models.Finding{
					ID:             rule.ID,
					Type:           rule.Type,
					Description:    rule.Description,
					Line:           lineNum + 1,
					Snippet:        strings.TrimSpace(line),
					Recommendation: rule.Recommendation,
					Severity:       rule.Severity,
				})
			}
		}
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
		if len(findings) > 0 {
			fileResults = append(fileResults, models.FileResult{
				File:     file.Path,
				Findings: findings,
			})
			allFindings = append(allFindings, findings...)
		}
	}

	score, grade, breakdown := ComputeScore(allFindings)

	return models.ScanResult{
		Files: fileResults,
		Score: score,
		Grade: grade,
		Summary: models.Summary{
			TotalFiles:      len(files),
			FilesWithIssues: len(fileResults),
			ScoreBreakdown:  breakdown,
		},
	}
}
