package models

type Finding struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Description    string `json:"description"`
	Line           int    `json:"line"`
	Snippet        string `json:"snippet"`
	Recommendation string `json:"recommendation"`
	Severity       string `json:"severity"`
}

type FileResult struct {
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type ScoreBreakdown struct {
	Critical int `json:"critical"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Base     int `json:"base"`
	Final    int `json:"final"`
}

type Summary struct {
	TotalFiles      int            `json:"total_files"`
	FilesWithIssues int            `json:"files_with_issues"`
	ScoreBreakdown  ScoreBreakdown `json:"score_breakdown"`
}

type ScanResult struct {
	Files   []FileResult `json:"files"`
	Score   int          `json:"score"`
	Grade   string       `json:"grade"`
	Summary Summary      `json:"summary"`
}

type ScanRequest struct {
	Files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"files"`
}
