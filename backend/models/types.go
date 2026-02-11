package models

type Finding struct {
	ID             string `json:"id"`
	// Class          string `json:"class"` // class/category of the vulnerability
	Type           string `json:"type"`
	Description    string `json:"description"`
	Line           int    `json:"line"`
	Snippet        string `json:"snippet"`
	Recommendation string `json:"recommendation"`
	Severity       string `json:"severity"`
	// Confidence     string `json:"confidence"`   // high/medium/low, class dependent (how accurately can this be detected)
	// ScoreImpact    int    `json:"score_impact"` // score value?
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

// for LLM remedies (better fix recommendations which have proper context of the full code (in file or all uploaded files (not sure yet)))

// type LLMRequest struct {
// 	Code        string  `json:"code"`
// 	Finding     Finding `json:"finding"`
// 	Language    string  `json:"language"`
// 	FileContext string  `json:"file_context"`
// }

// type LLMResponse struct {
// 	Fix         string `json:"fix`
// 	Explanation string `json:"explanation"`
// }
