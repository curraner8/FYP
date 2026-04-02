package main

// import (
// 	"FYP/backend/models"
// 	"fmt"
// 	"os"
// )

// // will write a formatted Markdown summary visible in the actions tab after the workflow runs

// func writeGitHubSummary(result models.ScanResult) {
// 	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
// 	if summaryPath == "" {
// 		return
// 	}

// 	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_WRONLY, 0644)
// 	if err != nil {
// 		return
// 	}
// 	defer f.Close()

// 	status := "---->PASSED<----"
// 	if result.Grade == "C" || result.Grade == "D" || result.Grade == "E" || result.Grade == "F" {
// 		status = "----->FAILED<-----"
// 	}

// 	fmt.Fprintf(f, "# Scan Summary\n\n")
// 	fmt.Fprintf(f, "### Status: %s\n\n", status)
// 	fmt.Fprintf(f, "#### Score: (%d / 100)\n", result.Score)
// 	fmt.Fprintf(f, "#### Grade: %s\n", result.Grade)
// 	fmt.Fprintf(f, "#### Files Scanned: %d\n", result.Summary.TotalFiles)
// 	fmt.Fprintf(f, "#### Files With Issues: %d\n", result.Summary.FilesWithIssues)

// 	if len(result.Files) > 0 {
// 		fmt.Fprintf(f, "\n## Findings by File\n\n")
// 		for _, file := range result.Files {
// 			fmt.Fprintf(f, "**File** : %s\n", file.File)
// 			fmt.Fprintf(f, "| Line | Severity | Type | Description | Recommendation |\n")
// 			fmt.Fprintf(f, "|------|----------|------|-------------|----------------|\n")
// 			for _, finding := range file.Findings {
// 				fmt.Fprintf(f, "| %d | %s | `%s` | %s | %s |\n",
// 					finding.Line, finding.Severity, finding.Type, finding.Description, finding.Recommendation)
// 			}
// 			fmt.Fprintf(f, "\n**AI Suggestions**\n\n")
// 			for _, finding := range file.Findings {
// 				fmt.Fprintf(f, "- **%s** (Line %d): %s\n", finding.Type, finding.Line, finding.LLMFix)
// 				fmt.Fprintf(f, " - *%s*\n", finding.LLMExplanation)
// 			}
// 		}
// 	} else {
// 		fmt.Fprintf(f, "\n## No Vulnerabilities Found\n")
// 	}
// }
