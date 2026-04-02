package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"FYP/backend/scanner"
)

// takes a directory path as command line argument and prints JSON results to stdout
// go run main.go (path)
// runs once then exits

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	var files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if !scanner.SupportedExtensions[ext] {
			return nil
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		files = append(files, struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}{
			Path:    path,
			Content: string(content),
		})

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
		os.Exit(1)
	}

	result := scanner.ScanFiles(files)

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling results: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))

	// GitHub Action outputs (written to $GITHUB_OUTPUT)
	githubOutput := os.Getenv("GITHUB_OUTPUT")
	if githubOutput != "" {
		f, err := os.OpenFile(githubOutput, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			fmt.Fprintf(f, "score=%d\n", result.Score)
			fmt.Fprintf(f, "grade=%s\n", result.Grade)
			fmt.Fprintf(f, "files_with_issues=%d\n", result.Summary.FilesWithIssues)
			fmt.Fprintf(f, "critical=%d\n", result.Summary.ScoreBreakdown.Critical)
			fmt.Fprintf(f, "high=%d\n", result.Summary.ScoreBreakdown.High)
			fmt.Fprintf(f, "medium=%d\n", result.Summary.ScoreBreakdown.Medium)
			fmt.Fprintf(f, "low=%d\n", result.Summary.ScoreBreakdown.Low)
		}
	}

	// fail based on threshold
	failOnGrade := os.Getenv("FAIL_ON_GRADE")
	if shouldFail(result.Grade, failOnGrade) {
		fmt.Fprintf(os.Stderr, "\n --->SECURITY SCAN FAILED: Grade %s is below %s (%d/100)\n", result.Grade, failOnGrade, result.Score)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n ---> SECURITY SCAN PASSED: Grade %s (%d/100)\n", result.Grade, result.Score)
}
