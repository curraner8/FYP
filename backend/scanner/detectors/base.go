package detectors

import (
	"FYP/backend/models"
	"fmt"
	"regexp"
	"strings"
)

// Detector will define the interface for all of the detection classes

type Detector interface {
	Detect(filename, content string) []models.Finding
	Class() string
	Name() string
	Description() string
}

// PatternRule will define a static pattern detection rule

type PatternRule struct {
	ID             string
	Type           string
	Severity       string
	Description    string
	Pattern        *regexp.Regexp
	Recommendation string
	Score          int
}

// BaseDetector will provide common functionality

type BaseDetector struct {
	class       string
	name        string
	description string
}

func (b *BaseDetector) Class() string {
	return b.class
}

func (b *BaseDetector) Name() string {
	return b.name
}

func (b *BaseDetector) Description() string {
	return b.description
}

// getLines will split content and return the lines with their line numbers (1-based)

func getLines(content string) []string {
	return strings.Split(content, "\n")
}

func getContext(content string, lineNum int, contextLines int) string {
	lines := strings.Split(content, "\n")
	start := lineNum - contextLines
	if start < 1 {
		start = 1
	}

	end := lineNum + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	var contextBuilder strings.Builder
	for i := start; i <= end; i++ {
		if i == lineNum {
			contextBuilder.WriteString(fmt.Sprintf("->>> %d: %s\n", i, lines[i-1]))
		} else {
			contextBuilder.WriteString(fmt.Sprintf("    %d: %s\n", i, lines[i-1]))
		}
	}
	return contextBuilder.String()
}
