package class_e

import (
	"FYP/backend/models"
	"path/filepath"
)

type ClassEDetector struct {
	class       string
	name        string
	description string
}

func NewClassEDetector() *ClassEDetector {
	return &ClassEDetector{
		class:       "E",
		name:        "Dependency/Supply Chain",
		description: "Detects dependency risks and supply chain issues",
	}
}

func (d *ClassEDetector) Class() string {
	return d.class
}
func (d *ClassEDetector) Name() string {
	return d.name
}
func (d *ClassEDetector) Description() string {
	return d.description
}

func (d *ClassEDetector) Detect(filename, content string) []models.Finding {
	var findings []models.Finding
	base := filepath.Base(filename)

	switch {
	case base == "requirements.txt":
		findings = append(findings, checkPyPI(d.class, content)...)
	}
	return findings
}
