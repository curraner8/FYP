package detectors

import (
	"FYP/backend/models"
	"path/filepath"
	"regexp"
	"strings"
)

type ClassEDetector struct {
	BaseDetector
}

func NewClassEDetector() *ClassEDetector {
	return &ClassEDetector{
		BaseDetector: BaseDetector{
			class:       "E",
			name:        "Dependency/Supply Chain",
			description: "Detects dependency management risks and supply chain issues",
		},
	}
}

func (d *ClassEDetector) Detect(filename, content string) []models.Finding {
	var findings []models.Finding
	ext := filepath.Ext(filename)
	base := filepath.Base(filename)

	// E1: Missing lockfile (check for package.json without lock)
	if base == "package.json" {
		findings = append(findings, d.checkPackageJSON(filename, content)...)
	}

	// E2: Requirements.txt risk
	if base == "requirements.txt" {
		findings = append(findings, d.checkRequirementsTxt(filename, content)...)
	}

	// E3: Dangerous install patterns
	if ext == ".sh" || ext == ".bash" || ext == "" {
		findings = append(findings, d.checkInstallScripts(filename, content)...)
	}

	// E4: Outdated dependency patterns
	if base == "package.json" || base == "Cargo.toml" || base == "go.mod" {
		findings = append(findings, d.checkOutdatedDeps(filename, content)...)
	}

	return findings
}

func (d *ClassEDetector) checkPackageJSON(filename, content string) []models.Finding {
	var findings []models.Finding

	// Check for pre-1.0 versions (unstable)
	unstablePattern := regexp.MustCompile(`"([a-zA-Z0-9_-]+)":\s*"0\.[0-9]+"`)
	matches := unstablePattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			findings = append(findings, models.Finding{
				ID:             "E1",
				Class:          d.class,
				Type:           "UNSTABLE_DEPENDENCY",
				Description:    "Pre-1.0 dependency may be unstable: " + match[1],
				Line:           1,
				Snippet:        match[0],
				Recommendation: "Update to stable version (1.0+) or verify API stability",
				Severity:       "low",
				Confidence:     "low",
				ScoreImpact:    -5,
			})
		}
	}

	// Check for risky packages
	riskyPackages := []string{"event-stream", "flatmap-stream", "rc", "left-pad", "colors", "faker"}
	for _, pkg := range riskyPackages {
		if strings.Contains(content, `"`+pkg+`"`) {
			findings = append(findings, models.Finding{
				ID:             "E2",
				Class:          d.class,
				Type:           "KNOWN_RISKY_PACKAGE",
				Description:    "Known compromised or risky package: " + pkg,
				Line:           1,
				Snippet:        `"` + pkg + `":`,
				Recommendation: "Remove immediately; check for malicious activity in logs",
				Severity:       "critical",
				Confidence:     "high",
				ScoreImpact:    -30,
			})
		}
	}

	return findings
}

func (d *ClassEDetector) checkRequirementsTxt(filename, content string) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(content, "\n")

	// Check for unpinned versions (no ==)
	unpinnedPattern := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([<>!~]|$)`)

	for lineNum, line := range lines {
		if unpinnedPattern.MatchString(line) && !strings.Contains(line, "==") {
			findings = append(findings, models.Finding{
				ID:             "E3",
				Class:          d.class,
				Type:           "UNPINNED_DEPENDENCY",
				Description:    "Unpinned dependency version allows unexpected updates",
				Line:           lineNum + 1,
				Snippet:        strings.TrimSpace(line),
				Recommendation: "Pin versions: package==1.2.3; use pip freeze > requirements.txt",
				Severity:       "low",
				Confidence:     "low",
				ScoreImpact:    -14,
			})
		}
	}

	return findings
}

func (d *ClassEDetector) checkInstallScripts(filename, content string) []models.Finding {
	var findings []models.Finding

	// Dangerous curl | bash patterns
	dangerousPattern := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh|zsh)`)

	if dangerousPattern.MatchString(content) {
		findings = append(findings, models.Finding{
			ID:             "E4",
			Class:          d.class,
			Type:           "DANGEROUS_INSTALL",
			Description:    "Remote code execution via curl | bash",
			Line:           1,
			Snippet:        "curl ... | bash",
			Recommendation: "Verify checksums before execution; use package managers",
			Severity:       "critical",
			Confidence:     "high",
			ScoreImpact:    -28,
		})
	}

	return findings
}

func (d *ClassEDetector) checkOutdatedDeps(filename, content string) []models.Finding {
	var findings []models.Finding

	// Very old version patterns (0.x or ancient versions)
	ancientPattern := regexp.MustCompile(`(?i)"([a-zA-Z0-9_-]+)":\s*"([0-9]+\.[0-9]+\.[0-9]+)"`)
	matches := ancientPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) == 3 {
			version := match[2]
			// Check for very old versions (major version 0 or very low)
			if strings.HasPrefix(version, "0.") {
				findings = append(findings, models.Finding{
					ID:             "E5",
					Class:          d.class,
					Type:           "OUTDATED_DEPENDENCY",
					Description:    "Very old dependency version: " + match[1] + "@" + version,
					Line:           1,
					Snippet:        match[0],
					Recommendation: "Update to latest stable version and review changelog for security fixes",
					Severity:       "low",
					Confidence:     "low",
					ScoreImpact:    -6,
				})
			}
		}
	}

	return findings
}
