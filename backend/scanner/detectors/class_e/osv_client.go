package class_e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// OSV API structs
// API docs: google.github.io/osv.dev/api

type osvRequest struct {
	Version string     `json:"version"`
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulnerabilities []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// make POST request to osv api
func queryOSV(ecosystem, name, version string) (*osvResponse, error) {
	req := osvRequest{
		Version: version,
		Package: osvPackage{
			Name:      name,
			Ecosystem: ecosystem,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API error: %d", resp.StatusCode)
	}

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil

}
