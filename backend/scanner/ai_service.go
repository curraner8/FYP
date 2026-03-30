package scanner

import (
	"FYP/backend/models"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// before go run, MUST run this in the same terminal window:
// $env:GROQ_API_KEY = "....."

func GetLLMSuggestion(finding models.Finding, language string) (string, string) {
	apiKey := os.Getenv("GROQ_API_KEY")
	if apiKey == "" {
		return "MISSING_KEY", "Set GROQ_API_KEY env variable"
	}

	url := "https://api.groq.com/openai/v1/chat/completions"

	prompt := fmt.Sprintf("Fix this %s vulnerability: %s. Code: %s. Provide answer strictly as FIX: [code] WHY: [explanation]", finding.Type, finding.Description, finding.Snippet)

	payload := map[string]interface{}{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonPayload, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "API_ERROR", err.Error()
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Choices) == 0 {
		return "NO_RESPONSE", "Groq returned empty"
	}

	raw := result.Choices[0].Message.Content
	parts := strings.Split(raw, "WHY:")
	fix := strings.TrimSpace(strings.TrimPrefix(parts[0], "FIX:"))
	explanation := ""
	if len(parts) > 1 {
		explanation = strings.TrimSpace(parts[1])
	}

	return fix, explanation
}
