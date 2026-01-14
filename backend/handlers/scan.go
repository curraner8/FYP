package handlers

import (
	"encoding/json"
	"net/http"

	"FYP/backend/models"
	"FYP/backend/scanner"
)

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	result := scanner.ScanFiles(req.Files)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
