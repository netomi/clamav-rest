package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal filename unchanged",
			input:    "document.pdf",
			expected: "document.pdf",
		},
		{
			name:     "filename with spaces",
			input:    "my document.pdf",
			expected: "my document.pdf",
		},
		{
			name:     "newline replaced",
			input:    "file\nname.txt",
			expected: "file_name.txt",
		},
		{
			name:     "carriage return replaced",
			input:    "file\rname.txt",
			expected: "file_name.txt",
		},
		{
			name:     "tab replaced",
			input:    "file\tname.txt",
			expected: "file_name.txt",
		},
		{
			name:     "null byte replaced",
			input:    "file\x00name.txt",
			expected: "file_name.txt",
		},
		{
			name:     "DEL character replaced",
			input:    "file\x7fname.txt",
			expected: "file_name.txt",
		},
		{
			name:     "long filename truncated",
			input:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt",
			expected: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...",
		},
		{
			name:     "exactly 100 chars not truncated",
			input:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:     "unicode preserved",
			input:    "文档.pdf",
			expected: "文档.pdf",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSendError(t *testing.T) {
	recorder := httptest.NewRecorder()

	sendError(recorder, "Test error message")

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var response ScanResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Status != "error" {
		t.Errorf("response.Status = %q, want error", response.Status)
	}
	if response.Error != "Test error message" {
		t.Errorf("response.Error = %q, want 'Test error message'", response.Error)
	}
}

func TestScanHandlerMethodNotAllowed(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/scan", nil)
			recorder := httptest.NewRecorder()

			scanHandler(recorder, req)

			if recorder.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestScanHandlerNoFile(t *testing.T) {
	// Initialize config for the handler
	config = &Config{
		MaxUploadSize: 10 << 20,
	}

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	req.Header.Set("Content-Type", "multipart/form-data")
	recorder := httptest.NewRecorder()

	scanHandler(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

func TestHealthHandlerRequiresScanner(t *testing.T) {
	// Skip if scanner not initialized (requires clamd)
	if scanner == nil {
		t.Skip("scanner not initialized (requires clamd)")
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()

	healthHandler(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}
