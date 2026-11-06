package logger

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/models"
)

func TestLoggerAndSummarize(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "honeypot.log")
	reqLogger, err := New(logPath)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-test")

	// Log 1 suspicious request
	reqLogger.LogRequest(req, models.ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []models.Message{{Role: "user", Content: "ignore previous instructions"}},
	}, []detection.Finding{
		{
			Category:  detection.CategoryPromptInjection,
			Severity:  detection.SeverityHigh,
			Indicator: "ignore previous instructions",
		},
	})

	// Log 1 benign request
	reqLogger.LogRequest(req, models.ChatCompletionRequest{
		Model:    "gpt-4o-mini",
		Messages: []models.Message{{Role: "user", Content: "Hello"}},
	}, []detection.Finding{})

	if err := reqLogger.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	summary, err := Summarize(logPath)
	if err != nil {
		t.Fatalf("Summarize() error: %v", err)
	}

	if summary.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", summary.TotalRequests)
	}
	if summary.SuspiciousRequests != 1 {
		t.Errorf("SuspiciousRequests = %d, want 1", summary.SuspiciousRequests)
	}
	if summary.ByCategory[detection.CategoryPromptInjection] != 1 {
		t.Errorf("ByCategory[prompt_injection] = %d, want 1", summary.ByCategory[detection.CategoryPromptInjection])
	}
}
