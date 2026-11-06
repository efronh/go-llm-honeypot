package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/logger"
	"github.com/efronh/go-llm-honeypot/internal/models"
)

func newTestMux(t *testing.T) *http.ServeMux {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "honeypot.log")
	reqLogger, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("initialize test logger: %v", err)
	}
	t.Cleanup(func() {
		_ = reqLogger.Close()
	})

	mux := http.NewServeMux()
	NewHandler(detection.NewDetector(), reqLogger).RegisterRoutes(mux)
	return mux
}

func TestHealthEndpoint(t *testing.T) {
	mux := newTestMux(t)

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "GET returns 200 OK",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST returns 405 Method Not Allowed",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/healthz", nil)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.expectedStatus)
			}
		})
	}
}

func TestModelsEndpoint(t *testing.T) {
	mux := newTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-test-key-123")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.ModelListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode models response: %v", err)
	}
	if resp.Object != "list" || len(resp.Data) == 0 {
		t.Errorf("unexpected model list response: %+v", resp)
	}
}

func TestChatCompletionsEndpoint(t *testing.T) {
	mux := newTestMux(t)

	tests := []struct {
		name           string
		method         string
		body           string
		expectedStatus int
	}{
		{
			name:           "GET returns 405 Method Not Allowed",
			method:         http.MethodGet,
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "malformed JSON returns 400 Bad Request",
			method:         http.MethodPost,
			body:           `{"model":"gpt-4o",`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "multiple JSON objects return 400 Bad Request",
			method:         http.MethodPost,
			body:           `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}{"extra":true}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty messages array returns 400 Bad Request",
			method:         http.MethodPost,
			body:           `{"model":"gpt-4o","messages":[]}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "valid request returns 200 OK",
			method:         http.MethodPost,
			body:           `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/v1/chat/completions", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.expectedStatus)
			}

			if tc.expectedStatus == http.StatusOK {
				var resp models.ChatCompletionResponse
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("decode response JSON: %v", err)
				}
				if resp.Model != "gpt-4o" {
					t.Errorf("response model = %q, want %q", resp.Model, "gpt-4o")
				}
				if len(resp.Choices) != 1 || resp.Choices[0].Message.Content == "" {
					t.Errorf("unexpected choices: %+v", resp.Choices)
				}
				if resp.Usage.TotalTokens <= 0 || resp.Usage.TotalTokens != resp.Usage.PromptTokens+resp.Usage.CompletionTokens {
					t.Errorf("unexpected token usage: %+v", resp.Usage)
				}
			}
		})
	}
}

func TestRateLimiting(t *testing.T) {
	mux := newTestMux(t)
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`

	// Send defaultRateLimit requests from the same IP (with different source ports)
	for i := 0; i < defaultRateLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:5000"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}

	// Next request from the same IP (even with a different port) must be blocked with 429
	blockedReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	blockedReq.RemoteAddr = "192.0.2.10:5001"
	blockedRec := httptest.NewRecorder()
	mux.ServeHTTP(blockedRec, blockedReq)

	if blockedRec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked request: status = %d, want %d", blockedRec.Code, http.StatusTooManyRequests)
	}

	// Request from a different IP must still succeed
	otherIPReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	otherIPReq.RemoteAddr = "192.0.2.99:5000"
	otherIPRec := httptest.NewRecorder()
	mux.ServeHTTP(otherIPRec, otherIPReq)

	if otherIPRec.Code != http.StatusOK {
		t.Fatalf("other IP request: status = %d, want %d", otherIPRec.Code, http.StatusOK)
	}
}
