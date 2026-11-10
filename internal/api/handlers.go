package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/logger"
	"github.com/efronh/go-llm-honeypot/internal/models"
)

const maxRequestBody = 1 << 20

type Handler struct {
	detector        *detection.Detector
	logger          *logger.Logger
	limiter         *RateLimiter
	telemetryErrors atomic.Uint64
}

func NewHandler(detector *detection.Detector, requestLogger *logger.Logger) *Handler {
	return &Handler{
		detector: detector,
		logger:   requestLogger,
		limiter:  NewRateLimiter(defaultRateLimit, defaultRateWindow),
	}
}

func (h *Handler) TelemetryErrorCount() uint64 {
	return h.telemetryErrors.Load()
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.health)
	mux.HandleFunc("/v1/models", h.listModels)
	mux.HandleFunc("/v1/chat/completions", h.chatCompletions)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		if h.checkRateLimit(w, r) {
			h.rejectRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) listModels(w http.ResponseWriter, r *http.Request) {
	if !h.checkRateLimit(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		h.rejectRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
		return
	}

	if !h.recordRequest(w, r, models.ChatCompletionRequest{}, []detection.Finding{}) {
		return
	}

	writeJSON(w, http.StatusOK, models.ModelListResponse{
		Object: "list",
		Data: []models.ModelInfo{
			{
				ID:      "gpt-4o",
				Object:  "model",
				Created: 1715368132,
				OwnedBy: "system",
			},
			{
				ID:      "gpt-4o-mini",
				Object:  "model",
				Created: 1721172741,
				OwnedBy: "system",
			},
		},
	})
}

func (h *Handler) chatCompletions(w http.ResponseWriter, r *http.Request) {
	if !h.checkRateLimit(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		h.rejectRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close()

	var request models.ChatCompletionRequest
	var maxBytesErr *http.MaxBytesError
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		if errors.As(err, &maxBytesErr) {
			h.rejectRequest(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large", nil)
			return
		}
		h.rejectRequest(w, r, http.StatusBadRequest, "malformed_json", "invalid JSON request", nil)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if errors.As(err, &maxBytesErr) {
			h.rejectRequest(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large", nil)
			return
		}
		h.rejectRequest(w, r, http.StatusBadRequest, "multiple_json_values", "request must contain a single JSON value", nil)
		return
	}
	if len(request.Messages) == 0 {
		h.rejectRequest(w, r, http.StatusBadRequest, "empty_messages", "messages must not be empty", nil)
		return
	}

	findings := h.detector.Analyze(request)
	if !h.recordRequest(w, r, request, findings) {
		return
	}

	model := request.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	reply := buildDecoyReply(findings)
	usage := calculateUsage(request.Messages, reply)

	writeJSON(w, http.StatusOK, models.ChatCompletionResponse{
		ID:      "chatcmpl-" + time.Now().UTC().Format("20060102T150405.000000000"),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []models.Choice{{
			Index: 0,
			Message: models.Message{
				Role:    "assistant",
				Content: reply,
			},
			FinishReason: "stop",
		}},
		Usage: usage,
	})
}

func (h *Handler) recordRequest(w http.ResponseWriter, r *http.Request, request models.ChatCompletionRequest, findings []detection.Finding) bool {
	if err := h.logger.LogRequest(r, request, findings); err != nil {
		h.telemetryErrors.Add(1)
		log.Printf("telemetry error: failed to log accepted request (method=%s path=%s): %v", r.Method, r.URL.Path, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *Handler) rejectRequest(w http.ResponseWriter, r *http.Request, statusCode int, eventType string, reason string, extraMeta map[string]any) {
	if err := h.logger.LogRejectedRequest(r, statusCode, eventType, reason, extraMeta); err != nil {
		h.telemetryErrors.Add(1)
		log.Printf("telemetry error: failed to log rejected request (method=%s path=%s status=%d type=%s): %v",
			r.Method, r.URL.Path, statusCode, eventType, err)
	}
	http.Error(w, reason, statusCode)
}

func (h *Handler) checkRateLimit(w http.ResponseWriter, r *http.Request) bool {
	allowed, shouldLog, violations := h.limiter.Check(clientIP(r.RemoteAddr))
	if !allowed {
		if shouldLog {
			h.rejectRequest(w, r, http.StatusTooManyRequests, "rate_limit_exceeded", "rate limit exceeded", map[string]any{
				"violation_count": violations,
			})
		} else {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		}
		return false
	}
	return true
}

func buildDecoyReply(findings []detection.Finding) string {
	for _, f := range findings {
		switch f.Category {
		case detection.CategorySystemPromptExtraction:
			return "I cannot share internal system instructions or configuration details. How else can I assist you?"
		case detection.CategoryPromptInjection, detection.CategoryJailbreak:
			return "I'm sorry, but I cannot comply with instructions that override safety guidelines or system policies."
		case detection.CategoryRoleManipulation, detection.CategoryObfuscation, detection.CategoryMultiTurn:
			return "I can only process standard user requests in plain text. Please rephrase your request."
		}
	}
	return "I have processed your request. Could you provide more details on how you would like to proceed?"
}

func estimateTokens(text string) int {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0
	}
	return (len(trimmed) + 3) / 4
}

func calculateUsage(messages []models.Message, reply string) models.Usage {
	promptTokens := 0
	for _, msg := range messages {
		promptTokens += 3 + estimateTokens(msg.Role) + estimateTokens(msg.Content)
	}
	completionTokens := estimateTokens(reply)
	return models.Usage{
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      promptTokens + completionTokens,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
