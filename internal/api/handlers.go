package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/logger"
	"github.com/efronh/go-llm-honeypot/internal/models"
)

const maxRequestBody = 1 << 20

type Handler struct {
	detector *detection.Detector
	logger   *logger.Logger
	limiter  *RateLimiter
}

func NewHandler(detector *detection.Detector, requestLogger *logger.Logger) *Handler {
	return &Handler{
		detector: detector,
		logger:   requestLogger,
		limiter:  NewRateLimiter(defaultRateLimit, defaultRateWindow),
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.health)
	mux.HandleFunc("/v1/models", h.listModels)
	mux.HandleFunc("/v1/chat/completions", h.chatCompletions)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		if h.checkRateLimit(w, r) {
			_ = h.logger.LogRejectedRequest(r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		_ = h.logger.LogRejectedRequest(r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.logger.LogRequest(r, models.ChatCompletionRequest{}, []detection.Finding{}); err != nil {
		log.Printf("failed to log /v1/models request: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
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
		_ = h.logger.LogRejectedRequest(r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close()

	var request models.ChatCompletionRequest
	var maxBytesErr *http.MaxBytesError
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		if errors.As(err, &maxBytesErr) {
			_ = h.logger.LogRejectedRequest(r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large", nil)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		_ = h.logger.LogRejectedRequest(r, http.StatusBadRequest, "malformed_json", "invalid JSON request", nil)
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if errors.As(err, &maxBytesErr) {
			_ = h.logger.LogRejectedRequest(r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large", nil)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		_ = h.logger.LogRejectedRequest(r, http.StatusBadRequest, "multiple_json_values", "request must contain a single JSON value", nil)
		http.Error(w, "request must contain a single JSON value", http.StatusBadRequest)
		return
	}
	if len(request.Messages) == 0 {
		_ = h.logger.LogRejectedRequest(r, http.StatusBadRequest, "empty_messages", "messages must not be empty", nil)
		http.Error(w, "messages must not be empty", http.StatusBadRequest)
		return
	}

	findings := h.detector.Analyze(request)
	if err := h.logger.LogRequest(r, request, findings); err != nil {
		log.Printf("failed to log chat completion request: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
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

func (h *Handler) checkRateLimit(w http.ResponseWriter, r *http.Request) bool {
	allowed, shouldLog, violations := h.limiter.Check(clientIP(r.RemoteAddr))
	if !allowed {
		if shouldLog {
			_ = h.logger.LogRejectedRequest(r, http.StatusTooManyRequests, "rate_limit_exceeded", "rate limit exceeded", map[string]any{
				"violation_count": violations,
			})
		}
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
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
