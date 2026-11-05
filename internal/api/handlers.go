package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	mux.HandleFunc("/v1/chat/completions", h.chatCompletions)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) chatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.limiter.Allow(clientIP(r.RemoteAddr)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close()

	var request models.ChatCompletionRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "request must contain a single JSON value", http.StatusBadRequest)
		return
	}
	if len(request.Messages) == 0 {
		http.Error(w, "messages must not be empty", http.StatusBadRequest)
		return
	}

	findings := h.detector.Analyze(request)
	h.logger.LogRequest(r, request, findings)

	model := request.Model
	if model == "" {
		model = "honeypot-stub"
	}
	writeJSON(w, http.StatusOK, models.ChatCompletionResponse{
		ID:      "chatcmpl-" + time.Now().UTC().Format("20060102T150405.000000000"),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []models.Choice{{
			Index: 0,
			Message: models.Message{
				Role:    "assistant",
				Content: "Request received.",
			},
			FinishReason: "stop",
		}},
		Usage: models.Usage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
