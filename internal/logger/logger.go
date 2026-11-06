package logger

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/models"
)

type Logger struct {
	file   *os.File
	logger *slog.Logger
}

func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	return &Logger{
		file:   file,
		logger: slog.New(slog.NewJSONHandler(file, nil)),
	}, nil
}

func (l *Logger) LogRequest(r *http.Request, request models.ChatCompletionRequest, findings []detection.Finding) {
	hasAuth, authHash := hashAuthHeader(r)

	l.logger.Info("request received",
		"method", r.Method,
		"path", r.URL.Path,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"has_auth_header", hasAuth,
		"auth_sha256", authHash,
		"model", request.Model,
		"message_count", len(request.Messages),
		"prompt_sha256", hashMessages(request.Messages),
		"is_suspicious", len(findings) > 0,
		"findings", findings,
	)
}

func hashAuthHeader(r *http.Request) (bool, string) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return false, ""
	}
	sum := sha256.Sum256([]byte(auth))
	return true, hex.EncodeToString(sum[:])
}

func hashMessages(messages []models.Message) string {
	if len(messages) == 0 {
		return ""
	}
	hasher := sha256.New()
	for _, msg := range messages {
		hasher.Write([]byte(msg.Role))
		hasher.Write([]byte(":"))
		hasher.Write([]byte(msg.Content))
		hasher.Write([]byte("\n"))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func (l *Logger) Close() error {
	return l.file.Close()
}
