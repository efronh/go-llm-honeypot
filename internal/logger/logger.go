package logger

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/efronh/go-llm-honeypot/internal/detection"
	"github.com/efronh/go-llm-honeypot/internal/models"
)

const defaultMaxLogSize = 10 << 20 // 10 MB

type Logger struct {
	mu          sync.Mutex
	path        string
	file        *os.File
	hmacKey     []byte
	maxSize     int64
	currentSize int64
}

func New(path string) (*Logger, error) {
	hmacKey, err := loadHMACKey()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	return &Logger{
		path:        path,
		file:        file,
		hmacKey:     hmacKey,
		maxSize:     defaultMaxLogSize,
		currentSize: info.Size(),
	}, nil
}

func (l *Logger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxSize > 0 && l.currentSize > 0 && l.currentSize+int64(len(p)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := l.file.Write(p)
	l.currentSize += int64(n)
	return n, err
}

func (l *Logger) rotate() error {
	if err := l.file.Close(); err != nil {
		return err
	}

	backupPath := l.path + ".1"
	_ = os.Remove(backupPath)
	if err := os.Rename(l.path, backupPath); err != nil {
		return err
	}

	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.file = file
	l.currentSize = 0
	return nil
}

func (l *Logger) LogEvent(event models.Event) {
	if event.EventID == "" {
		event.EventID = newEventID()
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}

	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = l.Write(line)
}

func (l *Logger) LogRequest(r *http.Request, request models.ChatCompletionRequest, findings []detection.Finding) {
	hasAuth, authScheme, authHMAC := l.inspectAuthHeader(r)
	promptHMAC := l.hashMessages(request.Messages)
	srcIP, srcPort := splitAddr(r.RemoteAddr)

	eventType, severity, confidence := classifyAPIEvent(r.URL.Path, findings)
	evidenceHash := promptHMAC
	if evidenceHash == "" {
		evidenceHash = authHMAC
	}

	event := models.Event{
		EventID:      newEventID(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		Sensor:       models.SensorAPI,
		SourceIP:     srcIP,
		EventType:    eventType,
		Severity:     severity,
		Confidence:   confidence,
		Target:       r.URL.Path,
		EvidenceHash: evidenceHash,
		Metadata: map[string]any{
			"method":             r.Method,
			"source_port":        srcPort,
			"user_agent":         r.UserAgent(),
			"has_auth_header":    hasAuth,
			"auth_scheme":        authScheme,
			"auth_hmac_sha256":   authHMAC,
			"model":              request.Model,
			"message_count":      len(request.Messages),
			"prompt_hmac_sha256": promptHMAC,
			"is_suspicious":      len(findings) > 0,
			"findings":           findings,
		},
	}

	l.LogEvent(event)
}

func classifyAPIEvent(path string, findings []detection.Finding) (string, string, float64) {
	if len(findings) == 0 {
		if path == "/v1/models" {
			return "api_recon", "info", 1.0
		}
		return "benign_request", "info", 1.0
	}

	primary := findings[0]
	for _, f := range findings[1:] {
		if severityRank(f.Severity) > severityRank(primary.Severity) {
			primary = f
		}
	}
	return primary.Category, primary.Severity, primary.Confidence
}

func severityRank(severity string) int {
	switch severity {
	case detection.SeverityHigh:
		return 3
	case detection.SeverityMedium:
		return 2
	case detection.SeverityLow:
		return 1
	default:
		return 0
	}
}

func splitAddr(remoteAddr string) (string, string) {
	trimmed := strings.TrimSpace(remoteAddr)
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return trimmed, ""
	}
	return host, port
}

func newEventID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "evt-" + time.Now().UTC().Format("20060102150405.000000")
	}
	return "evt-" + hex.EncodeToString(b[:])
}

func (l *Logger) inspectAuthHeader(r *http.Request) (bool, string, string) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return false, "", ""
	}

	scheme := "custom"
	if parts := strings.Fields(auth); len(parts) >= 2 {
		candidate := strings.ToLower(parts[0])
		if candidate == "bearer" || candidate == "basic" {
			scheme = candidate
		}
	}

	return true, scheme, computeHMAC(l.hmacKey, []byte(auth))
}

func (l *Logger) hashMessages(messages []models.Message) string {
	if len(messages) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, l.hmacKey)
	for _, msg := range messages {
		mac.Write([]byte(msg.Role))
		mac.Write([]byte(":"))
		mac.Write([]byte(msg.Content))
		mac.Write([]byte("\n"))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func computeHMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func loadHMACKey() ([]byte, error) {
	if keyFile := strings.TrimSpace(os.Getenv("HMAC_KEY_FILE")); keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			return nil, errors.New("HMAC_KEY_FILE is empty")
		}
		return trimmed, nil
	}

	if envKey := strings.TrimSpace(os.Getenv("HMAC_KEY")); envKey != "" {
		return []byte(envKey), nil
	}

	ephemeral := make([]byte, 32)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, err
	}
	return ephemeral, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

type Summary struct {
	TotalRequests      int            `json:"total_requests"`
	SuspiciousRequests int            `json:"suspicious_requests"`
	BySensor           map[string]int `json:"by_sensor"`
	ByEventType        map[string]int `json:"by_event_type"`
	ByPath             map[string]int `json:"by_path"`
	ByModel            map[string]int `json:"by_model"`
	ByCategory         map[string]int `json:"by_category"`
	BySeverity         map[string]int `json:"by_severity"`
}

type storedEvent struct {
	Sensor    string            `json:"sensor"`
	EventType string            `json:"event_type"`
	Severity  string            `json:"severity"`
	Target    string            `json:"target"`
	Path      string            `json:"path"`
	Metadata  storedEventMeta   `json:"metadata"`
	Findings  []detection.Finding `json:"findings"`
}

type storedEventMeta struct {
	Model        string              `json:"model"`
	IsSuspicious bool                `json:"is_suspicious"`
	Findings     []detection.Finding `json:"findings"`
}

func Summarize(path string) (Summary, error) {
	summary := Summary{
		BySensor:    make(map[string]int),
		ByEventType: make(map[string]int),
		ByPath:      make(map[string]int),
		ByModel:     make(map[string]int),
		ByCategory:  make(map[string]int),
		BySeverity:  make(map[string]int),
	}

	file, err := os.Open(path)
	if err != nil {
		return summary, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev storedEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}

		summary.TotalRequests++
		if ev.Sensor != "" {
			summary.BySensor[ev.Sensor]++
		}
		if ev.EventType != "" {
			summary.ByEventType[ev.EventType]++
		}

		target := ev.Target
		if target == "" {
			target = ev.Path
		}
		if target != "" {
			summary.ByPath[target]++
		}

		if ev.Metadata.Model != "" {
			summary.ByModel[ev.Metadata.Model]++
		}

		findings := ev.Metadata.Findings
		if len(findings) == 0 {
			findings = ev.Findings
		}

		isSuspicious := ev.Metadata.IsSuspicious || len(findings) > 0 || (ev.Severity != "" && ev.Severity != "info")
		if isSuspicious {
			summary.SuspiciousRequests++
		}

		for _, f := range findings {
			if f.Category != "" {
				summary.ByCategory[f.Category]++
			}
			if f.Severity != "" {
				summary.BySeverity[f.Severity]++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return summary, err
	}
	return summary, nil
}
