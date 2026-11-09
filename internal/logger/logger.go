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

const (
	defaultMaxLogSize           = 10 << 20 // 10 MB
	maxScannerBuffer            = 1 << 20  // 1 MB max line size for Summarize
	minHMACKeyLength            = 16
	logFilePerm     os.FileMode = 0o600
)

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
	file, info, err := openSecureLogFile(path)
	if err != nil {
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

func openSecureLogFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFilePerm)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("log path must be a regular file")
	}

	if info.Mode().Perm() != logFilePerm {
		if err := file.Chmod(logFilePerm); err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		info, err = file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		if info.Mode().Perm() != logFilePerm {
			_ = file.Close()
			return nil, nil, errors.New("failed to enforce 0600 permissions on log file")
		}
	}

	return file, info, nil
}

func (l *Logger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return 0, errors.New("logger file is closed")
	}

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
	l.file = nil

	backupPath := l.path + ".1"
	_ = os.Remove(backupPath)
	if err := os.Rename(l.path, backupPath); err != nil {
		return err
	}
	if err := os.Chmod(backupPath, logFilePerm); err != nil {
		return err
	}

	file, info, err := openSecureLogFile(l.path)
	if err != nil {
		return err
	}
	l.file = file
	l.currentSize = info.Size()
	return nil
}

func (l *Logger) LogEvent(event models.Event) error {
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
		return err
	}
	line = append(line, '\n')
	_, err = l.Write(line)
	return err
}

func (l *Logger) LogRequest(r *http.Request, request models.ChatCompletionRequest, findings []detection.Finding) error {
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

	return l.LogEvent(event)
}

func (l *Logger) LogRejectedRequest(r *http.Request, statusCode int, eventType string, reason string, extraMeta map[string]any) error {
	hasAuth, authScheme, authHMAC := l.inspectAuthHeader(r)
	srcIP, srcPort := splitAddr(r.RemoteAddr)

	severity := detection.SeverityLow
	isSuspicious := false
	if statusCode == http.StatusTooManyRequests || statusCode == http.StatusRequestEntityTooLarge || eventType == "multiple_json_values" {
		severity = detection.SeverityMedium
		isSuspicious = true
	}

	meta := map[string]any{
		"method":           r.Method,
		"source_port":      srcPort,
		"user_agent":       r.UserAgent(),
		"status_code":      statusCode,
		"reason":           reason,
		"has_auth_header":  hasAuth,
		"auth_scheme":      authScheme,
		"auth_hmac_sha256": authHMAC,
		"is_suspicious":    isSuspicious,
	}
	for k, v := range extraMeta {
		meta[k] = v
	}

	event := models.Event{
		EventID:      newEventID(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		Sensor:       models.SensorAPI,
		SourceIP:     srcIP,
		EventType:    eventType,
		Severity:     severity,
		Confidence:   1.0,
		Target:       r.URL.Path,
		EvidenceHash: authHMAC,
		Metadata:     meta,
	}

	return l.LogEvent(event)
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
	encoded, err := json.Marshal(messages)
	if err != nil {
		return ""
	}
	return computeHMAC(l.hmacKey, encoded)
}

func computeHMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func loadHMACKey() ([]byte, error) {
	if keyFile := strings.TrimSpace(os.Getenv("HMAC_KEY_FILE")); keyFile != "" {
		info, err := os.Stat(keyFile)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("HMAC_KEY_FILE must be a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("HMAC_KEY_FILE permissions are too open: must not be accessible by group or others (use 0600 or 0400)")
		}
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) < minHMACKeyLength {
			return nil, errors.New("HMAC key in HMAC_KEY_FILE must be at least 16 bytes")
		}
		return trimmed, nil
	}

	if envKey := strings.TrimSpace(os.Getenv("HMAC_KEY")); envKey != "" {
		if len(envKey) < minHMACKeyLength {
			return nil, errors.New("HMAC_KEY must be at least 16 bytes")
		}
		return []byte(envKey), nil
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv("REQUIRE_HMAC_KEY")), "true") {
		return nil, errors.New("persistent HMAC_KEY_FILE or HMAC_KEY is required when REQUIRE_HMAC_KEY=true")
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
	err := l.file.Close()
	l.file = nil
	return err
}

type Summary struct {
	TotalEvents        int            `json:"total_events"`
	SuspiciousEvents   int            `json:"suspicious_events"`
	TotalRequests      int            `json:"total_requests"`
	SuspiciousRequests int            `json:"suspicious_requests"`
	BySensor           map[string]int `json:"by_sensor"`
	ByEventType        map[string]int `json:"by_event_type"`
	ByEventSeverity    map[string]int `json:"by_event_severity"`
	ByFindingSeverity  map[string]int `json:"by_finding_severity"`
	ByPath             map[string]int `json:"by_path"`
	ByModel            map[string]int `json:"by_model"`
	ByCategory         map[string]int `json:"by_category"`
	BySeverity         map[string]int `json:"by_severity"`
}

type storedEvent struct {
	Sensor    string              `json:"sensor"`
	EventType string              `json:"event_type"`
	Severity  string              `json:"severity"`
	Target    string              `json:"target"`
	Path      string              `json:"path"`
	Metadata  storedEventMeta     `json:"metadata"`
	Findings  []detection.Finding `json:"findings"`
}

type storedEventMeta struct {
	Model        string              `json:"model"`
	IsSuspicious bool                `json:"is_suspicious"`
	Findings     []detection.Finding `json:"findings"`
}

func Summarize(path string) (Summary, error) {
	summary := Summary{
		BySensor:          make(map[string]int),
		ByEventType:       make(map[string]int),
		ByEventSeverity:   make(map[string]int),
		ByFindingSeverity: make(map[string]int),
		ByPath:            make(map[string]int),
		ByModel:           make(map[string]int),
		ByCategory:        make(map[string]int),
		BySeverity:        make(map[string]int),
	}

	file, err := os.Open(path)
	if err != nil {
		return summary, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxScannerBuffer)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev storedEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}

		summary.TotalEvents++
		summary.TotalRequests++

		if ev.Sensor != "" {
			summary.BySensor[ev.Sensor]++
		}
		if ev.EventType != "" {
			summary.ByEventType[ev.EventType]++
		}
		if ev.Severity != "" {
			summary.ByEventSeverity[ev.Severity]++
			summary.BySeverity[ev.Severity]++
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
			summary.SuspiciousEvents++
			summary.SuspiciousRequests++
		}

		for _, f := range findings {
			if f.Category != "" {
				summary.ByCategory[f.Category]++
			}
			if f.Severity != "" {
				summary.ByFindingSeverity[f.Severity]++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return summary, err
	}
	return summary, nil
}
