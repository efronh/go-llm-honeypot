package models

type ChatCompletionRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type ModelListResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

const (
	SensorAPI     = "api"
	SensorSSH     = "ssh"
	SensorNetwork = "network"
	SensorProcess = "process"
)

type Event struct {
	EventID      string         `json:"event_id"`
	Timestamp    string         `json:"timestamp"`
	Sensor       string         `json:"sensor"`
	SourceIP     string         `json:"source_ip"`
	EventType    string         `json:"event_type"`
	Severity     string         `json:"severity"`
	Confidence   float64        `json:"confidence"`
	Target       string         `json:"target"`
	EvidenceHash string         `json:"evidence_hash"`
	Metadata     map[string]any `json:"metadata"`
}
