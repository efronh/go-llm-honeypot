package detection

import (
	"strings"

	"github.com/efronh/go-llm-honeypot/internal/models"
)

const (
	CategoryPromptInjection        = "prompt_injection"
	CategorySystemPromptExtraction = "system_prompt_extraction"
	CategoryJailbreak              = "jailbreak"
	CategoryRoleManipulation       = "role_manipulation"
	CategoryObfuscation            = "obfuscation"

	SeverityHigh   = "high"
	SeverityMedium = "medium"
)

type Rule struct {
	Category  string
	Severity  string
	Indicator string
}

type Finding struct {
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Indicator string `json:"indicator"`
}

type Detector struct {
	rules []Rule
}

func NewDetector() *Detector {
	return &Detector{
		rules: []Rule{
			// Prompt Injection & Delimiter/Token Injection
			{
				Category:  CategoryPromptInjection,
				Severity:  SeverityHigh,
				Indicator: "ignore all previous instructions",
			},
			{
				Category:  CategoryPromptInjection,
				Severity:  SeverityHigh,
				Indicator: "ignore previous instructions",
			},
			{
				Category:  CategoryPromptInjection,
				Severity:  SeverityHigh,
				Indicator: "disregard previous instructions",
			},
			{
				Category:  CategoryPromptInjection,
				Severity:  SeverityHigh,
				Indicator: "<|im_start|>",
			},
			{
				Category:  CategoryPromptInjection,
				Severity:  SeverityHigh,
				Indicator: "[inst]",
			},

			// System Prompt Extraction
			{
				Category:  CategorySystemPromptExtraction,
				Severity:  SeverityHigh,
				Indicator: "reveal the system prompt",
			},
			{
				Category:  CategorySystemPromptExtraction,
				Severity:  SeverityHigh,
				Indicator: "show me your system prompt",
			},
			{
				Category:  CategorySystemPromptExtraction,
				Severity:  SeverityHigh,
				Indicator: "repeat the words above",
			},
			{
				Category:  CategorySystemPromptExtraction,
				Severity:  SeverityMedium,
				Indicator: "what are your instructions",
			},
			{
				Category:  CategorySystemPromptExtraction,
				Severity:  SeverityMedium,
				Indicator: "developer message",
			},

			// Jailbreak
			{
				Category:  CategoryJailbreak,
				Severity:  SeverityHigh,
				Indicator: "jailbreak",
			},
			{
				Category:  CategoryJailbreak,
				Severity:  SeverityHigh,
				Indicator: "do anything now",
			},
			{
				Category:  CategoryJailbreak,
				Severity:  SeverityHigh,
				Indicator: "dan mode",
			},
			{
				Category:  CategoryJailbreak,
				Severity:  SeverityHigh,
				Indicator: "bypass safety",
			},

			// Obfuscation / Encoding Evasion
			{
				Category:  CategoryObfuscation,
				Severity:  SeverityMedium,
				Indicator: "base64",
			},
			{
				Category:  CategoryObfuscation,
				Severity:  SeverityMedium,
				Indicator: "rot13",
			},
		},
	}
}

func (d *Detector) Analyze(request models.ChatCompletionRequest) []Finding {
	findings := []Finding{}
	seen := make(map[string]bool)

	addFinding := func(category, severity, indicator string) {
		if !seen[indicator] {
			seen[indicator] = true
			findings = append(findings, Finding{
				Category:  category,
				Severity:  severity,
				Indicator: indicator,
			})
		}
	}

	for _, message := range request.Messages {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if role == "system" || role == "developer" {
			addFinding(CategoryRoleManipulation, SeverityMedium, "privileged_role:"+role)
		}

		content := strings.ToLower(message.Content)
		for _, rule := range d.rules {
			if strings.Contains(content, rule.Indicator) {
				addFinding(rule.Category, rule.Severity, rule.Indicator)
			}
		}
	}
	return findings
}
