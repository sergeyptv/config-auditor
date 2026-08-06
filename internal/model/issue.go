package model

type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Issue struct {
	RuleID         string   `json:"rule_id"`
	Severity       Severity `json:"severity"`
	Path           string   `json:"path,omitempty"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
}
