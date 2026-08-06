package rules

import (
	"encoding/json"
	"github.com/sergeyptv/config-auditor/internal/configutil"
	"github.com/sergeyptv/config-auditor/internal/model"
	"regexp"
	"strings"
)

const plaintextPasswordRuleID = "CFG002"

var (
	environmentReferencePattern = regexp.MustCompile(`^\$\{[^{}]+\}$`)
	shellReferencePattern       = regexp.MustCompile(`^\$\([A-Za-z_][A-Za-z0-9_]*\)$`)
	templateReferencePattern    = regexp.MustCompile(`^\{\{.+\}\}$`)
)

type PlaintextPasswordRule struct{}

func NewPlaintextPasswordRule() *PlaintextPasswordRule {
	return &PlaintextPasswordRule{}
}

func (r *PlaintextPasswordRule) ID() string {
	return plaintextPasswordRuleID
}

func (r *PlaintextPasswordRule) Check(cfg map[string]any) []model.Issue {
	var issues []model.Issue

	configutil.Walk(cfg, func(entry configutil.Entry) {
		if !isPasswordKey(entry.Key) {
			return
		}

		if !isPlaintextPasswordValue(entry.Value) {
			return
		}

		issues = append(issues, model.Issue{
			RuleID:         r.ID(),
			Severity:       model.SeverityHigh,
			Path:           entry.Path,
			Message:        "Пароль в конфигурации хранится в открытом виде",
			Recommendation: "Удалите пароль из конфигурации и передавайте его через переменную окружения или менеджер секретов",
		})
	})

	return issues
}

func isPasswordKey(key string) bool {
	normalized := normalizeKey(key)

	if normalized == "" {
		return false
	}

	if strings.Contains(normalized, "hash") ||
		strings.Contains(normalized, "digest") ||
		strings.Contains(normalized, "encrypted") ||
		strings.Contains(normalized, "ciphertext") {
		return false
	}

	switch normalized {
	case "password", "passwd", "pwd":
		return true
	}

	return strings.HasSuffix(normalized, "password") ||
		strings.HasSuffix(normalized, "passwd") ||
		strings.HasSuffix(normalized, "pwd")
}

func isPlaintextPasswordValue(value any) bool {
	switch typedValue := value.(type) {
	case string:
		return isLiteralSecret(typedValue)

	case json.Number:
		return strings.TrimSpace(typedValue.String()) != ""

	case int, int8, int16, int32, int64:
		return true

	case uint, uint8, uint16, uint32, uint64:
		return true

	case float32, float64:
		return true

	default:
		return false
	}
}

func isLiteralSecret(value string) bool {
	value = strings.TrimSpace(value)

	if value == "" {
		return false
	}

	if isSecretReference(value) {
		return false
	}

	return true
}

func isSecretReference(value string) bool {
	if environmentReferencePattern.MatchString(value) ||
		shellReferencePattern.MatchString(value) ||
		templateReferencePattern.MatchString(value) {
		return true
	}

	normalized := strings.ToLower(strings.TrimSpace(value))

	safePrefixes := []string{
		"env:",
		"secret://",
		"vault://",
		"file://",
		"ref://",
		"aws-secrets://",
		"gcp-secrets://",
	}

	for _, prefix := range safePrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}

	return false
}
