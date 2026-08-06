package rules

import (
	"github.com/sergeyptv/config-auditor/internal/configutil"
	"github.com/sergeyptv/config-auditor/internal/model"
	"strings"
)

const debugLoggingRuleID = "CFG001"

type DebugLoggingRule struct{}

func NewDebugLoggingRule() *DebugLoggingRule {
	return &DebugLoggingRule{}
}

func (r *DebugLoggingRule) ID() string {
	return debugLoggingRuleID
}

func (r *DebugLoggingRule) Check(cfg map[string]any) []model.Issue {
	var issues []model.Issue

	configutil.Walk(cfg, func(entry configutil.Entry) {
		if !isLoggingLevelPath(entry.Path) {
			return
		}

		lvl, ok := entry.Value.(string)
		if !ok {
			return
		}

		if !strings.EqualFold(strings.TrimSpace(lvl), "debug") {
			return
		}

		issues = append(issues, model.Issue{
			RuleID:         r.ID(),
			Severity:       model.SeverityLow,
			Path:           entry.Path,
			Message:        "Установлен debug уровень логирования",
			Recommendation: "Используйте уровень логирования info или выше",
		})
	})

	return issues
}

func isLoggingLevelPath(path string) bool {
	normalizedPath := strings.ToLower(path)
	parts := strings.Split(normalizedPath, ".")

	if len(parts) < 2 {
		return false
	}

	lastPart := parts[len(parts)-1]
	parentPart := parts[len(parts)-2]

	if lastPart != "level" {
		return false
	}

	switch parentPart {
	case "log", "logging", "logger":
		return true
	default:
		return false
	}
}
