package analyzer

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"testing"
)

type stubRule struct {
	id     string
	issues []model.Issue
}

func (r stubRule) ID() string {
	return r.id
}

func (r stubRule) Check(_ map[string]any) []model.Issue {
	return r.issues
}

func TestAnalyzer_Analyze(t *testing.T) {
	firstRule := stubRule{
		id: "TEST001",
		issues: []model.Issue{
			{
				RuleID:         "TEST001",
				Severity:       model.SeverityLow,
				Path:           "log.level",
				Message:        "Первая проблема",
				Recommendation: "Первая рекомендация",
			},
		},
	}

	secondRule := stubRule{
		id: "TEST002",
		issues: []model.Issue{
			{
				RuleID:         "TEST002",
				Severity:       model.SeverityHigh,
				Path:           "storage.algorithm",
				Message:        "Вторая проблема",
				Recommendation: "Вторая рекомендация",
			},
		},
	}

	securityAnalyzer := New(firstRule, secondRule)

	issues := securityAnalyzer.Analyze(map[string]any{})

	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}

	if issues[0].RuleID != "TEST002" {
		t.Errorf("expected first rule ID %q, got %q", "TEST002", issues[0].RuleID)
	}

	if issues[1].RuleID != "TEST001" {
		t.Errorf("expected second rule ID %q, got %q", "TEST001", issues[1].RuleID)
	}
}

func TestAnalyzer_AnalyzeWithoutRules(t *testing.T) {
	securityAnalyzer := New()

	issues := securityAnalyzer.Analyze(map[string]any{})

	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %d", len(issues))
	}
}

func TestAnalyzer_AnalyzeSortsIssues(t *testing.T) {
	rule := stubRule{
		id: "TEST001",
		issues: []model.Issue{
			{
				RuleID:   "TEST003",
				Severity: model.SeverityLow,
				Path:     "log.level",
			},
			{
				RuleID:   "TEST002",
				Severity: model.SeverityHigh,
				Path:     "server.tls",
			},
			{
				RuleID:   "TEST001",
				Severity: model.SeverityHigh,
				Path:     "database.password",
			},
			{
				RuleID:   "TEST004",
				Severity: model.SeverityMedium,
				Path:     "server.host",
			},
		},
	}

	securityAnalyzer := New(rule)
	issues := securityAnalyzer.Analyze(map[string]any{})

	expectedRuleIDs := []string{
		"TEST001",
		"TEST002",
		"TEST004",
		"TEST003",
	}

	if len(issues) != len(expectedRuleIDs) {
		t.Fatalf("expected %d issues, got %d", len(expectedRuleIDs), len(issues))
	}

	for idx, expectedRuleID := range expectedRuleIDs {
		if issues[idx].RuleID != expectedRuleID {
			t.Errorf("issue %d: expected rule ID %q, got %q", idx, expectedRuleID, issues[idx].RuleID)
		}
	}
}
