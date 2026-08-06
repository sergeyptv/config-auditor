package analyzer

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/rules"
)

type Analyzer struct {
	rules []rules.Rule
}

func New(configuredRules ...rules.Rule) *Analyzer {
	rulesCopy := make([]rules.Rule, len(configuredRules))
	copy(rulesCopy, configuredRules)

	return &Analyzer{rules: rulesCopy}
}

func (a *Analyzer) Analyze(cfg map[string]any) []model.Issue {
	var issues []model.Issue

	for _, rule := range a.rules {
		issues = append(issues, rule.Check(cfg)...)
	}

	model.SortIssues(issues)

	return issues
}
