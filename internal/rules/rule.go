package rules

import "github.com/sergeyptv/config-auditor/internal/model"

type Rule interface {
	ID() string
	Check(cfg map[string]any) []model.Issue
}
