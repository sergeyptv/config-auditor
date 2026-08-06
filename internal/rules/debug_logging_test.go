package rules

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"testing"
)

func TestDebugLoggingRule_Check(t *testing.T) {
	tests := []struct {
		name             string
		cfg              map[string]any
		expectedIssues   int
		expectedPath     string
		expectedSeverity model.Severity
	}{
		{
			name: "debug logging level detected",
			cfg: map[string]any{
				"log": map[string]any{
					"level": "debug",
				},
			},
			expectedIssues:   1,
			expectedPath:     "log.level",
			expectedSeverity: model.SeverityLow,
		},
		{
			name: "nested debug logging level detected",
			cfg: map[string]any{
				"application": map[string]any{
					"logging": map[string]any{
						"level": "DEBUG",
					},
				},
			},
			expectedIssues:   1,
			expectedPath:     "application.logging.level",
			expectedSeverity: model.SeverityLow,
		},
		{
			name: "info logging level",
			cfg: map[string]any{
				"log": map[string]any{
					"level": "info",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "unrelated debug level",
			cfg: map[string]any{
				"compression": map[string]any{
					"level": "debug",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "no string logging level",
			cfg: map[string]any{
				"log": map[string]any{
					"level": 3,
				},
			},
			expectedIssues: 0,
		},
	}

	rule := NewDebugLoggingRule()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := rule.Check(test.cfg)

			if len(issues) != test.expectedIssues {
				t.Fatalf("expected %d issues, got %d", test.expectedIssues, len(issues))
			}

			if test.expectedIssues == 0 {
				return
			}

			issue := issues[0]

			if issue.RuleID != rule.ID() {
				t.Errorf("expected rule ID %q, got %q", rule.ID(), issue.RuleID)
			}

			if issue.Path != test.expectedPath {
				t.Errorf("expected path %q, got %q", test.expectedPath, issue.Path)
			}

			if issue.Severity != test.expectedSeverity {
				t.Errorf("expected severity %q, got %q", test.expectedSeverity, issue.Severity)
			}
		})
	}
}
