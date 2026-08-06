package rules

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"strings"
	"testing"
)

func TestPlaintextPasswordRule_Check(t *testing.T) {
	tests := []struct {
		name             string
		cfg              map[string]any
		expectedIssues   int
		expectedPath     string
		expectedSeverity model.Severity
	}{
		{
			name: "plain password detected",
			cfg: map[string]any{
				"database": map[string]any{
					"password": "super-secret",
				},
			},
			expectedIssues:   1,
			expectedPath:     "database.password",
			expectedSeverity: model.SeverityHigh,
		},
		{
			name: "underscored password key detected",
			cfg: map[string]any{
				"database": map[string]any{
					"db_password": "super-secret",
				},
			},
			expectedIssues:   1,
			expectedPath:     "database.db_password",
			expectedSeverity: model.SeverityHigh,
		},
		{
			name: "numeric password detected",
			cfg: map[string]any{
				"database": map[string]any{
					"password": 123456,
				},
			},
			expectedIssues:   1,
			expectedPath:     "database.password",
			expectedSeverity: model.SeverityHigh,
		},
		{
			name: "environment reference ignored",
			cfg: map[string]any{
				"database": map[string]any{
					"password": "${DB_PASSWORD}",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "vault reference ignored",
			cfg: map[string]any{
				"database": map[string]any{
					"password": "vault://database/password",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "empty password ignored",
			cfg: map[string]any{
				"database": map[string]any{
					"password": "",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "password hash ignored",
			cfg: map[string]any{
				"user": map[string]any{
					"password_hash": "$2a$10$fsdg",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "password policy ignored",
			cfg: map[string]any{
				"security": map[string]any{
					"password_policy": "strict",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "secret reference object ignored",
			cfg: map[string]any{
				"database": map[string]any{
					"password": map[string]any{
						"secretKeyRef": map[string]any{
							"name": "database-secret",
							"key":  "password",
						},
					},
				},
			},
			expectedIssues: 0,
		},
	}

	rule := NewPlaintextPasswordRule()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issues := rule.Check(test.cfg)

			if len(issues) != test.expectedIssues {
				t.Fatalf("expected %d issues, got %d: %#v", test.expectedIssues, len(issues), issues)
			}

			if test.expectedIssues == 0 {
				return
			}

			issue := issues[0]

			if issue.RuleID != rule.ID() {
				t.Errorf("expected rule ID %q, got %q", rule.ID(), issue.RuleID)
			}

			if issue.Severity != test.expectedSeverity {
				t.Errorf("expected severity %q, got %q", test.expectedSeverity, issue.Severity)
			}
		})
	}
}

func TestPlaintextPasswordRule_DoesNotExposeSecret(t *testing.T) {
	const secret = "very-sensitive-password"

	cfg := map[string]any{
		"database": map[string]any{
			"password": secret,
		},
	}

	rule := NewPlaintextPasswordRule()
	issues := rule.Check(cfg)

	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}

	issue := issues[0]

	if strings.Contains(issue.Message, secret) {
		t.Error("issue message exposes the password")
	}

	if strings.Contains(issue.Recommendation, secret) {
		t.Error("issue recommendation exposes the password")
	}
}
