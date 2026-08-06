package rules

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"strings"
	"testing"
)

func TestDisabledTLSRule_Check(t *testing.T) {
	tests := []struct {
		name             string
		cfg              map[string]any
		expectedIssues   int
		expectedPath     string
		expectedSeverity model.Severity
		expectedMessage  string
	}{
		{
			name: "top level TLS disabled",
			cfg: map[string]any{
				"tls": false,
			},
			expectedIssues:   1,
			expectedPath:     "tls",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "TLS отключен",
		},
		{
			name: "nested TLS enabled flag is false",
			cfg: map[string]any{
				"server": map[string]any{
					"tls": map[string]any{
						"enabled": false,
					},
				},
			},
			expectedIssues:   1,
			expectedPath:     "server.tls.enabled",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "TLS отключен",
		},
		{
			name: "SSL disabled",
			cfg: map[string]any{
				"server": map[string]any{
					"ssl": false,
				},
			},
			expectedIssues:   1,
			expectedPath:     "server.ssl",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "TLS отключен",
		},
		{
			name: "disable TLS flag enabled",
			cfg: map[string]any{
				"server": map[string]any{
					"disable_tls": true,
				},
			},
			expectedIssues:   1,
			expectedPath:     "server.disable_tls",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "TLS отключен",
		},
		{
			name: "insecure skip verify enabled",
			cfg: map[string]any{
				"client": map[string]any{
					"insecure_skip_verify": true,
				},
			},
			expectedIssues:   1,
			expectedPath:     "client.insecure_skip_verify",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "Проверка TLS сертификата отключена",
		},
		{
			name: "TLS verify disabled",
			cfg: map[string]any{
				"client": map[string]any{
					"tls": map[string]any{
						"verify": false,
					},
				},
			},
			expectedIssues:   1,
			expectedPath:     "client.tls.verify",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "Проверка TLS сертификата отключена",
		},
		{
			name: "TLS verification enabled flag is false",
			cfg: map[string]any{
				"client": map[string]any{
					"tls": map[string]any{
						"verification": map[string]any{
							"enabled": false,
						},
					},
				},
			},
			expectedIssues:   1,
			expectedPath:     "client.tls.verification.enabled",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "Проверка TLS сертификата отключена",
		},
		{
			name: "TLS enabled is safe",
			cfg: map[string]any{
				"server": map[string]any{
					"tls": map[string]any{
						"enabled": true,
					},
				},
			},
			expectedIssues: 0,
		},
		{
			name: "TLS verification enabled is safe",
			cfg: map[string]any{
				"client": map[string]any{
					"tls": map[string]any{
						"verify": true,
					},
				},
			},
			expectedIssues: 0,
		},
		{
			name: "unrelated verify flag ignored",
			cfg: map[string]any{
				"application": map[string]any{
					"verify": false,
				},
			},
			expectedIssues: 0,
		},
		{
			name: "unrelated insecure flag ignored",
			cfg: map[string]any{
				"development": map[string]any{
					"insecure": true,
				},
			},
			expectedIssues: 0,
		},
		{
			name: "string false ignored",
			cfg: map[string]any{
				"tls": "false",
			},
			expectedIssues: 0,
		},
	}

	rule := NewDisabledTLSRule()

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

			if issue.Path != test.expectedPath {
				t.Errorf("expected path %q, got %q", test.expectedPath, issue.Path)
			}

			if issue.Severity != test.expectedSeverity {
				t.Errorf("expected severity %q, got %q", test.expectedSeverity, issue.Severity)
			}

			if !strings.Contains(issue.Message, test.expectedMessage) {
				t.Errorf("expected message to contain %q, got %q", test.expectedMessage, issue.Message)
			}
		})
	}
}

func TestDisabledTLSRule_ReturnsAllIssues(t *testing.T) {
	cfg := map[string]any{
		"server": map[string]any{
			"tls": false,
		},
		"client": map[string]any{
			"insecure_skip_verify": true,
		},
	}

	rule := NewDisabledTLSRule()
	issues := rule.Check(cfg)

	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d: %#v", len(issues), issues)
	}
}
