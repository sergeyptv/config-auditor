package rules

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"testing"
)

func TestOpenBindAddressRule_Check(t *testing.T) {
	tests := []struct {
		name             string
		cfg              map[string]any
		expectedIssues   int
		expectedPath     string
		expectedSeverity model.Severity
	}{
		{
			name: "all interfaces host detected",
			cfg: map[string]any{
				"server": map[string]any{
					"host": "0.0.0.0",
				},
			},
			expectedIssues:   1,
			expectedPath:     "server.host",
			expectedSeverity: model.SeverityMedium,
		},
		{
			name: "all interfaces address with port detected",
			cfg: map[string]any{
				"server": map[string]any{
					"address": "0.0.0.0:8080",
				},
			},
			expectedIssues:   1,
			expectedPath:     "server.address",
			expectedSeverity: model.SeverityMedium,
		},
		{
			name: "URL with all interfaces detected",
			cfg: map[string]any{
				"http": map[string]any{
					"listen": "http://0.0.0.0:8080",
				},
			},
			expectedIssues:   1,
			expectedPath:     "http.listen",
			expectedSeverity: model.SeverityMedium,
		},
		{
			name: "underscored bind address detected",
			cfg: map[string]any{
				"server": map[string]any{
					"bind_address": "0.0.0.0",
				},
			},
			expectedIssues:   1,
			expectedPath:     "server.bind_address",
			expectedSeverity: model.SeverityMedium,
		},
		{
			name: "localhost is safe",
			cfg: map[string]any{
				"server": map[string]any{
					"host": "127.0.0.1",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "specific network address is safe",
			cfg: map[string]any{
				"server": map[string]any{
					"host": "192.168.1.10",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "unrelated zero address ignored",
			cfg: map[string]any{
				"documentation": map[string]any{
					"example": "0.0.0.0",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "non-string host ignored",
			cfg: map[string]any{
				"server": map[string]any{
					"host": 123,
				},
			},
			expectedIssues: 0,
		},
	}

	rule := NewOpenBindAddressRule()

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
		})
	}
}

func TestOpenBindAddressRule_ReturnsAllIssues(t *testing.T) {
	cfg := map[string]any{
		"http": map[string]any{
			"host": "0.0.0.0",
		},
		"grpc": map[string]any{
			"address": "0.0.0.0:9090",
		},
	}

	rule := NewOpenBindAddressRule()
	issues := rule.Check(cfg)

	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d: %#v", len(issues), issues)
	}
}
