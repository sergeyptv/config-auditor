package rules

import (
	"github.com/sergeyptv/config-auditor/internal/model"
	"strings"
	"testing"
)

func TestWeakAlgorithmRule_Check(t *testing.T) {
	tests := []struct {
		name             string
		cfg              map[string]any
		expectedIssues   int
		expectedPath     string
		expectedSeverity model.Severity
		expectedMessage  string
	}{
		{
			name: "MD5 digest detected",
			cfg: map[string]any{
				"storage": map[string]any{
					"digest-algorithm": "MD5",
				},
			},
			expectedIssues:   1,
			expectedPath:     "storage.digest-algorithm",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "MD5",
		},
		{
			name: "SHA-1 hash detected",
			cfg: map[string]any{
				"security": map[string]any{
					"hash_algorithm": "SHA-1",
				},
			},
			expectedIssues:   1,
			expectedPath:     "security.hash_algorithm",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "SHA-1",
		},
		{
			name: "SHA-1 signature detected",
			cfg: map[string]any{
				"security": map[string]any{
					"signature_algorithm": "RSA-SHA1",
				},
			},
			expectedIssues:   1,
			expectedPath:     "security.signature_algorithm",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "SHA-1",
		},
		{
			name: "DES cipher detected",
			cfg: map[string]any{
				"encryption": map[string]any{
					"cipher": "DES-CBC",
				},
			},
			expectedIssues:   1,
			expectedPath:     "encryption.cipher",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "DES",
		},
		{
			name: "3DES cipher detected",
			cfg: map[string]any{
				"encryption": map[string]any{
					"cipher": "3DES-EDE-CBC",
				},
			},
			expectedIssues:   1,
			expectedPath:     "encryption.cipher",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "3DES",
		},
		{
			name: "RC4 cipher detected",
			cfg: map[string]any{
				"encryption": map[string]any{
					"cipher": "RC4",
				},
			},
			expectedIssues:   1,
			expectedPath:     "encryption.cipher",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "RC4",
		},
		{
			name: "weak algorithm in array detected",
			cfg: map[string]any{
				"security": map[string]any{
					"allowed_algorithms": []any{
						"SHA-256",
						"MD5",
					},
				},
			},
			expectedIssues:   1,
			expectedPath:     "security.allowed_algorithms[1]",
			expectedSeverity: model.SeverityHigh,
			expectedMessage:  "MD5",
		},
		{
			name: "SHA-256 is safe",
			cfg: map[string]any{
				"security": map[string]any{
					"hash_algorithm": "SHA-256",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "AES-GCM is safe",
			cfg: map[string]any{
				"encryption": map[string]any{
					"cipher": "AES-256-GCM",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "unrelated MD5 text ignored",
			cfg: map[string]any{
				"documentation": map[string]any{
					"note": "MD5 is unsupported",
				},
			},
			expectedIssues: 0,
		},
		{
			name: "non-string algorithm ignored",
			cfg: map[string]any{
				"security": map[string]any{
					"algorithm": 123,
				},
			},
			expectedIssues: 0,
		},
	}

	rule := NewWeakAlgorithmRule()

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
