package filecheck

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sergeyptv/config-auditor/internal/model"
)

func TestCheckPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions are not supported on Windows")
	}

	tests := []struct {
		name             string
		permissions      os.FileMode
		expectedIssues   int
		expectedRuleIDs  []string
		expectedSeverity []model.Severity
	}{
		{
			name:           "private file",
			permissions:    0o600,
			expectedIssues: 0,
		},
		{
			name:             "group-readable file",
			permissions:      0o640,
			expectedIssues:   1,
			expectedRuleIDs:  []string{groupReadableRuleID},
			expectedSeverity: []model.Severity{model.SeverityLow},
		},
		{
			name:             "world-readable file",
			permissions:      0o644,
			expectedIssues:   1,
			expectedRuleIDs:  []string{worldReadableRuleID},
			expectedSeverity: []model.Severity{model.SeverityMedium},
		},
		{
			name:             "group-writable file",
			permissions:      0o660,
			expectedIssues:   2,
			expectedRuleIDs:  []string{groupWritableRuleID, groupReadableRuleID},
			expectedSeverity: []model.Severity{model.SeverityMedium, model.SeverityLow},
		},
		{
			name:             "world-writable file",
			permissions:      0o666,
			expectedIssues:   2,
			expectedRuleIDs:  []string{worldWritableRuleID, worldReadableRuleID},
			expectedSeverity: []model.Severity{model.SeverityHigh, model.SeverityMedium},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")

			if err := os.WriteFile(path, []byte("log:\n  level: info\n"), 0o600); err != nil {
				t.Fatalf("write test file: %v", err)
			}

			if err := os.Chmod(path, test.permissions); err != nil {
				t.Fatalf("change file permissions: %v", err)
			}

			issues, err := CheckPermissions(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(issues) != test.expectedIssues {
				t.Fatalf("expected %d issues, got %d: %#v", test.expectedIssues, len(issues), issues)
			}

			for idx := range test.expectedRuleIDs {
				if issues[idx].RuleID != test.expectedRuleIDs[idx] {
					t.Errorf("issue %d: expected rule ID %q, got %q", idx, test.expectedRuleIDs[idx], issues[idx].RuleID)
				}

				if issues[idx].Severity != test.expectedSeverity[idx] {
					t.Errorf("issue %d: expected severity %q, got %q", idx, test.expectedSeverity[idx], issues[idx].Severity)
				}
			}
		})
	}
}

func TestCheckPermissionsRejectsDirectory(t *testing.T) {
	path := t.TempDir()

	_, err := CheckPermissions(path)

	if err == nil {
		t.Fatal("expected error for directory")
	}
}

func TestCheckPermissionsReturnsStatError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	_, err := CheckPermissions(path)

	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
