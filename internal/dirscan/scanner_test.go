package dirscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sergeyptv/config-auditor/internal/app"
)

func TestScan(t *testing.T) {
	root := t.TempDir()

	nestedDirectory := filepath.Join(root, "nested")

	if err := os.Mkdir(nestedDirectory, 0o700); err != nil {
		t.Fatalf("create nested directory: %v", err)
	}

	debugPath := filepath.Join(root, "application.yaml")

	if err := os.WriteFile(debugPath, []byte(`
log:
  level: debug
`), 0o600); err != nil {
		t.Fatalf("write YAML configuration: %v", err)
	}

	passwordPath := filepath.Join(nestedDirectory, "database.json")

	if err := os.WriteFile(passwordPath, []byte(
		`{"database":{"password":"secret"}}`,
	), 0o600); err != nil {
		t.Fatalf("write JSON configuration: %v", err)
	}

	ignoredPath := filepath.Join(root, "README.txt")

	if err := os.WriteFile(ignoredPath, []byte("log.level=debug"), 0o600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	report, err := Scan(root, app.NewAnalysisService())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.FilesScanned != 2 {
		t.Fatalf("expected 2 scanned files, got %d", report.FilesScanned)
	}

	if len(report.Errors) != 0 {
		t.Fatalf("expected no file errors, got %#v", report.Errors)
	}

	if len(report.Issues) != 2 {
		t.Fatalf("expected 2 issues, got %d: %#v", len(report.Issues), report.Issues)
	}

	foundRules := map[string]bool{}
	foundSources := map[string]bool{}

	for _, issue := range report.Issues {
		foundRules[issue.RuleID] = true
		foundSources[issue.Source] = true
	}

	if !foundRules["CFG001"] {
		t.Error("expected CFG001 issue")
	}

	if !foundRules["CFG002"] {
		t.Error("expected CFG002 issue")
	}

	if !foundSources[debugPath] {
		t.Errorf("expected source %q", debugPath)
	}

	if !foundSources[passwordPath] {
		t.Errorf("expected source %q", passwordPath)
	}
}

func TestScanContinuesAfterInvalidFile(t *testing.T) {
	root := t.TempDir()

	invalidPath := filepath.Join(root, "invalid.json")

	if err := os.WriteFile(invalidPath, []byte(`{"log":`), 0o600); err != nil {
		t.Fatalf("write invalid configuration: %v", err)
	}

	validPath := filepath.Join(root, "valid.yaml")

	if err := os.WriteFile(validPath, []byte(`
storage:
  digest-algorithm: MD5
`), 0o600); err != nil {
		t.Fatalf("write valid configuration: %v", err)
	}

	report, err := Scan(root, app.NewAnalysisService())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.FilesScanned != 2 {
		t.Fatalf("expected 2 scanned files, got %d", report.FilesScanned)
	}

	if len(report.Errors) != 1 {
		t.Fatalf("expected 1 file error, got %d: %#v", len(report.Errors), report.Errors)
	}

	if !strings.Contains(report.Errors[0].Error(), "invalid.json") {
		t.Fatalf("expected invalid file path, got %q", report.Errors[0].Error())
	}

	if len(report.Issues) != 1 {
		t.Fatalf("expected 1 issue from valid file, got %d", len(report.Issues))
	}

	if report.Issues[0].RuleID != "CFG005" {
		t.Fatalf("expected CFG005, got %q", report.Issues[0].RuleID)
	}
}

func TestScanRejectsFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	if err := os.WriteFile(path, []byte("log:\n  level: info\n"), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	_, err := Scan(path, app.NewAnalysisService())

	if err == nil {
		t.Fatal("expected error for non-directory path")
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	report, err := Scan(t.TempDir(), app.NewAnalysisService())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.FilesScanned != 0 {
		t.Fatalf("expected no scanned files, got %d", report.FilesScanned)
	}
}
