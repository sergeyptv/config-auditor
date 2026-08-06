package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunFromStdin(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		input          string
		expectedCode   int
		stdoutContains string
		stderrContains string
	}{
		{
			name: "debug issue produces issue exit code",
			args: []string{
				"--stdin",
			},
			input: `
log:
  level: debug
`,
			expectedCode:   exitIssues,
			stdoutContains: "CFG001",
		},
		{
			name: "plaintext password produces issue exit code",
			args: []string{
				"--stdin",
			},
			input: `
database:
  password: super-secret
`,
			expectedCode:   exitIssues,
			stdoutContains: "CFG002",
		},
		{
			name: "silent mode produces success code",
			args: []string{
				"--stdin",
				"--silent",
			},
			input: `
log:
  level: debug
`,
			expectedCode:   exitSuccess,
			stdoutContains: "CFG001",
		},
		{
			name: "short silent flag produces success code",
			args: []string{
				"--stdin",
				"-s",
			},
			input: `
log:
  level: debug
`,
			expectedCode:   exitSuccess,
			stdoutContains: "CFG001",
		},
		{
			name: "safe configuration produces success code",
			args: []string{
				"--stdin",
			},
			input: `
log:
  level: info
database:
  password: ${DB_PASSWORD}
`,
			expectedCode:   exitSuccess,
			stdoutContains: "No security issues found",
		},
		{
			name: "invalid configuration produces error code",
			args: []string{
				"--stdin",
			},
			input:          `{"log":`,
			expectedCode:   exitError,
			stderrContains: "error:",
		},
		{
			name: "open bind address produces issue exit code",
			args: []string{
				"--stdin",
			},
			input: `
server:
  host: 0.0.0.0
`,
			expectedCode:   exitIssues,
			stdoutContains: "CFG003",
		},
		{
			name: "disabled TLS produces issue exit code",
			args: []string{
				"--stdin",
			},
			input: `
server:
  tls:
    enabled: false
`,
			expectedCode:   exitIssues,
			stdoutContains: "CFG004",
		},
		{
			name: "disabled certificate verification produces issue",
			args: []string{
				"--stdin",
			},
			input: `
client:
  insecure_skip_verify: true
`,
			expectedCode:   exitIssues,
			stdoutContains: "CFG004",
		},
		{
			name: "weak algorithm produces issue exit code",
			args: []string{
				"--stdin",
			},
			input: `
storage:
  digest-algorithm: MD5
`,
			expectedCode:   exitIssues,
			stdoutContains: "CFG005",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			exitCode := run(test.args, strings.NewReader(test.input), &stdout, &stderr)

			if exitCode != test.expectedCode {
				t.Fatalf("expected exit code %d, got %d\nstdout:\n%s\nstderr:\n%s",
					test.expectedCode, exitCode, stdout.String(), stderr.String())
			}

			if test.stdoutContains != "" && !strings.Contains(stdout.String(), test.stderrContains) {
				t.Errorf("expected stdout to contain %q, got:\n%s", test.stdoutContains, stdout.String())
			}

			if test.stderrContains != "" && !strings.Contains(stderr.String(), test.stderrContains) {
				t.Errorf("expected stderr to contain %q, got:\n%s", test.stderrContains, stderr.String())
			}
		})
	}
}

func TestRunFromFile(t *testing.T) {
	tempDirectory := t.TempDir()
	cfgPath := filepath.Join(tempDirectory, "config.yaml")

	cfg := []byte(`
log:
  level: debug
`)

	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatalf("write test configuration: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{cfgPath}, strings.NewReader(""), &stdout, &stderr)

	if exitCode != exitIssues {
		t.Fatalf("expected exit code %d, got %d\nstderr:\n%s", exitIssues, exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "CFG001") {
		t.Fatalf("expected debug issue in stdout, got:\n%s", stdout.String())
	}
}

func TestRunRejectsMissingPath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(nil, strings.NewReader(""), &stdout, &stderr)

	if exitCode != exitError {
		t.Fatalf("expected exit code %d, got %d", exitError, exitCode)
	}

	if !strings.Contains(stderr.String(), "exactly one configuration file path is required") {
		t.Fatalf("unexpected stderr:\n%s", stderr.String())
	}
}

func TestRunRejectsFileWithStdinFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"--stdin", "config.yaml"}, strings.NewReader(""), &stdout, &stderr)

	if exitCode != exitError {
		t.Fatalf("expected exit code %d, got %d", exitError, exitCode)
	}

	if !strings.Contains(stderr.String(), "file path must not be provided together with --stdin") {
		t.Fatalf("unexpected stderr:\n%s", stderr.String())
	}
}

func TestRunReturnsAllDetectedIssues(t *testing.T) {
	input := `
log:
  level: debug

database:
  password: super-secret

server:
  host: 0.0.0.0

client:
  insecure_skip_verify: true

storage:
  digest-algorithm: MD5
`

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"--stdin"}, strings.NewReader(input), &stdout, &stderr)

	if exitCode != exitIssues {
		t.Fatalf("expected exit code %d, got %d\nstderr:\n%s", exitIssues, exitCode, stderr.String())
	}

	expectedRuleIDs := []string{
		"CFG001",
		"CFG002",
		"CFG003",
		"CFG004",
		"CFG005",
	}

	for _, ruleID := range expectedRuleIDs {
		if !strings.Contains(stdout.String(), ruleID) {
			t.Errorf("expected stdout to contain %q, got:\n%s", ruleID, stdout.String())
		}
	}
}

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"--help"}, strings.NewReader(""), &stdout, &stderr)

	if exitCode != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, exitCode)
	}

	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage information, got:\n%s", stderr.String())
	}
}
