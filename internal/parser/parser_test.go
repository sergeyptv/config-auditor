package parser

import (
	"errors"
	"testing"
)

func TestParseJSON(t *testing.T) {
	data := []byte(`{
		"log": {
			"level": "debug"
		}
	}`)

	cfg, err := Parse(data, FormatJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logCfg, ok := cfg["log"].(map[string]any)
	if !ok {
		t.Fatalf("expected a log map object, got %T", cfg["log"])
	}

	if logCfg["level"] != "debug" {
		t.Fatalf("expected log level %q, got %#v", "debug", logCfg["level"])
	}
}

func TestParseYAML(t *testing.T) {
	data := []byte(`
application:
  logging:
    level: debug
`)

	cfg, err := Parse(data, FormatYAML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	application, ok := cfg["application"].(map[string]any)
	if !ok {
		t.Fatalf("expected an application object, got %T", cfg["application"])
	}

	logging, ok := application["logging"].(map[string]any)
	if !ok {
		t.Fatalf("expected a logging map object, got %T", cfg["logging"])
	}

	if logging["level"] != "debug" {
		t.Fatalf("expected log level %q, got %#v", "debug", logging["level"])
	}
}

func TestParseAuto(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "JSON",
			data: `{"log":{"level":"debug"}}`,
		},
		{
			name: "YAML",
			data: `
log:
  level: debug
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := Parse([]byte(test.data), FormatAuto)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("unexpected nil configuration")
			}
		})
	}
}

func TestParseEmptyConfig(t *testing.T) {
	_, err := Parse([]byte(" \n\t"), FormatAuto)

	if !errors.Is(err, ErrEmptyConfig) {
		t.Fatalf("expected ErrEmptyConfig, got %v", err)
	}
}

func TestParseInvalidConfig(t *testing.T) {
	_, err := Parse([]byte("{invalid"), FormatJSON)

	if err == nil {
		t.Fatal("unexpected nil error")
	}
}

func TestParseJSONArray(t *testing.T) {
	_, err := Parse([]byte(`[{"log":{"level":"debug"}}]`), FormatJSON)

	if err == nil {
		t.Fatal("expected error for JSON array")
	}
}

func TestParseMultipleYAMLDocuments(t *testing.T) {
	data := []byte(`
log:
  level: debug
---
tls:
  enabled: false
`)

	_, err := Parse(data, FormatYAML)

	if err == nil {
		t.Fatal("expected error for multiple YAML documents")
	}
}

func TestFormatFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected Format
	}{
		{
			path:     "config.json",
			expected: FormatJSON,
		},
		{
			path:     "config.yaml",
			expected: FormatYAML,
		},
		{
			path:     "config.yml",
			expected: FormatYAML,
		},
		{
			path:     "CONFIG.JSON",
			expected: FormatJSON,
		},
		{
			path:     "config.conf",
			expected: FormatAuto,
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			actual := FormatFromPath(test.path)

			if actual != test.expected {
				t.Fatalf("expected format %d, got %d", test.expected, actual)
			}
		})
	}
}
