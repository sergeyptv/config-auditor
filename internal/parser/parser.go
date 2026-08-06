package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go.yaml.in/yaml/v4"
	"io"
)

var ErrEmptyConfig = errors.New("configuration is empty")

func Parse(data []byte, format Format) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrEmptyConfig
	}

	switch format {
	case FormatJSON:
		return parseJSON(data)

	case FormatYAML:
		return parseYAML(data)

	case FormatAuto:
		return parseAuto(data)

	default:
		return nil, fmt.Errorf("unsupported configuration format: %d", format)
	}
}

func parseAuto(data []byte) (map[string]any, error) {
	cfg, jsonErr := parseJSON(data)
	if jsonErr == nil {
		return cfg, nil
	}

	cfg, yamlErr := parseYAML(data)
	if yamlErr == nil {
		return cfg, nil
	}

	return nil, fmt.Errorf(
		"failed to parse configuration as JSON or YAML: JSON error: %v; YAML error: %v",
		jsonErr,
		yamlErr,
	)
}

func parseJSON(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var cfg map[string]any

	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}

	if cfg == nil {
		return nil, errors.New("JSON configuration must contain an object")
	}

	if err := ensureJSONDocumentEnded(decoder); err != nil {
		return nil, err
	}

	return cfg, nil
}

func ensureJSONDocumentEnded(decoder *json.Decoder) error {
	var extra any

	err := decoder.Decode(&extra)

	switch {
	case errors.Is(err, io.EOF):
		return nil

	case err == nil:
		return errors.New("JSON configuration contains multiple values")

	default:
		return fmt.Errorf("invalid data after JSON document: %w", err)
	}
}

func parseYAML(data []byte) (map[string]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var cfg map[string]any

	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode YAML: %w", err)
	}

	if cfg == nil {
		return nil, errors.New("YAML configuration must contain an object")
	}

	if err := ensureYAMLDocumentEnded(decoder); err != nil {
		return nil, err
	}

	return cfg, nil
}

func ensureYAMLDocumentEnded(decoder *yaml.Decoder) error {
	var extra any

	err := decoder.Decode(&extra)

	switch {
	case errors.Is(err, io.EOF):
		return nil

	case err == nil:
		return errors.New("multiple YAML documents are not supported")

	default:
		return fmt.Errorf("invalid data after YAML document: %w", err)
	}
}
