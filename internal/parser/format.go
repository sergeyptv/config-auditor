package parser

import (
	"path/filepath"
	"strings"
)

type Format uint8

const (
	FormatAuto = iota
	FormatJSON
	FormatYAML
)

func FormatFromPath(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return FormatJSON
	case ".yaml", ".yml":
		return FormatYAML
	default:
		return FormatAuto
	}
}
