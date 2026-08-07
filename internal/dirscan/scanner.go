package dirscan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/filecheck"
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/parser"
)

type FileError struct {
	Path string
	Err  error
}

func (e FileError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

type Report struct {
	Issues       []model.Issue
	Errors       []FileError
	FilesScanned int
}

func Scan(root string, service *app.AnalysisService) (Report, error) {
	if service == nil {
		return Report{}, fmt.Errorf("analysis service must not be nil")
	}

	rootInfo, err := os.Stat(root)
	if err != nil {
		return Report{}, fmt.Errorf("inspect directory %q: %w", root, err)
	}

	if !rootInfo.IsDir() {
		return Report{}, fmt.Errorf("path %q is not a directory", root)
	}

	var report Report

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			report.Errors = append(report.Errors, FileError{
				Path: path,
				Err:  walkErr,
			},
			)

			return nil
		}

		if entry.IsDir() {
			return nil
		}

		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			report.Errors = append(report.Errors, FileError{
				Path: path,
				Err:  fmt.Errorf("inspect file: %w", err),
			},
			)

			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		format, supported := formatFromPath(path)
		if !supported {
			return nil
		}

		report.FilesScanned++

		permissionIssues, err := filecheck.CheckPermissions(path)
		if err != nil {
			report.Errors = append(report.Errors, FileError{
				Path: path,
				Err:  fmt.Errorf("check permissions: %w", err),
			},
			)
		} else {
			report.Issues = append(report.Issues, permissionIssues...)
		}

		configIssues, err := analyzeFile(path, format, service)
		if err != nil {
			report.Errors = append(report.Errors, FileError{
				Path: path,
				Err:  err,
			},
			)

			return nil
		}

		report.Issues = append(report.Issues, configIssues...)

		return nil
	},
	)
	if err != nil {
		return report, fmt.Errorf("walk directory %q: %w", root, err)
	}

	model.SortIssues(report.Issues)

	return report, nil
}

func analyzeFile(path string, format parser.Format, service *app.AnalysisService) ([]model.Issue, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	issues, analyzeErr := service.Analyze(file, format)

	closeErr := file.Close()

	if analyzeErr != nil {
		return nil, fmt.Errorf("analyze configuration: %w", analyzeErr)
	}

	if closeErr != nil {
		return nil, fmt.Errorf("close file: %w", closeErr)
	}

	for idx := range issues {
		issues[idx].Source = filepath.Clean(path)
	}

	return issues, nil
}

func formatFromPath(path string) (parser.Format, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return parser.FormatJSON, true

	case ".yaml", ".yml":
		return parser.FormatYAML, true

	default:
		return parser.FormatAuto, false
	}
}
