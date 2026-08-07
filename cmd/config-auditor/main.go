package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/dirscan"
	"github.com/sergeyptv/config-auditor/internal/filecheck"
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/parser"
)

const (
	exitSuccess = 0
	exitIssues  = 1
	exitError   = 2
)

func main() {
	exitCode := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)

	os.Exit(exitCode)
}

func run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("config-auditor", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		silent    bool
		readStdin bool
		recursive bool
	)

	flags.BoolVar(&silent, "silent", false, "do not return an error code when issues are found")
	flags.BoolVar(&silent, "s", false, "short for --silent")
	flags.BoolVar(&readStdin, "stdin", false, "read configuration from standard input")
	flags.BoolVar(&recursive, "recursive", false, "recursively analyze configuration files in a directory")
	flags.BoolVar(&recursive, "r", false, "shorthand for --recursive")

	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s [options] <config-file>\n", flags.Name())
		fmt.Fprintln(flags.Output())
		fmt.Fprintln(flags.Output(), "Options:")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSuccess
		}

		return exitError
	}

	analysisService := app.NewAnalysisService()

	if recursive {
		return runDirectory(flags.Args(), readStdin, silent, analysisService, stdout, stderr)
	}

	reader, format, sourcePath, closeInput, err := openInput(flags.Args(), readStdin, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		flags.Usage()
		return exitError
	}

	if closeInput != nil {
		defer func() {
			_ = closeInput()
		}()
	}

	issues, err := analysisService.Analyze(reader, format)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	if sourcePath != "" {
		fileIssues, err := filecheck.CheckPermissions(sourcePath)
		if err != nil {
			fmt.Fprintf(stderr, "error: check file permissions: %v\n", err)

			return exitError
		}

		issues = append(issues, fileIssues...)
		model.SortIssues(issues)
	}

	printIssues(stdout, issues)

	if len(issues) > 0 && !silent {
		return exitIssues
	}

	return exitSuccess
}

func runDirectory(args []string, readStdin bool, silent bool, analysisService *app.AnalysisService, stdout io.Writer, stderr io.Writer) int {
	if readStdin {
		fmt.Fprintln(stderr, "error: --recursive cannot be used together with --stdin")

		return exitError
	}

	if len(args) != 1 {
		fmt.Fprintln(stderr, "error: exactly one directory path is required with --recursive")

		return exitError
	}

	report, err := dirscan.Scan(args[0], analysisService)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)

		return exitError
	}

	if report.FilesScanned == 0 {
		fmt.Fprintf(stderr, "error: no supported configuration files found in %q\n", args[0])

		return exitError
	}

	if len(report.Issues) > 0 {
		printIssues(stdout, report.Issues)
	} else {
		fmt.Fprintln(stdout, "No security issues found.")
	}

	for _, fileError := range report.Errors {
		fmt.Fprintf(stderr, "error: %s\n", fileError.Error())
	}

	if len(report.Errors) > 0 {
		return exitError
	}

	if len(report.Issues) > 0 && !silent {
		return exitIssues
	}

	return exitSuccess
}

func openInput(args []string, readStdin bool, stdin io.Reader) (io.Reader, parser.Format, string, func() error, error) {
	if readStdin {
		if len(args) != 0 {
			return nil, parser.FormatAuto, "", nil, errors.New("file path must not be provided together with --stdin")
		}

		return stdin, parser.FormatAuto, "", nil, nil
	}

	if len(args) != 1 {
		return nil, parser.FormatAuto, "", nil, errors.New("exactly one configuration file path is required")
	}

	path := args[0]

	file, err := os.Open(path)
	if err != nil {
		return nil, parser.FormatAuto, "", nil, fmt.Errorf("open configuration file %q: %w", path, err)
	}

	return file, parser.FormatFromPath(path), path, file.Close, nil
}

func printIssues(w io.Writer, issues []model.Issue) {
	if len(issues) == 0 {
		fmt.Fprintln(w, "No security issues found.")

		return
	}

	for idx, issue := range issues {
		location := issueLocation(issue)

		fmt.Fprintf(w, "%s [%s] %s\n", issue.Severity, issue.RuleID, location)

		fmt.Fprintf(w, "  Problem: %s\n", issue.Message)

		fmt.Fprintf(w, "  Recommendation: %s\n", issue.Recommendation)

		if idx < len(issues)-1 {
			fmt.Fprintln(w)
		}
	}
}

func issueLocation(issue model.Issue) string {
	switch {
	case issue.Source != "" && issue.Path != "":
		return issue.Source + ":" + issue.Path

	case issue.Source != "":
		return issue.Source

	case issue.Path != "":
		return issue.Path

	default:
		return "configuration"
	}
}
