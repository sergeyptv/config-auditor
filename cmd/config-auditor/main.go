package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/parser"
	"io"
	"os"
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
	)

	flags.BoolVar(&silent, "silent", false, "do not return an error code when issues are found")
	flags.BoolVar(&silent, "s", false, "short for --silent")
	flags.BoolVar(&readStdin, "stdin", false, "read configuration from standard input")

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

	reader, format, closeInput, err := openInput(flags.Args(), readStdin, stdin)
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

	analysisService := app.NewAnalysisService()

	issues, err := analysisService.Analyze(reader, format)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	printIssues(stdout, issues)

	if len(issues) > 0 && !silent {
		return exitIssues
	}

	return exitSuccess
}

func openInput(args []string, readStdin bool, stdin io.Reader) (io.Reader, parser.Format, func() error, error) {
	if readStdin {
		if len(args) != 0 {
			return nil, parser.FormatAuto, nil, errors.New("file path must not be provided together with --stdin")
		}

		return stdin, parser.FormatAuto, nil, nil
	}

	if len(args) != 1 {
		return nil, parser.FormatAuto, nil, errors.New("exactly one configuration file path is required")
	}

	path := args[0]

	file, err := os.Open(path)
	if err != nil {
		return nil, parser.FormatAuto, nil, fmt.Errorf("open configuration file %q: %w", path, err)
	}

	return file, parser.FormatFromPath(path), file.Close, nil
}

func printIssues(writer io.Writer, issues []model.Issue) {
	if len(issues) == 0 {
		fmt.Fprintln(writer, "No security issues found")
		return
	}

	for idx, issue := range issues {
		location := issue.Path
		if location == "" {
			location = "configuration"
		}

		fmt.Fprintf(writer, "%s [%s] %s\n", issue.Severity, issue.RuleID, location)
		fmt.Fprintf(writer, "	Problem: %s\n", issue.Message)
		fmt.Fprintf(writer, "	Recommendation: %s\n", issue.Recommendation)

		if idx < len(issues)-1 {
			fmt.Fprintln(writer)
		}
	}
}
