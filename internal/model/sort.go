package model

import "sort"

func SortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		left := issues[i]
		right := issues[j]

		leftSeverity := severityRank(left.Severity)
		rightSeverity := severityRank(right.Severity)

		if leftSeverity != rightSeverity {
			return leftSeverity > rightSeverity
		}

		if left.Source != right.Source {
			return left.Source < right.Source
		}

		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}

		return left.Path < right.Path
	})
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return 3

	case SeverityMedium:
		return 2

	case SeverityLow:
		return 1

	default:
		return 0
	}
}
