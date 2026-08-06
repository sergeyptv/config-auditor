package rules

import "strings"

func normalizeKey(key string) string {
	replacer := strings.NewReplacer(
		"-", "",
		"_", "",
		".", "",
		" ", "",
	)

	return strings.ToLower(replacer.Replace(strings.TrimSpace(key)))
}
