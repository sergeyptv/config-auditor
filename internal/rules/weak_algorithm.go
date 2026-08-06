package rules

import (
	"fmt"
	"github.com/sergeyptv/config-auditor/internal/configutil"
	"github.com/sergeyptv/config-auditor/internal/model"
	"regexp"
	"strings"
)

const weakAlgorithmRuleID = "CFG005"

var (
	nonAlphanumericPattern = regexp.MustCompile(`[^A-Z0-9]+`)

	desTokenPattern = regexp.MustCompile(`(^|[^A-Z0-9])DES([^A-Z0-9]|$)`)
)

type weakAlgorithmFinding struct {
	Name           string
	Recommendation string
}

type WeakAlgorithmRule struct{}

func NewWeakAlgorithmRule() *WeakAlgorithmRule {
	return &WeakAlgorithmRule{}
}

func (r *WeakAlgorithmRule) ID() string {
	return weakAlgorithmRuleID
}

func (r *WeakAlgorithmRule) Check(cfg map[string]any) []model.Issue {
	var issues []model.Issue

	configutil.Walk(cfg, func(entry configutil.Entry) {
		if !isAlgorithmEntry(entry) {
			return
		}

		value, ok := entry.Value.(string)
		if !ok {
			return
		}

		finding, found := findWeakAlgorithm(value)
		if !found {
			return
		}

		issues = append(issues, model.Issue{
			RuleID:         r.ID(),
			Severity:       model.SeverityHigh,
			Path:           entry.Path,
			Message:        fmt.Sprintf("Используется устаревший или небезопасный алгоритм %s", finding.Name),
			Recommendation: finding.Recommendation,
		})
	})

	return issues
}

func isAlgorithmEntry(entry configutil.Entry) bool {
	if isAlgorithmKey(entry.Key) {
		return true
	}

	normalizedKey := normalizeKey(entry.Key)

	switch normalizedKey {
	case "", "name", "value":
		return pathHasAlgorithmContext(entry.Path)

	default:
		return false
	}
}

func isAlgorithmKey(key string) bool {
	normalized := normalizeKey(key)

	switch normalized {
	case
		"algorithm",
		"algorithms",
		"algo",
		"algos",
		"hash",
		"hashing",
		"digest",
		"cipher",
		"ciphers",
		"ciphersuite",
		"ciphersuites",
		"encryption",
		"signature",
		"checksum":
		return true
	}

	return strings.HasSuffix(normalized, "algorithm") ||
		strings.HasSuffix(normalized, "algorithms") ||
		strings.HasSuffix(normalized, "hash") ||
		strings.HasSuffix(normalized, "digest") ||
		strings.HasSuffix(normalized, "cipher") ||
		strings.HasSuffix(normalized, "ciphersuite")
}

func pathHasAlgorithmContext(path string) bool {
	for _, pathPart := range strings.Split(path, ".") {
		if bracketIndex := strings.IndexByte(pathPart, '['); bracketIndex >= 0 {
			pathPart = pathPart[:bracketIndex]
		}

		if isAlgorithmKey(pathPart) {
			return true
		}
	}

	return false
}

func findWeakAlgorithm(value string) (weakAlgorithmFinding, bool) {
	upperValue := strings.ToUpper(strings.TrimSpace(value))
	if upperValue == "" {
		return weakAlgorithmFinding{}, false
	}

	compactValue := nonAlphanumericPattern.ReplaceAllString(upperValue, "")

	switch {
	case strings.Contains(compactValue, "MD5"):
		return weakAlgorithmFinding{
			Name:           "MD5",
			Recommendation: "Для проверки целостности используйте SHA-256 или SHA-3; для хранения паролей - Argon2id, bcrypt или scrypt",
		}, true

	case strings.Contains(compactValue, "SHA1"):
		return weakAlgorithmFinding{
			Name:           "SHA-1",
			Recommendation: "Замените SHA-1 на SHA-256, SHA-3 или другой современный алгоритм",
		}, true

	case strings.Contains(compactValue, "3DES"),
		strings.Contains(compactValue, "TRIPLEDES"),
		strings.Contains(compactValue, "DESEDE"):
		return weakAlgorithmFinding{
			Name:           "3DES",
			Recommendation: "Используйте современное аутентифицированное шифрование, например AES-GCM или ChaCha20-Poly1305",
		}, true

	case strings.Contains(compactValue, "RC4"),
		strings.Contains(compactValue, "ARC4"):
		return weakAlgorithmFinding{
			Name:           "RC4",
			Recommendation: "Используйте современное аутентифицированное шифрование, например AES-GCM или ChaCha20-Poly1305",
		}, true

	case desTokenPattern.MatchString(upperValue):
		return weakAlgorithmFinding{
			Name:           "DES",
			Recommendation: "Замените DES на AES-GCM или ChaCha20-Poly1305",
		}, true

	default:
		return weakAlgorithmFinding{}, false
	}
}
