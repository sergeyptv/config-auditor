package rules

import (
	"github.com/sergeyptv/config-auditor/internal/configutil"
	"github.com/sergeyptv/config-auditor/internal/model"
	"strings"
)

const disabledTLSRuleID = "CFG004"

type tlsProblem uint8

const (
	tlsProblemNone = iota
	tlsProblemDisabled
	tlsProblemVerificationDisabled
)

type DisabledTLSRule struct{}

func NewDisabledTLSRule() *DisabledTLSRule {
	return &DisabledTLSRule{}
}

func (r *DisabledTLSRule) ID() string {
	return disabledTLSRuleID
}

func (r *DisabledTLSRule) Check(cfg map[string]any) []model.Issue {
	var issues []model.Issue

	configutil.Walk(cfg, func(entry configutil.Entry) {
		problem := detectTLSProblem(entry)

		switch problem {
		case tlsProblemDisabled:
			issues = append(issues, model.Issue{
				RuleID:         r.ID(),
				Severity:       model.SeverityHigh,
				Path:           entry.Path,
				Message:        "TLS отключен - данные передаются по сети без шифрования",
				Recommendation: "Включите TLS и используйте действующий сертификат",
			})

		case tlsProblemVerificationDisabled:
			issues = append(issues, model.Issue{
				RuleID:         r.ID(),
				Severity:       model.SeverityHigh,
				Path:           entry.Path,
				Message:        "Проверка TLS сертификата отключена",
				Recommendation: "Включите проверку сертификатов",
			})
		}
	})

	return issues
}

func detectTLSProblem(entry configutil.Entry) tlsProblem {
	value, ok := entry.Value.(bool)
	if !ok {
		return tlsProblemNone
	}

	key := normalizeKey(entry.Key)
	parent := parentPathKey(entry.Path)

	if value {
		if isTLSDisableFlag(key, parent) {
			return tlsProblemDisabled
		}

		if isTLSVerificationBypassFlag(key, parent, entry.Path) {
			return tlsProblemVerificationDisabled
		}

		return tlsProblemNone
	}

	if isTLSVerificationFlag(key, parent, entry.Path) {
		return tlsProblemVerificationDisabled
	}

	if isTLSEnabledFlag(key, parent) {
		return tlsProblemDisabled
	}

	return tlsProblemNone
}

func isTLSEnabledFlag(key, parent string) bool {
	switch key {
	case
		"tls",
		"ssl",
		"https",
		"enabletls",
		"tlsenabled",
		"usetls",
		"enablessl",
		"sslenabled",
		"usessl",
		"enablehttps",
		"httpsenabled",
		"requiretls",
		"tlsrequired":
		return true

	case "enabled", "required":
		return isTLSContextPart(parent)

	default:
		return false
	}
}

func isTLSDisableFlag(key, parent string) bool {
	switch key {
	case
		"disabletls",
		"tlsdisabled",
		"disablessl",
		"ssldisabled",
		"disablehttps",
		"httpsdisabled":
		return true

	case "disabled":
		return isTLSContextPart(parent)

	default:
		return false
	}
}

func isTLSVerificationFlag(key, parent, path string) bool {
	switch key {
	case
		"verifytls",
		"tlsverify",
		"verifyssl",
		"sslverify",
		"verifycertificate",
		"verifycertificates",
		"verifyservercertificate",
		"certificateverification":
		return true

	case "verify", "verification":
		return pathHasTLSContext(path)

	case "enabled":
		return isVerificationContext(parent) && pathHasTLSContext(path)

	default:
		return false
	}
}

func isTLSVerificationBypassFlag(key, parent, path string) bool {
	switch key {
	case
		"insecureskipverify",
		"skiptlsverify",
		"skipverifytls",
		"tlsskipverify",
		"disabletlsverification",
		"tlsverificationdisabled",
		"allowinsecuretls",
		"insecuretls":
		return true

	case "insecure", "skipverify", "skipverification":
		return pathHasTLSContext(path)

	case "disabled":
		return isVerificationContext(parent) && pathHasTLSContext(path)

	default:
		return false
	}
}

func parentPathKey(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) < 2 {
		return ""
	}

	return normalizeKey(parts[len(parts)-2])
}

func pathHasTLSContext(path string) bool {
	for _, part := range strings.Split(path, ".") {
		if isTLSContextPart(normalizeKey(part)) {
			return true
		}
	}

	return false
}

func isTLSContextPart(value string) bool {
	return value == "tls" ||
		value == "ssl" ||
		value == "https" ||
		strings.HasPrefix(value, "tls") ||
		strings.HasSuffix(value, "tls") ||
		strings.HasPrefix(value, "ssl") ||
		strings.HasSuffix(value, "ssl")
}

func isVerificationContext(value string) bool {
	switch value {
	case
		"verify",
		"verification",
		"certverification",
		"certificateverification":
		return true

	default:
		return false
	}
}
