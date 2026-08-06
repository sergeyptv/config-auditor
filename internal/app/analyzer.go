package app

import (
	"github.com/sergeyptv/config-auditor/internal/analyzer"
	"github.com/sergeyptv/config-auditor/internal/rules"
)

func NewSecurityAnalyzer() *analyzer.Analyzer {
	return analyzer.New(
		rules.NewDebugLoggingRule(),
		rules.NewPlaintextPasswordRule(),
		rules.NewOpenBindAddressRule(),
		rules.NewDisabledTLSRule(),
		rules.NewWeakAlgorithmRule(),
	)
}
