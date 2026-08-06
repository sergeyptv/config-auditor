package rules

import (
	"github.com/sergeyptv/config-auditor/internal/configutil"
	"github.com/sergeyptv/config-auditor/internal/model"
	"net"
	"net/url"
	"strings"
)

const openBindAddressRuleID = "CFG003"

type OpenBindAddressRule struct{}

func NewOpenBindAddressRule() *OpenBindAddressRule {
	return &OpenBindAddressRule{}
}

func (r *OpenBindAddressRule) ID() string {
	return openBindAddressRuleID
}

func (r *OpenBindAddressRule) Check(cfg map[string]any) []model.Issue {
	var issues []model.Issue

	configutil.Walk(cfg, func(entry configutil.Entry) {
		if !isNetworkBindKey(entry.Key) {
			return
		}

		if !isAllInterfacesAddress(entry.Value) {
			return
		}

		issues = append(issues, model.Issue{
			RuleID:         r.ID(),
			Severity:       model.SeverityMedium,
			Path:           entry.Path,
			Message:        "Сервис привязан к адресу 0.0.0.0 и прослушивает все сетевые интерфейсы",
			Recommendation: "Используйте конкретный сетевой адрес",
		})
	})

	return issues
}

func isNetworkBindKey(key string) bool {
	switch normalizeKey(key) {
	case
		"host",
		"address",
		"addr",
		"bind",
		"bindaddress",
		"bindaddr",
		"listen",
		"listenaddress",
		"listenaddr",
		"interface",
		"serverhost",
		"serveraddress",
		"serveraddr",
		"httphost",
		"httpaddress",
		"httpaddr",
		"grpchost",
		"grpcaddress",
		"grpcaddr":
		return true

	default:
		return false
	}
}

func isAllInterfacesAddress(value any) bool {
	address, ok := value.(string)
	if !ok {
		return false
	}

	return extractHost(address) == "0.0.0.0"
}

func extractHost(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}

	if strings.Contains(address, "://") {
		parsedURL, err := url.Parse(address)
		if err == nil && parsedURL.Hostname() != "" {
			return parsedURL.Hostname()
		}
	}

	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return strings.Trim(host, "[]")
	}

	return strings.Trim(address, "[]")
}
