package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	configauditv1 "github.com/sergeyptv/config-auditor/api/configaudit/v1"
	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/configloader"
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/parser"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	configauditv1.UnimplementedConfigAuditorServer

	service *app.AnalysisService
}

func NewServer(service *app.AnalysisService) *Server {
	if service == nil {
		panic("analysis service must not be nil")
	}

	return &Server{service: service}
}

func (s *Server) Analyze(ctx context.Context, request *configauditv1.AnalyzeRequest) (*configauditv1.AnalyzeResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request must not be nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}

	format, err := requestFormat(request.GetFormat())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if len(request.GetConfig()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration is empty")
	}

	issues, err := s.service.Analyze(bytes.NewReader(request.GetConfig()), format)
	if err != nil {
		return nil, analysisError(err)
	}

	protoIssues := make([]*configauditv1.Issue, 0, len(issues))

	for _, issue := range issues {
		protoIssues = append(protoIssues, issueToProto(issue))
	}

	return &configauditv1.AnalyzeResponse{
		Issues: protoIssues,
		Count:  uint32(len(protoIssues)),
	}, nil
}

func requestFormat(format configauditv1.ConfigFormat) (parser.Format, error) {
	switch format {
	case configauditv1.ConfigFormat_CONFIG_FORMAT_UNSPECIFIED:
		return parser.FormatAuto, nil

	case configauditv1.ConfigFormat_CONFIG_FORMAT_JSON:
		return parser.FormatJSON, nil

	case configauditv1.ConfigFormat_CONFIG_FORMAT_YAML:
		return parser.FormatYAML, nil

	default:
		return parser.FormatAuto, fmt.Errorf("unsupported configuration format: %d", format)
	}
}

func analysisError(err error) error {
	if errors.Is(err, configloader.ErrConfigTooLarge) {
		return status.Error(codes.ResourceExhausted, "configuration exceeds maximum allowed size")
	}

	return status.Errorf(codes.InvalidArgument, "invalid configuration: %v", err)
}

func issueToProto(issue model.Issue) *configauditv1.Issue {
	return &configauditv1.Issue{
		RuleId:         issue.RuleID,
		Severity:       severityToProto(issue.Severity),
		Path:           issue.Path,
		Message:        issue.Message,
		Recommendation: issue.Recommendation,
	}
}

func severityToProto(severity model.Severity) configauditv1.Severity {
	switch severity {
	case model.SeverityLow:
		return configauditv1.Severity_SEVERITY_LOW

	case model.SeverityMedium:
		return configauditv1.Severity_SEVERITY_MEDIUM

	case model.SeverityHigh:
		return configauditv1.Severity_SEVERITY_HIGH

	default:
		return configauditv1.Severity_SEVERITY_UNSPECIFIED
	}
}
