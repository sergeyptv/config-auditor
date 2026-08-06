package app

import (
	"github.com/sergeyptv/config-auditor/internal/analyzer"
	"github.com/sergeyptv/config-auditor/internal/configloader"
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/parser"
	"io"
)

type AnalysisService struct {
	analyzer *analyzer.Analyzer
}

func NewAnalysisService() *AnalysisService {
	return &AnalysisService{analyzer: NewSecurityAnalyzer()}
}

func (s *AnalysisService) Analyze(reader io.Reader, format parser.Format) ([]model.Issue, error) {
	cfg, err := configloader.Load(reader, format)
	if err != nil {
		return nil, err
	}

	return s.analyzer.Analyze(cfg), nil
}
