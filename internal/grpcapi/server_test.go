package grpcapi

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	configauditv1 "github.com/sergeyptv/config-auditor/api/configaudit/v1"
	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/configloader"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestAnalyzeYAML(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	response, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(`
log:
  level: debug
`),
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_YAML,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.GetCount() != 1 {
		t.Fatalf("expected 1 issue, got %d", response.GetCount())
	}

	issue := response.GetIssues()[0]

	if issue.GetRuleId() != "CFG001" {
		t.Fatalf("expected CFG001, got %q", issue.GetRuleId())
	}

	if issue.GetSeverity() != configauditv1.Severity_SEVERITY_LOW {
		t.Fatalf("expected LOW severity, got %s", issue.GetSeverity())
	}
}

func TestAnalyzeJSON(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	response, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(
				`{"storage":{"digest-algorithm":"MD5"}}`,
			),
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_JSON,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.GetCount() != 1 {
		t.Fatalf("expected 1 issue, got %d", response.GetCount())
	}

	if response.GetIssues()[0].GetRuleId() != "CFG005" {
		t.Fatalf("expected CFG005, got %q", response.GetIssues()[0].GetRuleId())
	}
}

func TestAnalyzeAutoFormat(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	response, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(`
server:
  host: 0.0.0.0
`),
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.GetCount() != 1 {
		t.Fatalf("expected 1 issue, got %d", response.GetCount())
	}

	if response.GetIssues()[0].GetRuleId() != "CFG003" {
		t.Fatalf("expected CFG003, got %q", response.GetIssues()[0].GetRuleId())
	}
}

func TestAnalyzeSafeConfiguration(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	response, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(`
log:
  level: info

server:
  host: 127.0.0.1

tls:
  enabled: true
`),
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_YAML,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.GetCount() != 0 {
		t.Fatalf("expected no issues, got %d", response.GetCount())
	}
}

func TestAnalyzeRejectsInvalidConfig(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	_, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(`{"log":`),
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_JSON,
		},
	)

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected %s, got %s: %v", codes.InvalidArgument, status.Code(err), err)
	}
}

func TestAnalyzeRejectsEmptyConfig(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	_, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: nil,
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_YAML,
		},
	)

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected %s, got %s", codes.InvalidArgument, status.Code(err))
	}
}

func TestAnalyzeRejectsUnknownFormat(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	_, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(`log: {level: info}`),
			Format: configauditv1.ConfigFormat(100),
		},
	)

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected %s, got %s", codes.InvalidArgument, status.Code(err))
	}
}

func TestAnalyzeRejectsLargeConfig(t *testing.T) {
	server := NewServer(app.NewAnalysisService())

	data := strings.Repeat("a", int(configloader.MaxConfigSize)+1)

	_, err := server.Analyze(
		context.Background(),
		&configauditv1.AnalyzeRequest{
			Config: []byte(data),
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_YAML,
		},
	)

	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected %s, got %s: %v", codes.ResourceExhausted, status.Code(err), err)
	}
}

func TestGRPCServerEndToEnd(t *testing.T) {
	const bufferSize = 1024 * 1024

	listener := bufconn.Listen(bufferSize)

	grpcServer := grpc.NewServer()

	configauditv1.RegisterConfigAuditorServer(grpcServer, NewServer(app.NewAnalysisService()))

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("gRPC server stopped: %v", err)
		}
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	connection, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}

	t.Cleanup(func() {
		_ = connection.Close()
	})

	client := configauditv1.NewConfigAuditorClient(connection)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	response, err := client.Analyze(
		ctx,
		&configauditv1.AnalyzeRequest{
			Config: []byte(`
database:
  password: secret
`),
			Format: configauditv1.ConfigFormat_CONFIG_FORMAT_YAML,
		},
	)
	if err != nil {
		t.Fatalf("Analyze RPC failed: %v", err)
	}

	if response.GetCount() != 1 {
		t.Fatalf("expected 1 issue, got %d", response.GetCount())
	}

	if response.GetIssues()[0].GetRuleId() != "CFG002" {
		t.Fatalf("expected CFG002, got %q", response.GetIssues()[0].GetRuleId())
	}
}
