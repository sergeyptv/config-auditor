package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sergeyptv/config-auditor/internal/app"
)

func TestAnalyzeYAML(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader(`
log:
  level: debug
`),
	)

	request.Header.Set("Content-Type", "application/yaml")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}

	var response AnalysisResponse

	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Count != 1 {
		t.Fatalf("expected 1 issue, got %d", response.Count)
	}

	if response.Issues[0].RuleID != "CFG001" {
		t.Fatalf("expected CFG001, got %q", response.Issues[0].RuleID)
	}
}

func TestAnalyzeJSON(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader(`{"storage":{"digest-algorithm":"MD5"}}`))

	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}

	var response AnalysisResponse

	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Count != 1 {
		t.Fatalf("expected 1 issue, got %d", response.Count)
	}

	if response.Issues[0].RuleID != "CFG005" {
		t.Fatalf("expected CFG005, got %q", response.Issues[0].RuleID)
	}
}

func TestAnalyzeSafeConfiguration(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader(`
log:
  level: info

server:
  host: 127.0.0.1

tls:
  enabled: true
`),
	)

	request.Header.Set("Content-Type", "application/yaml")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var response AnalysisResponse

	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Count != 0 {
		t.Fatalf("expected no issues, got %d", response.Count)
	}

	if response.Issues == nil {
		t.Fatal("expected empty issues array, got null")
	}
}

func TestAnalyzeInvalidConfiguration(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(`{"log":`))

	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, recorder.Code, recorder.Body.String())
	}
}

func TestAnalyzeRejectsUnsupportedContentType(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader("key=value"))

	request.Header.Set("Content-Type", "application/xml")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status %d, got %d", http.StatusUnsupportedMediaType, recorder.Code)
	}
}

func TestAnalyzeRejectsWrongMethod(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodGet, "/v1/analyze", nil)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, recorder.Code)
	}

	if recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("expected Allow header %q, got %q", http.MethodPost, recorder.Header().Get("Allow"))
	}
}

func TestAnalyzeRejectsLargeBody(t *testing.T) {
	handler := newHandler(app.NewAnalysisService(), 32)

	request := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(strings.Repeat("a", 33)))

	request.Header.Set("Content-Type", "application/yaml")

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d: %s", http.StatusRequestEntityTooLarge, recorder.Code, recorder.Body.String())
	}
}

func TestHealth(t *testing.T) {
	handler := NewHandler(app.NewAnalysisService())

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if !strings.Contains(recorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}
