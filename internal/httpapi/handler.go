package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/configloader"
	"github.com/sergeyptv/config-auditor/internal/model"
	"github.com/sergeyptv/config-auditor/internal/parser"
	"mime"
	"net/http"
	"strings"
)

var errUnsupportedMediaType = errors.New("unsupported media type")

type Handler struct {
	service     *app.AnalysisService
	maxBodySize int64
}

type AnalysisResponse struct {
	Issues []model.Issue `json:"issues"`
	Count  int           `json:"count"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func NewHandler(service *app.AnalysisService) http.Handler {
	return newHandler(service, configloader.MaxConfigSize)
}

func newHandler(service *app.AnalysisService, maxBodySize int64) http.Handler {
	if service == nil {
		panic("analysis service must not be nil")
	}

	handler := &Handler{
		service:     service,
		maxBodySize: maxBodySize,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/analyze", handler.analyze)
	mux.HandleFunc("/healthz", handler.health)

	return mux
}

func (h *Handler) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)

		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})

		return
	}

	format, err := requestFormat(r)
	if err != nil {
		statusCode := http.StatusBadRequest

		if errors.Is(err, errUnsupportedMediaType) {
			statusCode = http.StatusUnsupportedMediaType
		}

		writeJSON(w, statusCode, ErrorResponse{Error: err.Error()})

		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)

	issues, err := h.service.Analyze(r.Body, format)
	if err != nil {
		statusCode := statusCodeForAnalysisError(err)

		writeJSON(w, statusCode, ErrorResponse{Error: "invalid configuration: " + err.Error()})

		return
	}

	if issues == nil {
		issues = make([]model.Issue, 0)
	}

	writeJSON(w, http.StatusOK, AnalysisResponse{
		Issues: issues,
		Count:  len(issues),
	},
	)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)

		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func requestFormat(r *http.Request) (parser.Format, error) {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))

	if contentType == "" {
		return parser.FormatAuto, nil
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return parser.FormatAuto, fmt.Errorf("invalid Content-Type header: %w", err)
	}

	switch strings.ToLower(mediaType) {
	case "application/json":
		return parser.FormatJSON, nil

	case
		"application/yaml",
		"application/x-yaml",
		"text/yaml",
		"text/x-yaml":
		return parser.FormatYAML, nil

	default:
		return parser.FormatAuto, fmt.Errorf("%w: %s", errUnsupportedMediaType, mediaType)
	}
}

func statusCodeForAnalysisError(err error) int {
	var maxBytesError *http.MaxBytesError

	if errors.As(err, &maxBytesError) ||
		errors.Is(err, configloader.ErrConfigTooLarge) {
		return http.StatusRequestEntityTooLarge
	}

	return http.StatusBadRequest
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	w.WriteHeader(statusCode)

	_ = json.NewEncoder(w).Encode(value)
}
