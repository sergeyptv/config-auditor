package main

import (
	"context"
	"errors"
	"flag"
	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/httpapi"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 5 * time.Second

	maxHeaderBytes = 1 << 20
)

func main() {
	address := flag.String("addr", "127.0.0.1:8080", "HTTP server listen address")

	flag.Parse()

	analysisService := app.NewAnalysisService()

	server := &http.Server{
		Addr:              *address,
		Handler:           httpapi.NewHandler(analysisService),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go shutdownOnSignal(ctx, server)

	log.Printf("HTTP server is listening on http://%s", *address)

	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func shutdownOnSignal(ctx context.Context, server *http.Server) {
	<-ctx.Done()

	log.Print("shutting down HTTP server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
