package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	configauditv1 "github.com/sergeyptv/config-auditor/api/configaudit/v1"
	"github.com/sergeyptv/config-auditor/internal/app"
	"github.com/sergeyptv/config-auditor/internal/configloader"
	"github.com/sergeyptv/config-auditor/internal/grpcapi"

	"google.golang.org/grpc"
)

const (
	shutdownTimeout = 5 * time.Second

	messageOverhead = 64 * 1024
)

func main() {
	address := flag.String("addr", "127.0.0.1:9090", "gRPC server listen address")

	flag.Parse()

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatalf("listen on %s: %v", *address, err)
	}

	maxReceiveSize := int(configloader.MaxConfigSize + messageOverhead)

	grpcServer := grpc.NewServer(grpc.MaxRecvMsgSize(maxReceiveSize))

	analysisService := app.NewAnalysisService()

	configauditv1.RegisterConfigAuditorServer(grpcServer, grpcapi.NewServer(analysisService))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go shutdownOnSignal(ctx, grpcServer)

	log.Printf("gRPC server is listening on %s", *address)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}

func shutdownOnSignal(ctx context.Context, server *grpc.Server) {
	<-ctx.Done()

	log.Print("shutting down gRPC server")

	stopped := make(chan struct{})

	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		log.Print("gRPC server stopped gracefully")

	case <-time.After(shutdownTimeout):
		log.Print("graceful shutdown timed out; forcing stop")

		server.Stop()
	}
}
