package main

import (
	"context"
	auth "github.com/Brain-Wave-Ecosystem/auth-service/internal/config"
	"github.com/Brain-Wave-Ecosystem/auth-service/internal/server"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/abstractions"
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/config"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := config.Load[auth.Config]()
	if err != nil {
		slog.Error("Error loading config: ", "error", err)
		return
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), cfg.StartTimeout)
	defer startCancel()

	var srv abstractions.Server

	srv, err = server.NewServer(startCtx, cfg)
	if err != nil {
		slog.Error("Error starting server: ", "error", err)
		return
	}

	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

		<-signalCh
		slog.Info("Shutting down server...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer shutdownCancel()

		if err = srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("Server forced to shutdown", "error", err)
		}
	}()

	if err = srv.Start(); err != nil {
		slog.Error("Server failed to start", "error", err)
	}
}
