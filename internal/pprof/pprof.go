package pprof

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" //nolint:gosec
	"time"
)

// StartPprofServer starts a pprof server on the given address.
func StartPprofServer(ctx context.Context, addr string) error {
	if addr == "" {
		return errors.New("address cannot be empty")
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Starting pprof server on %s\n", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("could not listen on %s: %v\n", addr, err)
		}
	}()

	<-ctx.Done()
	log.Printf("Shutting down pprof server on %s\n", addr)
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}
	return nil
}
