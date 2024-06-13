package pprof

import (
	"context"
	"log"
	"net/http"
	_ "net/http/pprof" //nolint:gosec
	"time"
)

// StartPprofServer starts a pprof server on the given address.
func StartPprofServer(ctx context.Context, addr string) {
	server := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Minute,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", addr, err)
	}
}
