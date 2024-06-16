package pprof

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestStartPprofServer(t *testing.T) {
	t.Run("Valid_address", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		addr := "127.0.0.1:6060"
		go func() {
			if err := StartPprofServer(ctx, addr); err != nil {
				t.Logf("expected no error, got %v", err)
			}
		}()

		// Retry mechanism to check if the server is running
		var (
			resp *http.Response
			err  error
		)
		for i := 0; i < 10; i++ {
			resp, err = http.Get(fmt.Sprintf("http://%s/debug/pprof/", addr)) //nolint:bodyclose,noctx
			if err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
		}
	})
}
