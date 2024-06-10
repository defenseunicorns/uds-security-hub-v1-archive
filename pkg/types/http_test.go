package types

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// MockHTTPClient is a mock implementation of HTTPClientInterface for testing purposes.
type MockHTTPClient struct {
	Response *http.Response
	Err      error
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.Response, m.Err
}

func TestRealHTTPClient_Do(t *testing.T) {
	// Create a test server that returns a predefined response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, client")) //nolint:errcheck
	}))
	defer ts.Close()

	client := NewRealHTTPClient()
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil) //nolint:noctx
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestMockHTTPClient_Do(t *testing.T) {
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("Mock response")),
	}
	mockClient := &MockHTTPClient{
		Response: mockResp,
		Err:      nil,
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := mockClient.Do(req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
	defer resp.Body.Close()
}

func TestMockHTTPClient_Do_Error(t *testing.T) {
	mockClient := &MockHTTPClient{
		Response: nil,
		Err:      fmt.Errorf("mock error"),
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := mockClient.Do(req) //nolint:bodyclose
	if err == nil {
		t.Fatalf("Expected error, got none")
	}
	if resp != nil {
		t.Fatalf("Expected no response, got %v", resp)
	}
}
