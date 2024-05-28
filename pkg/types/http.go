package types

import (
	"fmt"
	"net/http"
	"time"
)

// HTTPClientInterface is an abstraction that allows for easier testing by mocking HTTP responses.
// It defines a single method, Do, which takes an http.Request and returns an http.Response and an error.
type HTTPClientInterface interface {
	Do(req *http.Request) (*http.Response, error)
}

// RealHTTPClient is a concrete implementation of HTTPClientInterface that uses a real http.Client to make requests.
type RealHTTPClient struct {
	Client *http.Client
}

// NewRealHTTPClient creates a new instance of RealHTTPClient with a default http.Client.
// The http.Client can be customized as needed, for example, by setting timeouts.
func NewRealHTTPClient() *RealHTTPClient {
	return &RealHTTPClient{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		}, // Customize it as needed, e.g., by setting timeouts
	}
}

// Do sends an HTTP request using the underlying http.Client and returns the response.
// It satisfies the HTTPClientInterface by implementing the Do method.
func (c *RealHTTPClient) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	return resp, nil
}
