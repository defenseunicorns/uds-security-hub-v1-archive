package oci

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
)

// MockDockerClient is a mock of the Docker client.
type MockDockerClient struct {
	mock.Mock
}

// ImageInspectWithRaw mocks the ImageInspectWithRaw function.
func (m *MockDockerClient) ImageInspectWithRaw(ctx context.Context, imageID string) (types.ImageInspect, []byte, error) {
	args := m.Called(ctx, imageID)
	return args.Get(0).(types.ImageInspect), args.Get(1).([]byte), args.Error(2)
}

// TestImageBuildTime tests the ImageBuildTime function.
func TestImageBuildTime(t *testing.T) {
	mockClient := new(MockDockerClient)
	ctx := context.Background()

	// Test cases.
	tests := []struct {
		name         string
		imageRef     string
		setupMocks   func()
		expectedErr  string
		expectedTime *time.Time
	}{
		{
			name:     "Successful image inspection",
			imageRef: "valid-image",
			setupMocks: func() {
				mockClient.On("ImageInspectWithRaw", ctx, "valid-image").Return(types.ImageInspect{Created: "2021-10-21T14:33:00Z"}, []byte{}, nil)
			},
			expectedErr:  "",
			expectedTime: func() *time.Time { t, _ := time.Parse(time.RFC3339, "2021-10-21T14:33:00Z"); return &t }(), //nolint:errcheck
		},
		{
			name:     "Error inspecting image",
			imageRef: "invalid-image",
			setupMocks: func() {
				mockClient.On("ImageInspectWithRaw", ctx, "invalid-image").Return(types.ImageInspect{}, []byte{}, errors.New("failed to inspect image"))
			},
			expectedErr:  "failed to inspect image: failed to inspect image",
			expectedTime: nil,
		},
		{
			name:     "Error parsing creation time",
			imageRef: "image-with-invalid-time",
			setupMocks: func() {
				mockClient.On("ImageInspectWithRaw", ctx, "image-with-invalid-time").Return(types.ImageInspect{Created: "invalid-time"}, []byte{}, nil)
			},
			expectedErr:  "failed to parse image creation time: parsing time \"invalid-time\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"invalid-time\" as \"2006\"",
			expectedTime: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			buildTime, err := ImageBuildTime(mockClient, tt.imageRef)

			if tt.expectedErr != "" {
				if diff := cmp.Diff(tt.expectedErr, err.Error()); diff != "" {
					t.Errorf("Error mismatch (-want +got):\n%s", diff)
				}
			} else {
				if diff := cmp.Diff(tt.expectedTime, buildTime); diff != "" {
					t.Errorf("Time mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
