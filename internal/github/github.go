package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/defenseunicorns/uds-security-hub/pkg/types"
)

// PackageVersion is a struct that represents the package version.
type PackageVersion struct {
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Name           string    `json:"name"`
	URL            string    `json:"url"`
	PackageHTMLURL string    `json:"package_html_url"`
	HTMLURL        string    `json:"html_url"`
	Metadata       struct {
		PackageType string `json:"package_type"`
		Container   struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	} `json:"metadata"`
	ID int `json:"id"`
}

// VersionTagDate is a struct that represents the version tag date.
type VersionTagDate struct {
	Date time.Time `json:"date"`
	Tags []string  `json:"tags"`
}

// GetPackageVersions fetches package versions from GitHub and returns the tags and
// creation dates for versions with non-empty tags.
// GetPackageVersions is refactored to accept an HTTPClientInterface.
// This allows for injecting a mock HTTP client during testing.
func GetPackageVersions(ctx context.Context, client types.HTTPClientInterface, token, org, packageType,
	packageName string) ([]VersionTagDate, error) {
	if token == "" {
		return nil, fmt.Errorf("GitHub token is not provided")
	}

	if client == nil {
		// Fallback to a default HTTP client if none is provided.
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		client = oauth2.NewClient(ctx, ts)
	}

	url := fmt.Sprintf("https://api.github.com/orgs/%s/packages/%s/%s/versions", org, packageType, packageName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var versions []PackageVersion
	if err := json.Unmarshal(body, &versions); err != nil {
		return nil, fmt.Errorf("error parsing JSON response: %w", err)
	}

	var tagDates []VersionTagDate
	for i := range versions {
		v := &versions[i]
		if len(v.Metadata.Container.Tags) > 0 {
			tagDates = append(tagDates, VersionTagDate{
				Tags: v.Metadata.Container.Tags,
				Date: v.CreatedAt,
			})
		}
	}

	return tagDates, nil
}
