package cmd

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/gcrane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
)

func getTags(repoName string) ([]string, error) {
	repo, err := name.NewRepository(repoName)
	if err != nil {
		return nil, err
	}

	var t []string

	err = google.Walk(repo, func(repo name.Repository, tags *google.Tags, err error) error {
		if err != nil {
			return err
		}
		t = tags.Tags
		return nil
	}, google.WithAuthFromKeychain(gcrane.Keychain))

	if err != nil {
		return nil, err
	}

	var max = 5
	var tagsICareAbout []string
	var uniq map[string]struct{} = make(map[string]struct{})

	for i := len(t) - 1; i >= 0; i-- {
		tag := t[i]

		first := strings.SplitN(tag, "-", -1)[0]
		uniq[first] = struct{}{}

		if len(uniq) > max {
			break
		}

		tagsICareAbout = append(tagsICareAbout, tag)
	}

	return tagsICareAbout, nil
}

func TestT(t *testing.T) {
	tags, err := getTags("ghcr.io/defenseunicorns/packages/private/uds/core")
	if err != nil {
		t.Fatal(err)
	}

	for _, tag := range tags {
		t.Log(tag)
	}
	t.Fail()
}
