package semver

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetNMinusTwoSemvers(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 4

	expected := []string{"1.0.0", "1.1.0"}
	result, err := GetNMinusTwoSemvers(versions, n)
	require.NoError(t, err)
	require.Equal(t, len(expected), len(result), "expected and result slice lengths do not match")

	for i, v := range result {
		assert.Equal(t, expected[i], v, "version mismatch at index %d", i)
	}
}

func TestGetNMinusCustomExcludeSemvers(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 4
	exclude := 3

	expected := []string{"1.0.0"}
	result, err := GetNMinusTwoSemvers(versions, n, exclude) // Corrected function call
	require.NoError(t, err)
	require.Equal(t, len(expected), len(result), "expected and result slice lengths do not match")

	for i, v := range result {
		assert.Equal(t, expected[i], v, "version mismatch at index %d", i)
	}
}

func TestGetNMinusTwoSemversInvalidN(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 1 // n is less than excludeCount (which defaults to 2)

	_, err := GetNMinusTwoSemvers(versions, n)
	require.Error(t, err, "expected an error but got none")
	require.True(t, errors.Is(err, ErrInvalidN), "expected error %v, got %v", ErrInvalidN, err)
}

func TestGetNMinusTwoSemversNotEnoughVersions(t *testing.T) {
	versions := []string{"1.0.0"}
	n := 3 // More versions requested than available

	_, err := GetNMinusTwoSemvers(versions, n)
	require.Error(t, err, "expected an error but got none")
	require.True(t, errors.Is(err, ErrNotEnoughVersions), "expected error %v, got %v", ErrNotEnoughVersions, err)
}

func TestGetNMinusTwoSemversInvalidVersion(t *testing.T) {
	versions := []string{"1.0.0", "invalid_version", "2.0.0"} // invalid_version is not a valid semver
	n := 3

	_, err := GetNMinusTwoSemvers(versions, n)
	require.Error(t, err, "expected an error but got none")
	require.True(t, errors.Is(err, ErrInvalidSemver), "expected error %v, got %v", ErrInvalidSemver, err)
}
