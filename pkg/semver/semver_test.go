package semver

import (
	"errors"
	"testing"
)

func TestGetNMinusTwoSemvers(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 4

	expected := []string{"1.0.0", "1.1.0"}
	result, err := GetNMinusTwoSemvers(versions, n)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(result) != len(expected) {
		t.Fatalf("Expected %d versions, got %d", len(expected), len(result))
	}

	for i, v := range result {
		if v != expected[i] {
			t.Errorf("Expected version %s, got %s", expected[i], v)
		}
	}
}

func TestGetNMinusCustomExcludeSemvers(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 4
	exclude := 3

	expected := []string{"1.0.0"}
	result, err := GetNMinusTwoSemvers(versions, n, exclude) // Corrected function call
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if len(result) != len(expected) {
		t.Fatalf("Expected %d versions, got %d", len(expected), len(result))
	}

	for i, v := range result {
		if v != expected[i] {
			t.Errorf("Expected version %s, got %s", expected[i], v)
		}
	}
}

func TestGetNMinusTwoSemversInvalidN(t *testing.T) {
	versions := []string{"1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"}
	n := 1 // n is less than excludeCount (which defaults to 2)

	_, err := GetNMinusTwoSemvers(versions, n)
	if err == nil {
		t.Fatal("Expected an error but got none")
	}

	if !errors.Is(err, ErrInvalidN) {
		t.Fatalf("Expected error %v, got %v", ErrInvalidN, err)
	}
}

func TestGetNMinusTwoSemversNotEnoughVersions(t *testing.T) {
	versions := []string{"1.0.0"}
	n := 3 // More versions requested than available

	_, err := GetNMinusTwoSemvers(versions, n)
	if err == nil {
		t.Fatal("Expected an error but got none")
	}

	if !errors.Is(err, ErrNotEnoughVersions) {
		t.Fatalf("Expected error %v, got %v", ErrNotEnoughVersions, err)
	}
}

func TestGetNMinusTwoSemversInvalidVersion(t *testing.T) {
	versions := []string{"1.0.0", "invalid_version", "2.0.0"} // invalid_version is not a valid semver
	n := 3

	_, err := GetNMinusTwoSemvers(versions, n)
	if err == nil {
		t.Fatal("Expected an error but got none")
	}

	if !errors.Is(err, ErrInvalidSemver) {
		t.Fatalf("Expected error %v, got %v", ErrInvalidSemver, err)
	}
}
