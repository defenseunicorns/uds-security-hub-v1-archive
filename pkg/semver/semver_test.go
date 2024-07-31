package semver

import (
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
