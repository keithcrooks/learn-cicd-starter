package auth

import (
	"fmt"
	"net/http"
	"testing"
)

func TestGetAPI(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		expectedAPIKey := "0123456789abcdef"
		authHeader := fmt.Sprintf("ApiKey %s", expectedAPIKey)
		headers := http.Header{}
		headers.Set("Authorization", authHeader)

		apiKey, err := GetAPIKey(headers)

		if err != nil {
			t.Fatalf("GetAPIKey(): expected '%s', got error: %v", expectedAPIKey, err)
		}

		if apiKey != expectedAPIKey {
			t.Fatalf("GetAPIKey(): expected: %s, Got: %s", expectedAPIKey, apiKey)
		}
	})

	t.Run("Authorization header not set", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)

		if err == nil {
			t.Fatalf("GetAPIKey(): expected error: %v, got API key: %s", ErrNoAuthHeaderIncluded, apiKey)
		}

		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("GetAPIKey(): expected error: %v, got: %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("Authorization header empty", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "")

		apiKey, err := GetAPIKey(headers)

		if err == nil {
			t.Fatalf("GetAPIKey(): expected error: %v, got API key: %s", ErrNoAuthHeaderIncluded, apiKey)
		}

		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("GetAPIKey(): expected error: %v, got: %v", ErrNoAuthHeaderIncluded, err)
		}
	})

	t.Run("Malformed authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer a1b2c3d4")

		apiKey, err := GetAPIKey(headers)

		if err == nil {
			t.Fatalf("GetAPIKey(): expected error: %v, got API key: %s", ErrNoAuthHeaderIncluded, apiKey)
		}

		if err.Error() != "malformed authorization header" {
			t.Fatalf("GetAPIKey(): expected error: %v, got: %v", "malformed authorization header", err)
		}
	})
}
