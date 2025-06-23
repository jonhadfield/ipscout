package ui

import (
	"errors"
	"testing"

	"github.com/jonhadfield/ipscout/providers"
)

func TestSimplifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrNoMatchFound",
			err:      providers.ErrNoMatchFound,
			expected: "No data found",
		},
		{
			name:     "ErrNoDataFound",
			err:      providers.ErrNoDataFound,
			expected: "No data available",
		},
		{
			name:     "ErrForbiddenByProvider",
			err:      providers.ErrForbiddenByProvider,
			expected: "Service temporarily unavailable",
		},
		{
			name:     "Complex error chain with no match found",
			err:      errors.New("failed to find hosts: failed to find hosts: annotated match failed: no match found"),
			expected: "No data found",
		},
		{
			name:     "Complex error chain with parsing error",
			err:      errors.New("error unmarshalling response: invalid character"),
			expected: "Invalid data format",
		},
		{
			name:     "Network timeout error",
			err:      errors.New("failed to make request: context deadline exceeded (Client.Timeout exceeded)"),
			expected: "Connection failed",
		},
		{
			name:     "Invalid host error",
			err:      errors.New("error parsing host: invalid IP address"),
			expected: "Invalid IP address",
		},
		{
			name:     "Provider not enabled",
			err:      errors.New("provider shodan is not enabled"),
			expected: "Provider not configured",
		},
		{
			name:     "Unknown error",
			err:      errors.New("some unknown error occurred"),
			expected: "Service error",
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := simplifyError(tt.err, "test", "127.0.0.1")
			if result != tt.expected {
				t.Errorf("simplifyError() = %q, want %q", result, tt.expected)
			}
		})
	}
}
