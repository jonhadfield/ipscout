package ui

import (
	"errors"
	"fmt"
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
			expected: fmt.Sprintf("test: %s", ErrMsgNoDataFound),
		},
		{
			name:     "ErrNoDataFound",
			err:      providers.ErrNoDataFound,
			expected: ErrMsgNoDataAvailable,
		},
		{
			name:     "ErrForbiddenByProvider",
			err:      providers.ErrForbiddenByProvider,
			expected: ErrMsgServiceTemporarilyUnavailable,
		},
		{
			name:     "Complex error chain with no match found",
			err:      errors.New("failed to find hosts: failed to find hosts: annotated match failed: no match found"),
			expected: fmt.Sprintf("test: %s", ErrMsgNoDataFound),
		},
		{
			name:     "Complex error chain with parsing error",
			err:      errors.New("error unmarshalling response: invalid character"),
			expected: ErrMsgInvalidDataFormat,
		},
		{
			name:     "Network timeout error",
			err:      errors.New("failed to make request: context deadline exceeded (Client.Timeout exceeded)"),
			expected: ErrMsgConnectionFailed,
		},
		{
			name:     "Invalid host error",
			err:      errors.New("error parsing host: invalid IP address"),
			expected: ErrMsgInvalidIPAddress,
		},
		{
			name:     "Provider not enabled",
			err:      errors.New("provider shodan is not enabled"),
			expected: ErrMsgProviderNotConfigured,
		},
		{
			name:     "Unknown error",
			err:      errors.New("some unknown error occurred"),
			expected: ErrMsgServiceError,
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
