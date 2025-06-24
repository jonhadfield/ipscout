package ui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jonhadfield/ipscout/providers"
)

// Error message constants
const (
	ErrMsgInvalidDataFormat = "Invalid data format"
)

// Common UI error variables for simplified user messages
var (
	ErrNoDataAvailable = errors.New("no data available")
	ErrInvalidIP       = errors.New("invalid IP address")
	ErrProviderError   = errors.New("provider unavailable")
	ErrParsingFailed   = errors.New("data parsing failed")
)

// simplifyError converts complex error chains into user-friendly messages
func simplifyError(err error, provider, _ string) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Check for common provider errors
	if errors.Is(err, providers.ErrNoMatchFound) ||
		strings.Contains(errStr, "no match found") ||
		strings.Contains(errStr, "not found") {
		return fmt.Sprintf("%s: No data found", provider)
	}

	if errors.Is(err, providers.ErrNoDataFound) ||
		strings.Contains(errStr, "no data found") {
		return "No data available"
	}

	if errors.Is(err, providers.ErrForbiddenByProvider) ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "quota") ||
		strings.Contains(errStr, "rate limit") {
		return "Service temporarily unavailable"
	}

	// Check for invalid host/IP first (more specific)
	if strings.Contains(errStr, "invalid") &&
		(strings.Contains(errStr, "host") || strings.Contains(errStr, "ip")) {
		return "Invalid IP address"
	}

	// Check for network/connection errors
	if strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "dial") ||
		strings.Contains(errStr, "deadline exceeded") {
		return "Connection failed"
	}

	// Check for parsing errors
	if strings.Contains(errStr, "unmarshal") ||
		strings.Contains(errStr, "decode") ||
		strings.Contains(errStr, "invalid character") {
		return ErrMsgInvalidDataFormat
	}

	// Check for generic parsing errors (less specific, so after others)
	if strings.Contains(errStr, "parsing") {
		return ErrMsgInvalidDataFormat
	}

	// Check for authentication/authorization errors
	if strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "api key") {
		return "Authentication required"
	}

	// Check for provider not enabled
	if strings.Contains(errStr, "not enabled") {
		return "Provider not configured"
	}

	// Default fallback for unknown errors
	return "Service error"
}
