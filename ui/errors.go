package ui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jonhadfield/ipscout/providers"
)

// Error message constants
const (
	ErrMsgInvalidDataFormat             = "Invalid data format"
	ErrMsgNoDataFound                   = "No data found"
	ErrMsgNoDataAvailable               = "No data available"
	ErrMsgServiceTemporarilyUnavailable = "Service temporarily unavailable"
	ErrMsgInvalidIPAddress              = "Invalid IP address"
	ErrMsgConnectionFailed              = "Connection failed"
	ErrMsgProviderNotConfigured         = "Provider not configured"
	ErrMsgAuthenticationRequired        = "Authentication required"
	ErrMsgServiceError                  = "Service error"
	ErrMsgAPIKeyRejected                = "API key rejected"
	// ErrMsgFailureReported marks a failure the provider explained itself,
	// whose message is shown in the footer instead of a generic line
	ErrMsgFailureReported = "See the message above"
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

	// checked first: its message would otherwise match the generic
	// authentication patterns below
	if errors.Is(err, providers.ErrAPIKeyRejected) {
		return ErrMsgAPIKeyRejected
	}

	// the provider has already said what went wrong, e.g. criminal ip naming
	// an exceeded quota, and that message reaches the footer on its own
	if errors.Is(err, providers.ErrFailureReported) {
		return ErrMsgFailureReported
	}

	// Check for common provider errors
	if errors.Is(err, providers.ErrNoMatchFound) ||
		strings.Contains(errStr, "no match found") ||
		strings.Contains(errStr, "not found") {
		return fmt.Sprintf("%s: %s", provider, ErrMsgNoDataFound)
	}

	if errors.Is(err, providers.ErrNoDataFound) ||
		strings.Contains(errStr, "no data found") {
		return ErrMsgNoDataAvailable
	}

	if errors.Is(err, providers.ErrForbiddenByProvider) ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "quota") ||
		strings.Contains(errStr, "rate limit") {
		return ErrMsgServiceTemporarilyUnavailable
	}

	// Check for invalid host/IP first (more specific)
	if strings.Contains(errStr, "invalid") &&
		(strings.Contains(errStr, "host") || strings.Contains(errStr, "ip")) {
		return ErrMsgInvalidIPAddress
	}

	// Check for network/connection errors
	if strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "dial") ||
		strings.Contains(errStr, "deadline exceeded") {
		return ErrMsgConnectionFailed
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
		return ErrMsgAuthenticationRequired
	}

	// Check for provider not enabled
	if strings.Contains(errStr, "not enabled") {
		return ErrMsgProviderNotConfigured
	}

	// Default fallback for unknown errors
	return ErrMsgServiceError
}
