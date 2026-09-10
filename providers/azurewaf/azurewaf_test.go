package azurewaf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// The error azure actually returns when a cached credential has been revoked,
// as reported from a real run. Kept verbatim, because the parsing depends on
// the shape of it rather than on any one field.
const expiredGrantErr = `policy.GetRawPolicy | API call failed after 951.627042ms: ` +
	`AzureCLICredential: ERROR: AADSTS50173: The provided grant has expired due to it being revoked, ` +
	`a fresh auth token is needed. The user might have changed or reset their password. ` +
	`The grant was issued on '2026-07-09T10:12:06.6848427Z' and the TokensValidFrom date ` +
	`(before which tokens are not valid) for this user is '2026-09-07T13:14:19.0000000Z'. ` +
	`Trace ID: 103ecf08-fa51-4c65-8d5a-ee6912a74b00 Correlation ID: a53038ad-f8a9-40f1-8966-81a4c1f94769 ` +
	`Timestamp: 2026-09-08 18:41:35Z` + "\n" +
	`Run the command below to authenticate interactively; additional arguments may be added as needed:` + "\n" +
	`az logout` + "\n" +
	`az login --tenant "78ade5b2-2582-4cdd-b7c6-587ba2187324" --scope "https://management.core.windows.net//.default"`

func TestAzureAuthHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "expired grant names the tenant from the suggested command",
			err:  errors.New(expiredGrantErr),
			want: "azure waf: your azure credentials have expired, so its policies were not read. " +
				"re-authenticate with: az login --tenant 78ade5b2-2582-4cdd-b7c6-587ba2187324",
		},
		{
			name: "auth failure with no tenant falls back to a bare az login",
			err:  errors.New("AzureCLICredential: ERROR: AADSTS700082: refresh token has expired"),
			want: "azure waf: your azure credentials have expired, so its policies were not read. " +
				"re-authenticate with: az login",
		},
		{
			name: "an unrelated failure is left alone",
			err:  errors.New("policy.GetRawPolicy | API call failed: connection refused"),
			want: "",
		},
		{
			name: "a missing policy is not an auth problem",
			err:  errors.New("RESPONSE 404: ResourceNotFound"),
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, azureAuthHint(tc.err))
		})
	}
}
