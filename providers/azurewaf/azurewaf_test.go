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

// The error azure returns when the login is valid but for a different tenant
// from the subscription, as reported from a real run with the ids and resource
// names replaced. The tenant to suggest is the second one: the first is the
// issuer of the token that was refused.
const wrongTenantErr = `error getting policy: policy.GetRawPolicy - GET https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000003/resourceGroups/example-rg/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/examplepolicy` + "\n" +
	`--------------------------------------------------------------------------------` + "\n" +
	`RESPONSE 401: 401 Unauthorized` + "\n" +
	`ERROR CODE: InvalidAuthenticationTokenTenant` + "\n" +
	`--------------------------------------------------------------------------------` + "\n" +
	`{` + "\n" +
	`  "error": {` + "\n" +
	`    "code": "InvalidAuthenticationTokenTenant",` + "\n" +
	`    "message": "The access token is from the wrong issuer 'https://sts.windows.net/00000000-0000-0000-0000-000000000001/'. ` +
	`It must match the tenant 'https://sts.windows.net/00000000-0000-0000-0000-000000000002/' associated with this subscription. ` +
	`Please use the authority (URL) 'https://login.windows.net/00000000-0000-0000-0000-000000000002' to get the token. ` +
	`Note, if the subscription is transferred to another tenant there is no impact to the services, but information about ` +
	`new tenant could take time to propagate (up to an hour). If you just transferred your subscription and see this error ` +
	`message, please try back later."` + "\n" +
	`  }` + "\n" +
	`}` + "\n" +
	`--------------------------------------------------------------------------------`

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
			name: "a login for the wrong tenant names the subscription's tenant, not the token's",
			err:  errors.New(wrongTenantErr),
			want: "azure waf: your azure login is for a different tenant from the waf policy's subscription, " +
				"so its policies were not read. log in to the right tenant with: " +
				"az login --tenant 00000000-0000-0000-0000-000000000002",
		},
		{
			name: "a wrong tenant error without the tenant falls back to a bare az login",
			err:  errors.New("RESPONSE 401: 401 Unauthorized\nERROR CODE: InvalidAuthenticationTokenTenant"),
			want: "azure waf: your azure login is for a different tenant from the waf policy's subscription, " +
				"so its policies were not read. log in to the right tenant with: az login",
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
