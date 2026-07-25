package cmd

import (
	"testing"

	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// TestAllRegistryProvidersWiredIntoConfig guards against the class of bug where
// a provider is added to the registry but not wired into initProviderConfig, so
// its Enabled flag is never read from config and process silently skips it.
func TestAllRegistryProvidersWiredIntoConfig(t *testing.T) {
	v := viper.New()
	for _, e := range registry.All() {
		v.Set("providers."+e.Name+".enabled", true)
	}

	sess := session.New()
	initProviderConfig(sess, v)

	for _, e := range registry.All() {
		enabled := e.Enabled(*sess)
		require.NotNilf(t, enabled, "provider %q is in the registry but not wired into initProviderConfig", e.Name)
		require.Truef(t, *enabled, "provider %q enabled flag was not read from config", e.Name)
	}
}

// TestNoConfigProvidersEnabledByDefault guards the promise that providers
// requiring no configuration are enabled even when absent from the user's
// config file, while providers that need config (API keys, paths, URLs,
// resource IDs) stay unset so process skips them.
func TestNoConfigProvidersEnabledByDefault(t *testing.T) {
	sess := session.New()
	initProviderConfig(sess, viper.New())

	for _, e := range registry.All() {
		enabled := e.Enabled(*sess)
		if e.DefaultEnabled {
			require.NotNilf(t, enabled, "no-config provider %q should be enabled by default", e.Name)
			require.Truef(t, *enabled, "no-config provider %q should be enabled by default", e.Name)
		} else {
			require.Nilf(t, enabled, "provider %q requires config and must not be enabled by default", e.Name)
		}
	}
}

// TestExplicitDisableOverridesDefaultEnabled ensures a user's explicit
// enabled=false still wins over the no-config default.
func TestExplicitDisableOverridesDefaultEnabled(t *testing.T) {
	v := viper.New()
	v.Set("providers.aws.enabled", false)

	sess := session.New()
	initProviderConfig(sess, v)

	require.NotNil(t, sess.Providers.AWS.Enabled)
	require.False(t, *sess.Providers.AWS.Enabled)
}
