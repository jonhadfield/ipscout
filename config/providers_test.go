package config

import (
	"testing"

	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// TestAllRegistryProvidersWiredIntoConfig guards against the class of bug where
// a provider is added to the registry but not wired into InitProviders, so
// its Enabled flag is never read from config and process silently skips it.
func TestAllRegistryProvidersWiredIntoConfig(t *testing.T) {
	v := viper.New()
	for _, e := range registry.All() {
		v.Set("providers."+e.Name+".enabled", true)
	}

	sess := session.New()
	InitProviders(sess, v)

	for _, e := range registry.All() {
		enabled := e.Enabled(*sess)
		require.NotNilf(t, enabled, "provider %q is in the registry but not wired into InitProviders", e.Name)
		require.Truef(t, *enabled, "provider %q enabled flag was not read from config", e.Name)
	}
}

// TestNoConfigProvidersEnabledByDefault guards the promise that providers
// requiring no configuration are enabled even when absent from the user's
// config file, while providers that need config (API keys, paths, URLs,
// resource IDs) stay unset so process skips them.
func TestNoConfigProvidersEnabledByDefault(t *testing.T) {
	sess := session.New()
	InitProviders(sess, viper.New())

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
	InitProviders(sess, v)

	require.NotNil(t, sess.Providers.AWS.Enabled)
	require.False(t, *sess.Providers.AWS.Enabled)
}

func TestGooglebotOutputPriorityKey(t *testing.T) {
	v := viper.New()
	v.Set("providers.googlebot.output_priority", int32(42))
	v.Set("providers.googlesc.output_priority", int32(43))

	sess := session.New()
	InitProviders(sess, v)

	require.NotNil(t, sess.Providers.Googlebot.OutputPriority)
	require.Equal(t, int32(42), *sess.Providers.Googlebot.OutputPriority)
	require.NotNil(t, sess.Providers.GoogleSC.OutputPriority)
	require.Equal(t, int32(43), *sess.Providers.GoogleSC.OutputPriority)
}

func TestToPtr(t *testing.T) {
	v := 7
	p := ToPtr(v)
	require.Equal(t, v, *p)
}

// TestProvidersAbsentFromConfigAddNoMessages guards that a provider missing
// from the config, such as a keyed provider in an older config, is simply
// disabled rather than reported on every run.
func TestProvidersAbsentFromConfigAddNoMessages(t *testing.T) {
	sess := session.New()
	InitProviders(sess, viper.New())

	require.Empty(t, sess.Messages.Info)
	require.Empty(t, sess.Messages.Warning)
	require.Empty(t, sess.Messages.Error)

	for _, e := range registry.All() {
		if e.DefaultEnabled {
			continue
		}

		if enabled := e.Enabled(*sess); enabled != nil && *enabled {
			t.Errorf("provider %s absent from config is enabled", e.Name)
		}
	}
}
