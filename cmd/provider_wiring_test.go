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
