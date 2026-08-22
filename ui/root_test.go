package ui

import (
	"strings"
	"testing"

	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
)

// TestInitProviderConfigCoversRegistry guards against the TUI's provider
// config wiring drifting from the registry: a provider whose enabled key is
// never read leaves its Enabled pointer nil, which the provider reads as
// disabled and the TUI reports as "Provider not configured".
func TestInitProviderConfigCoversRegistry(t *testing.T) {
	t.Parallel()

	s := session.New()
	v := viper.New()

	for _, e := range registry.All() {
		v.Set("providers."+strings.ToLower(e.Name)+".enabled", true)
	}

	initProviderConfig(s, v)

	for _, e := range registry.All() {
		enabled := e.Enabled(*s)
		if enabled == nil {
			t.Errorf("provider %q enabled config not read by initProviderConfig", e.Name)

			continue
		}

		if !*enabled {
			t.Errorf("provider %q enabled = false, want true", e.Name)
		}
	}
}

// TestInitProviderConfigSetsDefaultPriorities checks that providers absent
// from config still get their default output priority, as the display order
// relies on it.
func TestInitProviderConfigSetsDefaultPriorities(t *testing.T) {
	t.Parallel()

	s := session.New()
	v := viper.New()

	initProviderConfig(s, v)

	if s.Providers.Atlassian.OutputPriority == nil {
		t.Fatal("atlassian output priority not set")
	}

	if s.Providers.Alibaba.OutputPriority == nil {
		t.Fatal("alibaba output priority not set")
	}

	if got := *s.Providers.Alibaba.OutputPriority; got != defaultAlibabaOutputPriority {
		t.Errorf("alibaba output priority = %d, want %d", got, defaultAlibabaOutputPriority)
	}
}
