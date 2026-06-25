package registry

import (
	"testing"

	"github.com/jonhadfield/ipscout/session"
)

// expectedProviderCount is the number of provider entries currently registered
// in All(). Update this constant if providers are added or removed.
const expectedProviderCount = 27

func TestAllReturnsEntries(t *testing.T) {
	t.Parallel()

	entries := All()

	if len(entries) == 0 {
		t.Fatal("All() returned no entries")
	}

	if len(entries) != expectedProviderCount {
		t.Errorf("All() returned %d entries, want %d", len(entries), expectedProviderCount)
	}
}

func TestAllContainsKnownProviders(t *testing.T) {
	t.Parallel()

	names := make(map[string]bool)
	for _, e := range All() {
		names[e.Name] = true
	}

	known := []string{
		"shodan",
		"aws",
		"abuseipdb",
		"azure",
		"gcp",
		"virustotal",
		"ptr",
		"annotated",
	}

	for _, n := range known {
		if !names[n] {
			t.Errorf("All() missing expected provider %q", n)
		}
	}
}

func TestAllEntryFieldsPopulated(t *testing.T) {
	t.Parallel()

	for _, e := range All() {
		if e.Name == "" {
			t.Error("found entry with empty Name")
		}

		if e.Enabled == nil {
			t.Errorf("entry %q has nil Enabled func", e.Name)
		}

		if e.APIKey == nil {
			t.Errorf("entry %q has nil APIKey func", e.Name)
		}

		if e.NewClient == nil {
			t.Errorf("entry %q has nil NewClient func", e.Name)
		}
	}
}

func TestAllNamesUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)

	for _, e := range All() {
		if seen[e.Name] {
			t.Errorf("duplicate provider name %q in All()", e.Name)
		}

		seen[e.Name] = true
	}
}

func TestEntryEnabledAccessor(t *testing.T) {
	t.Parallel()

	// A zero-value session has all Enabled pointers nil, so each Enabled
	// accessor should run without panicking and return nil.
	var sess session.Session

	for _, e := range All() {
		if got := e.Enabled(sess); got != nil {
			t.Errorf("entry %q Enabled() on zero session = %v, want nil", e.Name, got)
		}
	}
}

func TestEntryAPIKeyAccessor(t *testing.T) {
	t.Parallel()

	// A zero-value session has empty API keys, so every APIKey accessor
	// (both the real getters and the noKey helper) should return "".
	var sess session.Session

	for _, e := range All() {
		if got := e.APIKey(sess); got != "" {
			t.Errorf("entry %q APIKey() on zero session = %q, want empty", e.Name, got)
		}
	}
}

func TestSupportsRatingFlags(t *testing.T) {
	t.Parallel()

	want := map[string]bool{
		"shodan":     true,
		"abuseipdb":  true,
		"azurewaf":   false,
		"scaleway":   false,
		"vultr":      false,
		"ptr":        false,
		"M247":       false,
		"googlesc":   false,
		"aws":        true,
		"virustotal": true,
	}

	got := make(map[string]bool)
	for _, e := range All() {
		got[e.Name] = e.SupportsRating
	}

	for name, expected := range want {
		actual, ok := got[name]
		if !ok {
			t.Errorf("provider %q not found in All()", name)

			continue
		}

		if actual != expected {
			t.Errorf("provider %q SupportsRating = %v, want %v", name, actual, expected)
		}
	}
}

func TestNoKeyHelper(t *testing.T) {
	t.Parallel()

	var sess session.Session

	if got := noKey(sess); got != "" {
		t.Errorf("noKey() = %q, want empty string", got)
	}
}
