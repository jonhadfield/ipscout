package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/providers/virustotal"
	"github.com/jonhadfield/ipscout/session"
	"gopkg.in/yaml.v3"
)

// expectedProviderCount is the number of provider entries currently registered
// in All(). Update this constant if providers are added or removed.
const expectedProviderCount = 88

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
		"alibaba":    true,
		"scaleway":   true,
		"vultr":      true,
		"ptr":        false,
		"M247":       true,
		"googlesc":   true,
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

// TestEveryEntryHasDisplayName guards the registry-driven `ipscout config`
// output: a provider without a DisplayName would render with a blank header,
// so every entry must supply one. This is the guardrail that prevents
// providers from being silently omitted from the config display.
func TestEveryEntryHasDisplayName(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)

	for _, e := range All() {
		if e.DisplayName == "" {
			t.Errorf("provider %q has an empty DisplayName", e.Name)
		}

		if seen[e.DisplayName] {
			t.Errorf("duplicate DisplayName %q", e.DisplayName)
		}

		seen[e.DisplayName] = true
	}
}

func TestNoKeyHelper(t *testing.T) {
	t.Parallel()

	var sess session.Session

	if got := noKey(sess); got != "" {
		t.Errorf("noKey() = %q, want empty string", got)
	}
}

// configProviders reads the providers section of a config file into a map of
// provider name to its settings.
func configProviders(t *testing.T) map[string]map[string]any {
	t.Helper()

	data, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	var conf struct {
		Providers map[string]map[string]any `yaml:"providers"`
	}

	if err := yaml.Unmarshal(data, &conf); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	return conf.Providers
}

func TestEnsureDefaultProvidersInConfigAddsMissing(t *testing.T) {
	// t.Chdir is incompatible with t.Parallel; the literal config path keeps
	// the Codacy fileread rule satisfied
	t.Chdir(t.TempDir())

	// an aged config: a comment, one no-config provider explicitly disabled,
	// one enabled, and none of the newer providers
	content := `---
global:
  max_age: 90d

providers:
  # aws disabled on purpose
  aws:
    enabled: false
  azure:
    enabled: true
  shodan:
    enabled: true
`

	if err := os.WriteFile("config.yaml", []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	changed, err := EnsureDefaultProvidersInConfig("config.yaml")
	if err != nil {
		t.Fatalf("EnsureDefaultProvidersInConfig() error: %v", err)
	}

	if !changed {
		t.Fatal("EnsureDefaultProvidersInConfig() = false, want true")
	}

	provs := configProviders(t)

	for _, e := range All() {
		if !e.DefaultEnabled || e.Name == aws.ProviderName || e.Name == "azure" {
			continue
		}

		p, ok := provs[strings.ToLower(e.Name)]
		if !ok {
			t.Errorf("provider %q not added to config", e.Name)

			continue
		}

		if enabled, _ := p["enabled"].(bool); !enabled {
			t.Errorf("provider %q added with enabled=%v, want true", e.Name, p["enabled"])
		}
	}

	// explicit user setting must be preserved
	if enabled, _ := provs[aws.ProviderName]["enabled"].(bool); enabled {
		t.Error("aws enabled=false was not preserved")
	}

	// keyed providers must not be added beyond those already present
	if _, ok := provs["abuseipdb"]; ok {
		t.Error("keyed provider abuseipdb should not be added")
	}

	// comments must survive the rewrite
	raw, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	if !strings.Contains(string(raw), "# aws disabled on purpose") {
		t.Error("comment was not preserved in rewritten config")
	}

	// a second run must be a no-op
	changed, err = EnsureDefaultProvidersInConfig("config.yaml")
	if err != nil {
		t.Fatalf("EnsureDefaultProvidersInConfig() second run error: %v", err)
	}

	if changed {
		t.Error("EnsureDefaultProvidersInConfig() second run = true, want false")
	}
}

// TestEnsureDefaultProvidersInConfigDefaultConfigComplete guards that the
// shipped default config already lists every no-config provider, so a fresh
// install's config is never rewritten on first run.
func TestEnsureDefaultProvidersInConfigDefaultConfigComplete(t *testing.T) {
	// t.Chdir is incompatible with t.Parallel; the literal config path keeps
	// the Codacy fileread rule satisfied
	t.Chdir(t.TempDir())

	if err := os.WriteFile("config.yaml", []byte(session.DefaultConfig), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	changed, err := EnsureDefaultProvidersInConfig("config.yaml")
	if err != nil {
		t.Fatalf("EnsureDefaultProvidersInConfig() error: %v", err)
	}

	if changed {
		t.Error("default config is missing no-config providers; update session/config.yaml")
	}

	raw, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	if string(raw) != session.DefaultConfig {
		t.Error("default config was rewritten despite no changes")
	}
}

func TestEnsureDefaultProvidersInConfigEmptyProviders(t *testing.T) {
	// t.Chdir is incompatible with t.Parallel; the literal config path keeps
	// the Codacy fileread rule satisfied
	t.Chdir(t.TempDir())

	if err := os.WriteFile("config.yaml", []byte("providers:\n"), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	changed, err := EnsureDefaultProvidersInConfig("config.yaml")
	if err != nil {
		t.Fatalf("EnsureDefaultProvidersInConfig() error: %v", err)
	}

	if !changed {
		t.Fatal("EnsureDefaultProvidersInConfig() = false, want true")
	}

	provs := configProviders(t)

	for _, e := range All() {
		if !e.DefaultEnabled {
			continue
		}

		if _, ok := provs[strings.ToLower(e.Name)]; !ok {
			t.Errorf("provider %q not added to empty providers section", e.Name)
		}
	}
}

func TestEnsureDefaultProvidersInConfigMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := EnsureDefaultProvidersInConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("EnsureDefaultProvidersInConfig() on missing file: expected error")
	}
}

func TestDisableKeylessProvidersInConfig(t *testing.T) {
	// t.Chdir is incompatible with t.Parallel; the literal config path keeps
	// the Codacy fileread rule satisfied
	t.Chdir(t.TempDir())

	// an aged config: keyed providers enabled with and without keys, one
	// already disabled, and no config_version
	content := `---
global:
  max_age: 90d

providers:
  # shodan key comes from the environment
  shodan:
    enabled: true
  ipqs:
    enabled: true
    api_key: from-config
  abuseipdb:
    enabled: true
  virustotal:
    enabled: false
  aws:
    enabled: true
`

	if err := os.WriteFile("config.yaml", []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	getenv := func(key string) string {
		if key == "SHODAN_API_KEY" {
			return "from-env"
		}

		return ""
	}

	disabled, err := DisableKeylessProvidersInConfig("config.yaml", getenv)
	if err != nil {
		t.Fatalf("DisableKeylessProvidersInConfig() error: %v", err)
	}

	if len(disabled) != 1 || disabled[0] != "AbuseIPDB" {
		t.Errorf("disabled = %v, want [AbuseIPDB]", disabled)
	}

	provs := configProviders(t)

	for name, want := range map[string]bool{shodan.ProviderName: true, "ipqs": true, abuseipdb.ProviderName: false, virustotal.ProviderName: false, aws.ProviderName: true} {
		if got, _ := provs[name]["enabled"].(bool); got != want {
			t.Errorf("%s enabled = %v, want %v", name, got, want)
		}
	}

	raw, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	if !strings.Contains(string(raw), "config_version: 1") {
		t.Error("config_version was not recorded")
	}

	if !strings.Contains(string(raw), "# shodan key comes from the environment") {
		t.Error("comment was not preserved in rewritten config")
	}

	// once migrated, a keyed provider the user enables without a key is
	// left alone so it can be reported instead
	reenabled := strings.Replace(string(raw), "abuseipdb:\n    enabled: false", "abuseipdb:\n    enabled: true", 1)

	if err = os.WriteFile("config.yaml", []byte(reenabled), 0o600); err != nil { //nolint:gosec // fixed file name in a temp dir
		t.Fatalf("failed to write config: %v", err)
	}

	disabled, err = DisableKeylessProvidersInConfig("config.yaml", getenv)
	if err != nil {
		t.Fatalf("DisableKeylessProvidersInConfig() second run error: %v", err)
	}

	if len(disabled) != 0 {
		t.Errorf("second run disabled %v, want none", disabled)
	}

	if enabled, _ := configProviders(t)[abuseipdb.ProviderName]["enabled"].(bool); !enabled {
		t.Error("second run changed a migrated config")
	}
}

func TestDisableKeylessProvidersInConfigMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := DisableKeylessProvidersInConfig(filepath.Join(t.TempDir(), "missing.yaml"), os.Getenv); err == nil {
		t.Error("DisableKeylessProvidersInConfig() on missing file: expected error")
	}
}

// TestDefaultConfigNeedsNoMigration guards that the shipped default config is
// already at ConfigVersion, so new users are not shown a migration notice.
func TestDefaultConfigNeedsNoMigration(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := os.WriteFile("config.yaml", []byte(session.DefaultConfig), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	disabled, err := DisableKeylessProvidersInConfig("config.yaml", func(string) string { return "" })
	if err != nil {
		t.Fatalf("DisableKeylessProvidersInConfig() error: %v", err)
	}

	if len(disabled) != 0 {
		t.Errorf("default config migration disabled %v, want none", disabled)
	}
}

func TestEnabledWithoutKeyAndUnconfigured(t *testing.T) {
	t.Parallel()

	var sess session.Session

	enabled := true
	sess.Providers.Shodan.Enabled = &enabled
	sess.Providers.IPQS.Enabled = &enabled
	sess.Providers.IPQS.APIKey = "key"

	missing := EnabledWithoutKey(sess)
	if len(missing) != 1 || missing[0].Name != shodan.ProviderName {
		t.Errorf("EnabledWithoutKey() = %v, want only shodan", missing)
	}

	var keyed int

	for _, e := range All() {
		if e.KeyEnv == "" {
			continue
		}

		keyed++

		if e.SignupURL == "" {
			t.Errorf("keyed provider %s has no SignupURL", e.Name)
		}
	}

	// every keyed provider but the configured IPQS
	if got := len(Unconfigured(sess)); got != keyed-1 {
		t.Errorf("Unconfigured() returned %d providers, want %d", got, keyed-1)
	}
}

func TestLookupAndAPIKeyRejectedMessage(t *testing.T) {
	t.Parallel()

	e, ok := Lookup(shodan.ProviderName)
	if !ok || e.DisplayName != "Shodan" {
		t.Fatalf("Lookup(shodan) = %v, %v", e, ok)
	}

	if _, ok = Lookup("nope"); ok {
		t.Error("Lookup(nope) found an entry")
	}

	if got, want := APIKeyRejectedMessage(shodan.ProviderName), "Shodan rejected the API key: check SHODAN_API_KEY is set to a valid key"; got != want {
		t.Errorf("APIKeyRejectedMessage(shodan) = %q, want %q", got, want)
	}

	if got, want := APIKeyRejectedMessage("nope"), "nope rejected the API key"; got != want {
		t.Errorf("APIKeyRejectedMessage(nope) = %q, want %q", got, want)
	}
}
