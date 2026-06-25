package cmd

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOutputPriority int32 = 99
	testCacheTTL       int64 = 1234
)

const (
	cmdConfig  = "config"
	cmdGet     = "get"
	cmdDefault = "default"
	cmdRate    = "rate"
	cmdVersion = "Version"
	hostA      = "1.1.1.1"
	hostB      = "8.8.8.8"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
}

func TestToPtr(t *testing.T) {
	t.Parallel()

	v := 42
	p := ToPtr(v)
	require.NotNil(t, p)
	assert.Equal(t, v, *p)

	s := ToPtr("hello")
	require.NotNil(t, s)
	assert.Equal(t, "hello", *s)

	b := ToPtr(true)
	require.NotNil(t, b)
	assert.True(t, *b)
}

func TestNewRootCommand(t *testing.T) {
	t.Parallel()

	rootCmd := newRootCommand()
	require.NotNil(t, rootCmd)
	assert.Equal(t, "ipscout [options] <host>", rootCmd.Use)
	assert.True(t, rootCmd.SilenceErrors)
	assert.True(t, rootCmd.SilenceUsage)

	wantSubcommands := []string{"cache", cmdConfig, cmdRate, cmdVersion, "ui"}
	for _, name := range wantSubcommands {
		_, _, err := rootCmd.Find([]string{name})
		require.NoErrorf(t, err, "expected subcommand %q", name)
	}

	wantFlags := []string{
		"log-level", "output", "style", "max-age", "max-reports",
		"use-test-data", "disable-cache", "ports", "max-value-chars",
		"filter-providers", "file",
	}
	for _, name := range wantFlags {
		assert.NotNilf(t, rootCmd.PersistentFlags().Lookup(name), "expected persistent flag %q", name)
	}
}

func TestNewCacheCommand(t *testing.T) {
	t.Parallel()

	cacheCmd := newCacheCommand()
	require.NotNil(t, cacheCmd)
	assert.Equal(t, "cache", cacheCmd.Use)

	wantSub := []string{"list", "init", cmdGet, "delete"}
	for _, name := range wantSub {
		_, _, err := cacheCmd.Find([]string{name})
		require.NoErrorf(t, err, "expected cache subcommand %q", name)
	}

	getCmd, _, err := cacheCmd.Find([]string{cmdGet})
	require.NoError(t, err)
	assert.NotNil(t, getCmd.PersistentFlags().Lookup("raw"))
}

func TestNewConfigCommand(t *testing.T) {
	t.Parallel()

	configCmd := newConfigCommand()
	require.NotNil(t, configCmd)
	assert.Equal(t, cmdConfig, configCmd.Use)

	for _, name := range []string{"show", cmdDefault} {
		_, _, err := configCmd.Find([]string{name})
		require.NoErrorf(t, err, "expected config subcommand %q", name)
	}
}

func TestNewRateCommand(t *testing.T) {
	t.Parallel()

	rateCmd := newRateCommand()
	require.NotNil(t, rateCmd)
	assert.Equal(t, cmdRate, rateCmd.Use)
	assert.NotNil(t, rateCmd.PersistentFlags().Lookup("ai"))
	assert.NotNil(t, rateCmd.PersistentFlags().Lookup("openai-api-key"))

	cfgCmd, _, err := rateCmd.Find([]string{cmdConfig})
	require.NoError(t, err)
	assert.NotNil(t, cfgCmd.Flags().Lookup(cmdDefault))
	assert.NotNil(t, cfgCmd.Flags().Lookup("path"))
}

func TestVersionCmd(t *testing.T) {
	t.Parallel()

	assert.Equal(t, cmdVersion, versionCmd.Use)

	var buf bytes.Buffer

	versionCmd.SetOut(&buf)
	versionCmd.SetErr(&buf)
	versionCmd.Run(versionCmd, nil)
	// version output goes to stdout via fmt.Println; ensure the command does not panic
	assert.NotNil(t, versionCmd.Run)
}

func TestUICmd(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "ui", uiCmd.Use)
	assert.NotNil(t, uiCmd.Run)
}

func TestReadHostsFromReader(t *testing.T) {
	t.Parallel()

	input := hostA + "\n\n# comment\n  " + hostB + "  \nexample.com\n"
	scanner := bufio.NewScanner(strings.NewReader(input))

	hosts, err := readHostsFromReader(scanner)
	require.NoError(t, err)
	assert.Equal(t, []string{hostA, hostB, "example.com"}, hosts)
}

func TestReadHostsFromReaderEmpty(t *testing.T) {
	t.Parallel()

	scanner := bufio.NewScanner(strings.NewReader("\n#only comments\n"))

	hosts, err := readHostsFromReader(scanner)
	require.NoError(t, err)
	assert.Empty(t, hosts)
}

func TestReadHostsFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	require.NoError(t, os.WriteFile(path, []byte("9.9.9.9\n# skip\n1.0.0.1\n"), 0o600))

	hosts, err := readHostsFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"9.9.9.9", "1.0.0.1"}, hosts)
}

func TestReadHostsFromFileMissing(t *testing.T) {
	t.Parallel()

	_, err := readHostsFromFile(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	require.Error(t, err)
}

func TestCollectHostsFromArgs(t *testing.T) {
	t.Parallel()

	cmd := newRootCommand()

	hosts, err := collectHosts(cmd, []string{hostA, hostB})
	require.NoError(t, err)
	assert.Equal(t, []string{hostA, hostB}, hosts)
}

func TestCollectHostsFromFileFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	require.NoError(t, os.WriteFile(path, []byte("2.2.2.2\n3.3.3.3\n"), 0o600))

	cmd := newRootCommand()
	// merge persistent flags into the local flag set that collectHosts reads.
	cmd.InheritedFlags()
	require.NoError(t, cmd.Flags().Set("file", path))

	hosts, err := collectHosts(cmd, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"2.2.2.2", "3.3.3.3"}, hosts)
}

func TestAddProviderConfigMessage(t *testing.T) {
	t.Parallel()

	s := session.New()
	addProviderConfigMessage(s, "TestProvider")
	require.Len(t, s.Messages.Info, 1)
	assert.Contains(t, s.Messages.Info[0], "TestProvider")
}

func TestSetProviderAPIKey(t *testing.T) {
	t.Parallel()

	t.Run("key from viper enables", func(t *testing.T) {
		t.Parallel()

		v := viper.New()
		v.Set("test_api_key", "secret")

		apiKey := ""
		enabled := ToPtr(true)
		setProviderAPIKey(v, "test_api_key", &apiKey, &enabled)
		assert.Equal(t, "secret", apiKey)
		require.NotNil(t, enabled)
		assert.True(t, *enabled)
	})

	t.Run("missing key disables", func(t *testing.T) {
		t.Parallel()

		v := viper.New()

		apiKey := ""
		enabled := ToPtr(true)
		setProviderAPIKey(v, "absent_api_key", &apiKey, &enabled)
		assert.Empty(t, apiKey)
		require.NotNil(t, enabled)
		assert.False(t, *enabled)
	})
}

func TestBindFlags(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}

	var value string

	cmd.Flags().StringVar(&value, "output", "table", "output")

	v := viper.New()
	// bindFlags overwrites viper with the current (unchanged) flag value, so it is
	// effectively a no-op for unchanged flags. Verify it runs without panicking and
	// leaves the flag at its default.
	bindFlags(cmd, v)

	got, err := cmd.Flags().GetString("output")
	require.NoError(t, err)
	assert.Equal(t, "table", got)

	// when a flag is explicitly changed, bindFlags must not clobber it.
	require.NoError(t, cmd.Flags().Set("output", "csv"))
	bindFlags(cmd, v)

	got, err = cmd.Flags().GetString("output")
	require.NoError(t, err)
	assert.Equal(t, "csv", got)
}

func TestInitProviderConfig(t *testing.T) {
	t.Parallel()

	s := session.New()
	v := viper.New()

	v.Set("providers.abuseipdb.enabled", true)
	v.Set("providers.abuseipdb.output_priority", int(testOutputPriority))
	v.Set("providers.shodan.result_cache_ttl", int(testCacheTTL))

	initProviderConfig(s, v)

	require.NotNil(t, s.Providers.AbuseIPDB.Enabled)
	assert.True(t, *s.Providers.AbuseIPDB.Enabled)
	require.NotNil(t, s.Providers.AbuseIPDB.OutputPriority)
	assert.Equal(t, testOutputPriority, *s.Providers.AbuseIPDB.OutputPriority)
	assert.Equal(t, testCacheTTL, s.Providers.Shodan.ResultCacheTTL)

	// providers not set should fall back to default priority and emit info messages
	require.NotNil(t, s.Providers.Alibaba.OutputPriority)
	assert.Equal(t, int32(defaultAlibabaOutputPriority), *s.Providers.Alibaba.OutputPriority)
	assert.NotEmpty(t, s.Messages.Info)
}

func TestInitSessionConfig(t *testing.T) {
	t.Parallel()

	s := session.New()
	v := viper.New()

	v.Set("global.max_age", "30d")
	v.Set("global.max_reports", session.DefaultMaxReports)
	v.Set("rating.use_ai", true)
	v.Set("rating.openai_api_key", "key")

	require.NoError(t, initSessionConfig(s, v))
	assert.Equal(t, "30d", s.Config.Global.MaxAge)
	assert.Equal(t, session.DefaultMaxReports, s.Config.Global.MaxReports)
	assert.True(t, s.Config.Rating.UseAI)
	assert.Equal(t, "key", s.Config.Rating.OpenAIAPIKey)
}

func TestInitSessionConfigPortsSentinel(t *testing.T) {
	t.Parallel()

	s := session.New()
	v := viper.New()
	v.Set("global.ports", []string{"[]"})

	require.NoError(t, initSessionConfig(s, v))
	assert.Nil(t, s.Config.Global.Ports)
}

func TestInitHomeDirConfigFromViper(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	s := session.New()
	v := viper.New()
	v.Set("home_dir", dir)

	require.NoError(t, initHomeDirConfig(s, v))
	assert.Equal(t, dir, s.Config.Global.HomeDir)
}

func TestInitHomeDirConfigMissing(t *testing.T) {
	t.Parallel()

	s := session.New()
	v := viper.New()
	v.Set("home_dir", filepath.Join(t.TempDir(), "missing-subdir"))

	err := initHomeDirConfig(s, v)
	require.Error(t, err)
}

func TestInitLogging(t *testing.T) {
	t.Parallel()

	levels := map[string]bool{
		"ERROR": false,
		"WARN":  false,
		"INFO":  true,
		"DEBUG": true,
	}

	for level, hideProgress := range levels {
		s := session.New()
		s.Target = os.Stderr

		// initLogging reads the package-level sess via assignment of fields on the passed session
		// Build a command carrying the log-level flag.
		cmd := &cobra.Command{Use: "test"}

		var ll string

		cmd.Flags().StringVar(&ll, "log-level", level, "log level")

		// initLogging operates on the package level sess variable.
		sess = s

		require.NoError(t, initLogging(cmd))
		assert.Equal(t, level, sess.Config.Global.LogLevel)
		assert.Equal(t, hideProgress, sess.HideProgress)
		require.NotNil(t, sess.Logger)
	}
}

// withSandboxHome points HOME at a temp dir so initConfig never touches the
// real user config and never hits the network.
func withSandboxHome(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // windows
}

func TestInitConfigSandboxed(t *testing.T) {
	withSandboxHome(t)

	cmd := newRootCommand()
	// ParseFlags merges the persistent flag set into cmd.Flags(), which initConfig reads.
	require.NoError(t, cmd.ParseFlags(nil))
	require.NoError(t, initConfig(cmd))
	require.NotNil(t, sess)
	require.NotNil(t, sess.Logger)
	assert.Equal(t, c.DefaultIndentSpaces, sess.Config.Global.IndentSpaces)

	// default config should have been written under the sandbox home
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	cfgPath := filepath.Join(home, ".config", AppName, "config.yaml")
	_, statErr := os.Stat(cfgPath)
	require.NoError(t, statErr)
}

func TestConfigDefaultCommandOffline(t *testing.T) {
	withSandboxHome(t)

	rootCmd := newRootCommand()

	var out bytes.Buffer

	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{cmdConfig, cmdDefault})

	require.NoError(t, rootCmd.Execute())
}

func TestRateConfigCommandResolves(t *testing.T) {
	t.Parallel()

	// The `rate config` RunE calls os.Exit() on every branch, so it cannot be
	// executed in-process. Verify the command resolves and its flags are wired.
	rootCmd := newRootCommand()

	cfgCmd, _, err := rootCmd.Find([]string{cmdRate, cmdConfig})
	require.NoError(t, err)
	assert.NotNil(t, cfgCmd.Flags().Lookup(cmdDefault))
	assert.NotNil(t, cfgCmd.Flags().Lookup("path"))
}

func TestRootHelpOffline(t *testing.T) {
	withSandboxHome(t)

	rootCmd := newRootCommand()

	var out bytes.Buffer

	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"--help"})

	require.NoError(t, rootCmd.Execute())
	assert.Contains(t, out.String(), "IPScout")
}

func TestFlagErrorFunc(t *testing.T) {
	withSandboxHome(t)

	rootCmd := newRootCommand()

	var out bytes.Buffer

	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"--nonexistent-flag"})

	err := rootCmd.Execute()
	require.Error(t, err)
}

func TestExecuteVersionOffline(t *testing.T) {
	// Execute() reads the real os.Args and builds its own root command. Drive it
	// through the Version subcommand, which only prints and performs no network I/O.
	withSandboxHome(t)

	origArgs := os.Args

	t.Cleanup(func() { os.Args = origArgs })

	os.Args = []string{AppName, cmdVersion}

	require.NoError(t, Execute())
}

func TestVisitAllPersistentFlags(t *testing.T) {
	t.Parallel()

	rootCmd := newRootCommand()

	count := 0

	rootCmd.PersistentFlags().VisitAll(func(_ *pflag.Flag) {
		count++
	})
	assert.Positive(t, count)
}

func TestDiscardLoggerHelper(t *testing.T) {
	t.Parallel()

	require.NotNil(t, discardLogger())
}
