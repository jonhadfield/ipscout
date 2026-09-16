package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers"

	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/process"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	AppName = "ipscout"
)

var sess *session.Session

var ErrSilent = errors.New("ErrSilent")

//nolint:funlen
func newRootCommand() *cobra.Command {
	var (
		useTestData     bool
		ports           []string
		maxValueChars   int32
		maxAge          string
		maxReports      int
		logLevel        string
		output          string
		style           string
		disableCache    bool
		filterProviders []string
		inputFile       string
	)

	rootCmd := &cobra.Command{
		Use:           "ipscout [options] <host>",
		Short:         "ipscout [command]",
		Long:          `IPScout searches providers for information about hosts`,
		Args:          cobra.MinimumNArgs(0),
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
	}

	cacheCommand := newCacheCommand()
	configCommand := newConfigCommand()
	rateCommand := newRateCommand()

	rootCmd.AddCommand(cacheCommand)
	rootCmd.AddCommand(configCommand)
	rootCmd.AddCommand(rateCommand)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(uiCmd)
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.Println(err)
		cmd.Println(cmd.UsageString())

		return ErrSilent
	})

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		// using test data doesn't require a host be provided
		// but command does so use placeholder
		if useTestData {
			args = []string{"8.8.8.8"}
		}

		hosts, err := collectHosts(cmd, args)
		if err != nil {
			return err
		}

		if len(hosts) == 0 {
			_ = cmd.Help()

			return nil
		}

		for _, host := range hosts {
			if sess.Host, err = helpers.ParseHost(host); err != nil {
				fmt.Fprintf(os.Stderr, "skipping invalid host %q: %s\n", host, err)

				continue
			}

			processor, pErr := process.New(sess)
			if pErr != nil {
				fmt.Fprintf(os.Stderr, "error creating processor for %s: %s\n", host, pErr)

				continue
			}

			if pErr = processor.Run(); pErr != nil {
				fmt.Fprintf(os.Stderr, "error processing %s: %s\n", host, pErr)
			}
		}

		return nil
	}

	// Define cobra flags, the default value has the lowest (least significant) precedence
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARN", "set log level as: ERROR, WARN, INFO, DEBUG")
	rootCmd.PersistentFlags().StringVar(&output, "output", "table", "output format: table, json, csv")
	rootCmd.PersistentFlags().StringVar(&style, "style", "", "output style: ascii, cyan, red, yellow, green, blue")
	rootCmd.PersistentFlags().StringVar(&maxAge, "max-age", "", "max age of data to consider")
	rootCmd.PersistentFlags().IntVar(&maxReports, "max-reports", session.DefaultMaxReports, "max reports to output for each provider")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().BoolVar(&disableCache, "disable-cache", false, "disable cache")
	rootCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "limit ports")
	rootCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")
	rootCmd.PersistentFlags().StringSliceVar(&filterProviders, "filter-providers", nil, "limit to specific providers (comma-separated)")
	rootCmd.PersistentFlags().StringVarP(&inputFile, "file", "f", "", "file containing IPs/hostnames (one per line)")

	return rootCmd
}

// collectHosts gathers hosts from CLI args, --file flag, or stdin.
func collectHosts(cmd *cobra.Command, args []string) ([]string, error) {
	// check --file flag
	filePath, _ := cmd.Flags().GetString("file")
	if filePath != "" {
		return readHostsFromFile(filePath)
	}

	// check stdin (only if no args and stdin is piped)
	if len(args) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			return readHostsFromReader(bufio.NewScanner(os.Stdin))
		}
	}

	return args, nil
}

func readHostsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", path, err)
	}

	defer f.Close()

	return readHostsFromReader(bufio.NewScanner(f))
}

func readHostsFromReader(scanner *bufio.Scanner) ([]string, error) {
	var hosts []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		hosts = append(hosts, line)
	}

	if err := scanner.Err(); err != nil {
		return hosts, fmt.Errorf("error reading hosts: %w", err)
	}

	return hosts, nil
}

func Execute() error {
	// setup session
	rootCmd := newRootCommand()
	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("error: %w", err)
	}

	return nil
}

func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(flg *pflag.Flag) {
		configName := flg.Name
		v.Set(configName, flg.Value)

		if !flg.Changed && v.IsSet(configName) {
			val := v.Get(configName)
			if err := cmd.Flags().Set(flg.Name, fmt.Sprintf("%v", val)); err != nil {
				fmt.Printf("error setting flag %s: %v\n", flg.Name, err)
			}
		}
	})
}

func initHomeDirConfig(sess *session.Session, v *viper.Viper) error {
	var err error

	homeDir := v.GetString("home_dir")
	if homeDir == "" {
		homeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
	}

	// check home directory exists
	_, err = os.Stat(homeDir)
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("home directory %s does not exist: %w", homeDir, err)
	}

	sess.Config.Global.HomeDir = homeDir

	return nil
}

func initSessionConfig(sess *session.Session, v *viper.Viper) error {
	config.InitProviders(sess, v)

	sess.Config.Global.Ports = v.GetStringSlice("global.ports")
	sess.Config.Global.MaxValueChars = v.GetInt32("global.max_value_chars")

	sess.Config.Global.MaxAge = v.GetString("global.max_age")
	sess.Config.Global.MaxReports = v.GetInt("global.max_reports")

	if len(sess.Config.Global.Ports) == 1 && sess.Config.Global.Ports[0] == "[]" {
		sess.Config.Global.Ports = nil
	}

	sess.Config.Global.MaxAge = v.GetString("global.max_age")

	sess.Config.Rating.ConfigPath = session.ExpandHome(v.GetString("rating.config_path"), sess.Config.Global.HomeDir)
	// config files written before these keys were corrected use hyphens, and
	// were silently ignored; fall back to them so existing installs start
	// working, but only when the corrected key is absent, so an explicit
	// value is never overridden by a stale one
	sess.Config.Rating.UseAI = v.GetBool("rating.use_ai")
	if !v.IsSet("rating.use_ai") {
		sess.Config.Rating.UseAI = v.GetBool("rating.use-ai")
	}

	sess.Config.Rating.OpenAIAPIKey = v.GetString("rating.openai_api_key")
	if !v.IsSet("rating.openai_api_key") {
		sess.Config.Rating.OpenAIAPIKey = v.GetString("rating.openai-api-key")
	}

	return nil
}

func initConfig(cmd *cobra.Command) error {
	v := viper.New()

	// create session
	sess = session.New()

	// get home dir to be used for config and cache
	if err := initHomeDirConfig(sess, v); err != nil {
		return err
	}

	configRoot := session.GetConfigRoot("", sess.Config.Global.HomeDir, AppName)
	sess.App.Version = helpers.Version
	sess.App.SemVer = helpers.SemVer

	if _, err := session.CreateDefaultConfigIfMissing(configRoot); err != nil {
		return fmt.Errorf("cannot create default session: %w", err)
	}

	// add any providers introduced since the user's config was written, so
	// their config shows all no-config providers as enabled
	if _, err := registry.EnsureDefaultProvidersInConfig(filepath.Join(configRoot, session.DefaultConfigFileName)); err != nil {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, fmt.Sprintf("unable to add new providers to config: %s", err))
		sess.Messages.Mu.Unlock()
	}

	v.AddConfigPath(configRoot)
	v.SetConfigName("config")

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("cannot read session: %w", err)
	}

	v.AutomaticEnv()

	if err := session.CreateConfigPathStructure(configRoot); err != nil {
		return fmt.Errorf("can't create cache directory: %w", err)
	}

	readProviderAuthKeys(v)

	// set cmd flags to those learned by viper if cmd flag is not set and viper's is
	bindFlags(cmd, v)

	sess.Target = os.Stderr

	if err := initSessionConfig(sess, v); err != nil {
		return err
	}

	// initialise logging
	if err := initLogging(cmd); err != nil {
		return err
	}

	sess.HTTPClient = helpers.GetHTTPClient()

	utd, err := cmd.Flags().GetBool("use-test-data")
	if err != nil {
		return fmt.Errorf("error getting use-test-data: %w", err)
	}

	sess.UseTestData = utd

	if utd {
		if err = ensureTestDataAvailable(); err != nil {
			return err
		}
	}

	ports, _ := cmd.Flags().GetStringSlice("ports")
	if len(ports) == 1 && ports[0] == "[]" {
		ports = nil
	}
	// if no ports specified on cli then default to global ports
	if len(ports) > 0 {
		sess.Config.Global.Ports = ports
	}

	maxAge, _ := cmd.Flags().GetString("max-age")
	if maxAge != "" {
		sess.Config.Global.MaxAge = maxAge
	}

	disableCache, _ := cmd.Flags().GetBool("disable-cache")
	if disableCache {
		sess.Config.Global.DisableCache = disableCache
	}

	output, _ := cmd.Flags().GetString("output")
	if output != "" {
		sess.Config.Global.Output = output
	}

	maxValueChars, _ := cmd.Flags().GetInt32("max-value-chars")
	if maxValueChars > 0 {
		sess.Config.Global.MaxValueChars = maxValueChars
	}

	filterProviders, _ := cmd.Flags().GetStringSlice("filter-providers")
	if len(filterProviders) == 1 && filterProviders[0] == "[]" {
		filterProviders = nil
	}

	if len(filterProviders) > 0 {
		sess.Config.Global.FilterProviders = filterProviders
	}

	sess.Config.Global.IndentSpaces = c.DefaultIndentSpaces

	// default to config global style
	sess.Config.Global.Style = v.GetString("global.style")

	// override with cli flag if set
	outputStyle, _ := cmd.Flags().GetString("style")
	if outputStyle != "" {
		sess.Config.Global.Style = outputStyle
	}

	return nil
}

var ProgramLevel = new(slog.LevelVar) // Info by default

func initLogging(cmd *cobra.Command) error {
	hOptions := slog.HandlerOptions{AddSource: false}

	ll, err := cmd.Flags().GetString("log-level")
	if err != nil {
		return fmt.Errorf("error getting log-level: %w", err)
	}

	sess.Config.Global.LogLevel = ll

	// set log level
	switch strings.ToUpper(ll) {
	case "ERROR":
		ProgramLevel.Set(slog.LevelError)

		sess.HideProgress = false
	case "WARN":
		ProgramLevel.Set(slog.LevelWarn)

		sess.HideProgress = false
	case "INFO":
		ProgramLevel.Set(slog.LevelInfo)

		sess.HideProgress = true
	case "DEBUG":
		ProgramLevel.Set(slog.LevelDebug)

		sess.HideProgress = true
	}

	hOptions.Level = ProgramLevel

	sess.Logger = slog.New(slog.NewTextHandler(sess.Target, &hOptions))

	return nil
}

func setProviderAPIKey(v *viper.Viper, envKey string, apiKey *string, enabled **bool) {
	if *apiKey == "" {
		*apiKey = v.GetString(envKey)
	}

	if *apiKey == "" {
		*enabled = config.ToPtr(false)
	}
}

func readProviderAuthKeys(v *viper.Viper) {
	// read provider auth keys from env if not set in session
	setProviderAPIKey(v, "abuseipdb_api_key", &sess.Providers.AbuseIPDB.APIKey, &sess.Providers.AbuseIPDB.Enabled)
	setProviderAPIKey(v, "criminal_ip_api_key", &sess.Providers.CriminalIP.APIKey, &sess.Providers.CriminalIP.Enabled)
	setProviderAPIKey(v, "ipqs_api_key", &sess.Providers.IPQS.APIKey, &sess.Providers.IPQS.Enabled)
	setProviderAPIKey(v, "shodan_api_key", &sess.Providers.Shodan.APIKey, &sess.Providers.Shodan.Enabled)
	setProviderAPIKey(v, "virustotal_api_key", &sess.Providers.VirusTotal.APIKey, &sess.Providers.VirusTotal.Enabled)
}

// ensureTestDataAvailable makes the providers' test data reachable on disk.
//
// The providers resolve their test data relative to the directory containing
// go.mod, which only exists when running from a source checkout. For an
// installed binary there is no such directory, so extract the copy embedded in
// the binary to the user's cache and point the providers at that instead.
func ensureTestDataAvailable() error {
	if _, err := helpers.FindProjectRoot(); err == nil {
		return nil
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("error locating user cache directory for test data: %w", err)
	}

	root := filepath.Join(cacheDir, "ipscout", "testdata-"+helpers.SemVer)

	if err = providers.ExtractTestData(root); err != nil {
		return fmt.Errorf("error extracting embedded test data: %w", err)
	}

	helpers.SetProjectRoot(root)

	return nil
}
