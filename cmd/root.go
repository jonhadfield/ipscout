package cmd

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/process"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	AppName = "ipscout"
)

var conf *config.Config

func newRootCommand() *cobra.Command {
	var (
		useTestData   bool
		ports         []string
		maxValueChars int32
		maxAge        string
		maxReports    int
		logLevel      string
		disableCache  bool
	)

	rootCmd := &cobra.Command{
		Use:   "ipscout",
		Short: "ipscout",
		Long:  `IPScout is a CLI application to prod to an IP address.`,
		Args:  cobra.MinimumNArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}

			var err error

			if conf.Host, err = netip.ParseAddr(args[0]); err != nil {
				return fmt.Errorf("invalid host: %w", err)
			}

			processor, err := process.New(conf)
			if err != nil {
				os.Exit(1)
			}
			processor.Run()

			return nil
		},
	}

	// Define cobra flags, the default value has the lowest (least significant) precedence
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARN", "set log level as: ERROR, WARN, INFO, DEBUG")
	rootCmd.PersistentFlags().StringVar(&maxAge, "max-age", "", "max age of data to consider")
	rootCmd.PersistentFlags().IntVar(&maxReports, "max-reports", config.DefaultMaxReports, "max reports to output for each provider")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().BoolVar(&disableCache, "disable-cache", false, "disable cache")
	rootCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "limit ports")
	rootCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")

	cacheCommand := newCacheCommand()

	rootCmd.AddCommand(cacheCommand)
	rootCmd.AddCommand(versionCmd)

	return rootCmd
}

func Execute() {
	// setup config
	rootCmd := newRootCommand()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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

func initConfig(cmd *cobra.Command) error {
	v := viper.New()

	conf = config.New()
	configRoot := config.GetConfigRoot("", AppName)
	conf.App.Version = version
	conf.App.SemVer = semver
	if err := config.CreateDefaultConfigIfMissing(configRoot); err != nil {
		fmt.Printf("can't create default config: %v\n", err)

		os.Exit(1)
	}

	v.AddConfigPath(configRoot)
	v.SetConfigName("config")

	if err := v.ReadInConfig(); err != nil {
		fmt.Println("can't read config:", err)
		os.Exit(1)
	}

	v.AutomaticEnv()

	if err := config.CreateConfigPathStructure(configRoot); err != nil {
		fmt.Printf("can't create cache directory: %v\n", err)

		os.Exit(1)
	}

	readProviderAuthKeys(v)

	// set cmd flags to those learned by viper if cmd flag is not set and viper's is
	bindFlags(cmd, v)

	conf.Output = os.Stdout

	conf.Providers.AbuseIPDB.Enabled = v.GetBool("providers.abuseipdb.enabled")
	conf.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	conf.Providers.Annotated.Enabled = v.GetBool("providers.annotated.enabled")
	conf.Providers.Annotated.Paths = v.GetStringSlice("providers.annotated.paths")
	conf.Providers.AWS.Enabled = v.GetBool("providers.aws.enabled")
	conf.Providers.AWS.URL = v.GetString("providers.aws.url")
	conf.Providers.Azure.Enabled = v.GetBool("providers.azure.enabled")
	conf.Providers.Azure.URL = v.GetString("providers.azure.url")
	conf.Providers.CriminalIP.Enabled = v.GetBool("providers.criminalip.enabled")
	conf.Providers.DigitalOcean.Enabled = v.GetBool("providers.digitalocean.enabled")
	conf.Providers.DigitalOcean.URL = v.GetString("providers.digitalocean.url")
	conf.Providers.IPURL.Enabled = v.GetBool("providers.ipurl.enabled")
	conf.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	conf.Providers.Shodan.Enabled = v.GetBool("providers.shodan.enabled")
	conf.Providers.PTR.Enabled = v.GetBool("providers.ptr.enabled")
	conf.Global.Ports = v.GetStringSlice("global.ports")
	conf.Global.MaxValueChars = v.GetInt32("global.max_value_chars")
	conf.Global.MaxAge = v.GetString("global.max_age")
	conf.Global.MaxReports = v.GetInt("global.max_reports")
	// TODO: Nasty Hack Alert
	// if not specified, ports is returned as a string: "[]"
	// set to nil if that's the case
	if len(conf.Global.Ports) == 0 || conf.Global.Ports[0] == "[]" {
		conf.Global.Ports = nil
	}

	conf.Global.MaxAge = v.GetString("global.max_age")

	// initialise logging
	initLogging(cmd)

	conf.HttpClient = getHTTPClient()

	utd, err := cmd.Flags().GetBool("use-test-data")
	if err != nil {
		fmt.Println("error getting use-test-data value:", err)
		os.Exit(1)
	}

	conf.UseTestData = utd

	ports, _ := cmd.Flags().GetStringSlice("ports")
	// TODO: Nasty Hack Alert
	// if not specified, ports is returned as a string: "[]"
	// set to nil if that's the case
	if len(ports) == 0 || ports[0] == "[]" {
		ports = nil
	}
	// if no ports specified on cli then default to global ports
	if len(ports) > 0 {
		conf.Global.Ports = ports
	}

	maxAge, _ := cmd.Flags().GetString("max-age")
	if maxAge != "" {
		conf.Global.MaxAge = maxAge
	}

	disableCache, _ := cmd.Flags().GetBool("disable-cache")
	if disableCache {
		conf.Global.DisableCache = disableCache
	}

	maxValueChars, _ := cmd.Flags().GetInt32("max-value-chars")
	if maxValueChars > 0 {
		conf.Global.MaxValueChars = maxValueChars
	}

	conf.Global.IndentSpaces = config.DefaultIndentSpaces

	return nil
}

var ProgramLevel = new(slog.LevelVar) // Info by default

func initLogging(cmd *cobra.Command) {
	hOptions := slog.HandlerOptions{AddSource: false}

	ll, err := cmd.Flags().GetString("log-level")
	if err != nil {
		fmt.Println("error getting log-level:", err)
		os.Exit(1)
	}

	conf.Global.LogLevel = ll

	// set log level
	switch strings.ToUpper(ll) {
	case "ERROR":
		ProgramLevel.Set(slog.LevelError)

		conf.HideProgress = false
	case "WARN":
		ProgramLevel.Set(slog.LevelWarn)

		conf.HideProgress = false
	case "INFO":
		ProgramLevel.Set(slog.LevelInfo)

		conf.HideProgress = true
	case "DEBUG":
		ProgramLevel.Set(slog.LevelDebug)

		conf.HideProgress = true
	}

	hOptions.Level = ProgramLevel

	conf.Logger = slog.New(slog.NewTextHandler(os.Stdout, &hOptions))
}

func readProviderAuthKeys(v *viper.Viper) {
	// read provider auth keys from env if not set in config
	if conf.Providers.AbuseIPDB.APIKey == "" {
		conf.Providers.AbuseIPDB.APIKey = v.GetString("abuseipdb_api_key")
	}

	if conf.Providers.Shodan.APIKey == "" {
		conf.Providers.Shodan.APIKey = v.GetString("shodan_api_key")
	}

	if conf.Providers.CriminalIP.APIKey == "" {
		conf.Providers.CriminalIP.APIKey = v.GetString("criminal_ip_api_key")
	}
}
