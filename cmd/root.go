package cmd

import (
	_ "embed"
	"fmt"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/process"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"log/slog"
	"net/netip"
	"os"
	"strings"
)

const (
	AppName = "crosscheck-ip"
)

var conf *config.Config

func newRootCommand() *cobra.Command {
	var (
		useTestData   bool
		ports         []string
		maxValueChars int32
		maxAge        string
		logLevel      string
	)

	rootCmd := &cobra.Command{
		Use:   "crosscheck-ip",
		Short: "crosscheck-ip",
		Long:  `crosscheck-ip is a CLI application that does stuff.`,
		Args:  cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// out := cmd.OutOrStdout()

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
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "limit ports")
	rootCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")

	rootCmd.AddCommand(newCacheCommand())
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
		// Determine the naming convention of the flags when represented in the config file
		// configName := strings.ReplaceAll(flg.Name, "-", "_")
		configName := flg.Name
		// configName = strings.ReplaceAll(configName, "-", "_")
		// Apply the viper config value to the flag when the flag is not set and viper has a value
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
	if err := config.CreateDefaultConfigIfMissing(configRoot); err != nil {
		fmt.Printf("can't create default config: %v\n", err)

		os.Exit(1)
	}

	v.AddConfigPath(configRoot)
	// v.AddConfigPath(".")
	v.SetConfigName("config")

	if err := v.ReadInConfig(); err != nil {
		fmt.Println("can't read config:", err)
		os.Exit(1)
	}

	// v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	// Bind the current command's flags to viper
	// fmt.Println("cmd.loglevel", cmd.Flags())

	if err := config.CreateConfigPathStructure(configRoot); err != nil {
		fmt.Printf("can't create cache directory: %v\n", err)

		os.Exit(1)
	}

	// read provider auth keys
	readProviderAuthKeys(v)

	// set cmd flags to those learned by viper if cmd flag is not set and viper's is
	bindFlags(cmd, v)

	conf.Output = os.Stdout

	conf.Providers.AWS.Enabled = v.GetBool("providers.aws.enabled")
	conf.Providers.AbuseIPDB.Enabled = v.GetBool("providers.abuseipdb.enabled")
	conf.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	conf.Providers.Azure.Enabled = v.GetBool("providers.azure.enabled")
	conf.Providers.DigitalOcean.Enabled = v.GetBool("providers.digitalocean.enabled")
	conf.Providers.CriminalIP.Enabled = v.GetBool("providers.criminalip.enabled")
	conf.Providers.IPURL.Enabled = v.GetBool("providers.ipurl.enabled")
	conf.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	conf.Providers.Shodan.Enabled = v.GetBool("providers.shodan.enabled")
	conf.Global.Ports = v.GetStringSlice("global.ports")
	conf.Global.MaxValueChars = v.GetInt32("global.max_value_chars")
	conf.Global.MaxAge = v.GetString("global.max_age")
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

	maxValueChars, _ := cmd.Flags().GetInt32("max-value-chars")
	if maxValueChars > 0 {
		conf.Global.MaxValueChars = maxValueChars
	}

	conf.Global.IndentSpaces = config.DefaultIndentSpaces

	return nil
}

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
		hOptions.Level = slog.LevelError
		conf.HideProgress = false
	case "WARN":
		hOptions.Level = slog.LevelWarn
		conf.HideProgress = false
	case "INFO":
		hOptions.Level = slog.LevelInfo
		conf.HideProgress = true
	case "DEBUG":
		hOptions.Level = slog.LevelDebug
		conf.HideProgress = true
	}

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
