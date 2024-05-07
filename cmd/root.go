package cmd

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/jonhadfield/ipscout/process"
	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	AppName = "ipscout"
)

var sess *session.Session

func newRootCommand() *cobra.Command {
	var (
		useTestData   bool
		ports         []string
		maxValueChars int32
		maxAge        string
		maxReports    int
		logLevel      string
		output        string
		disableCache  bool
	)

	rootCmd := &cobra.Command{
		Use:   "ipscout",
		Short: "ipscout",
		Long:  `IPScout is a CLI application to prod to an IP address.`,
		Args:  cobra.MinimumNArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// using test data doesn't require a host be provided
			// but command does so use placeholder
			if useTestData {
				args = []string{"8.8.8.8"}
			}

			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}

			var err error

			if sess.Host, err = netip.ParseAddr(args[0]); err != nil {
				return fmt.Errorf("invalid host: %w", err)
			}

			processor, err := process.New(sess)
			if err != nil {
				os.Exit(1)
			}
			processor.Run()

			return nil
		},
	}

	// Define cobra flags, the default value has the lowest (least significant) precedence
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARN", "set log level as: ERROR, WARN, INFO, DEBUG")
	rootCmd.PersistentFlags().StringVar(&output, "output", "table", "output format: table, json")
	rootCmd.PersistentFlags().StringVar(&maxAge, "max-age", "", "max age of data to consider")
	rootCmd.PersistentFlags().IntVar(&maxReports, "max-reports", session.DefaultMaxReports, "max reports to output for each provider")
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
	// setup session
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

	sess = session.New()
	configRoot := session.GetConfigRoot("", AppName)
	sess.App.Version = version
	sess.App.SemVer = semver

	if err := session.CreateDefaultConfigIfMissing(configRoot); err != nil {
		fmt.Printf("can't create default session: %v\n", err)

		os.Exit(1)
	}

	v.AddConfigPath(configRoot)
	v.SetConfigName("config")

	if err := v.ReadInConfig(); err != nil {
		fmt.Println("can't read session:", err)
		os.Exit(1)
	}

	v.AutomaticEnv()

	if err := session.CreateConfigPathStructure(configRoot); err != nil {
		fmt.Printf("can't create cache directory: %v\n", err)

		os.Exit(1)
	}

	readProviderAuthKeys(v)

	// set cmd flags to those learned by viper if cmd flag is not set and viper's is
	bindFlags(cmd, v)

	sess.Target = os.Stderr

	sess.Providers.AbuseIPDB.Enabled = v.GetBool("providers.abuseipdb.enabled")
	sess.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	sess.Providers.Annotated.Enabled = v.GetBool("providers.annotated.enabled")
	sess.Providers.Annotated.Paths = v.GetStringSlice("providers.annotated.paths")
	sess.Providers.AWS.Enabled = v.GetBool("providers.aws.enabled")
	sess.Providers.AWS.URL = v.GetString("providers.aws.url")
	sess.Providers.Azure.Enabled = v.GetBool("providers.azure.enabled")
	sess.Providers.Azure.URL = v.GetString("providers.azure.url")
	sess.Providers.CriminalIP.Enabled = v.GetBool("providers.criminalip.enabled")
	sess.Providers.DigitalOcean.Enabled = v.GetBool("providers.digitalocean.enabled")
	sess.Providers.DigitalOcean.URL = v.GetString("providers.digitalocean.url")
	sess.Providers.GCP.Enabled = v.GetBool("providers.gcp.enabled")
	sess.Providers.GCP.URL = v.GetString("providers.gcp.url")
	sess.Providers.Googlebot.Enabled = v.GetBool("providers.googlebot.enabled")
	sess.Providers.ICloudPR.Enabled = v.GetBool("providers.icloudpr.enabled")
	sess.Providers.ICloudPR.URL = v.GetString("providers.icloudpr.url")
	sess.Providers.IPURL.Enabled = v.GetBool("providers.ipurl.enabled")
	sess.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	sess.Providers.Linode.Enabled = v.GetBool("providers.linode.enabled")
	sess.Providers.Linode.URL = v.GetString("providers.linode.url")
	sess.Providers.Shodan.Enabled = v.GetBool("providers.shodan.enabled")
	sess.Providers.PTR.Enabled = v.GetBool("providers.ptr.enabled")
	sess.Providers.PTR.Nameservers = v.GetStringSlice("providers.ptr.nameservers")
	sess.Providers.IPAPI.Enabled = v.GetBool("providers.ipapi.enabled")
	sess.Config.Global.Ports = v.GetStringSlice("global.ports")
	sess.Config.Global.MaxValueChars = v.GetInt32("global.max_value_chars")
	sess.Config.Global.MaxAge = v.GetString("global.max_age")
	sess.Config.Global.MaxReports = v.GetInt("global.max_reports")
	// TODO: Nasty Hack Alert
	// if not specified, ports is returned as a string: "[]"
	// set to nil if that's the case
	if len(sess.Config.Global.Ports) == 0 || sess.Config.Global.Ports[0] == "[]" {
		sess.Config.Global.Ports = nil
	}

	sess.Config.Global.MaxAge = v.GetString("global.max_age")

	// initialise logging
	initLogging(cmd)

	sess.HTTPClient = getHTTPClient()

	utd, err := cmd.Flags().GetBool("use-test-data")
	if err != nil {
		os.Exit(1)
	}

	sess.UseTestData = utd

	ports, _ := cmd.Flags().GetStringSlice("ports")
	// TODO: Nasty Hack Alert
	// if not specified, ports is returned as a string: "[]"
	// set to nil if that's the case
	if len(ports) == 0 || ports[0] == "[]" {
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

	sess.Config.Global.IndentSpaces = session.DefaultIndentSpaces

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
}

func readProviderAuthKeys(v *viper.Viper) {
	// read provider auth keys from env if not set in session
	if sess.Providers.AbuseIPDB.APIKey == "" {
		sess.Providers.AbuseIPDB.APIKey = v.GetString("abuseipdb_api_key")
	}

	if sess.Providers.Shodan.APIKey == "" {
		sess.Providers.Shodan.APIKey = v.GetString("shodan_api_key")
	}

	if sess.Providers.CriminalIP.APIKey == "" {
		sess.Providers.CriminalIP.APIKey = v.GetString("criminal_ip_api_key")
	}
}
