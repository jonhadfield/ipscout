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
		Use:   "ipscout [options] <ip address>",
		Short: "ipscout [command]",
		Long:  `IPScout searches providers for info on IP addresses`,
		Args:  cobra.MinimumNArgs(0),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			return initConfig(cmd)
		}, // nolint:revive
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

	cacheCommand := newCacheCommand()

	rootCmd.AddCommand(cacheCommand)
	rootCmd.AddCommand(versionCmd)
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
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

func ToPtr[T any](v T) *T {
	return &v
}

func initConfig(cmd *cobra.Command) error {
	v := viper.New()

	sess = session.New()
	configRoot := session.GetConfigRoot("", AppName)
	sess.App.Version = version
	sess.App.SemVer = semver

	if _, err := session.CreateDefaultConfigIfMissing(configRoot); err != nil {
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

	if v.IsSet("providers.abuseipdb.enabled") {
		sess.Providers.AbuseIPDB.Enabled = ToPtr(v.GetBool("providers.abuseipdb.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "AbuseIPDB provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	sess.Providers.AbuseIPDB.ResultCacheTTL = v.GetInt64("providers.abuseipdb.result_cache_ttl")

	if v.IsSet("providers.annotated.enabled") {
		sess.Providers.Annotated.Enabled = ToPtr(v.GetBool("providers.annotated.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Annotated provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.Annotated.Paths = v.GetStringSlice("providers.annotated.paths")
	sess.Providers.Annotated.DocumentCacheTTL = v.GetInt64("providers.annotated.document_cache_ttl")

	if v.IsSet("providers.aws.enabled") {
		sess.Providers.AWS.Enabled = ToPtr(v.GetBool("providers.aws.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "AWS provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.AWS.URL = v.GetString("providers.aws.url")
	sess.Providers.AWS.DocumentCacheTTL = v.GetInt64("providers.aws.document_cache_ttl")

	if v.IsSet("providers.azure.enabled") {
		sess.Providers.Azure.Enabled = ToPtr(v.GetBool("providers.azure.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Azure provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.Azure.URL = v.GetString("providers.azure.url")

	sess.Providers.Azure.DocumentCacheTTL = v.GetInt64("providers.azure.document_cache_ttl")
	if v.IsSet("providers.criminalip.enabled") {
		sess.Providers.CriminalIP.Enabled = ToPtr(v.GetBool("providers.criminalip.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Criminal IP provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.CriminalIP.ResultCacheTTL = v.GetInt64("providers.criminalip.result_cache_ttl")
	if v.IsSet("providers.digitalocean.enabled") {
		sess.Providers.DigitalOcean.Enabled = ToPtr(v.GetBool("providers.digitalocean.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "DigitalOcean provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.DigitalOcean.URL = v.GetString("providers.digitalocean.url")
	sess.Providers.DigitalOcean.DocumentCacheTTL = v.GetInt64("providers.digitalocean.document_cache_ttl")

	if v.IsSet("providers.gcp.enabled") {
		sess.Providers.GCP.Enabled = ToPtr(v.GetBool("providers.gcp.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "GCP provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.GCP.URL = v.GetString("providers.gcp.url")
	sess.Providers.GCP.DocumentCacheTTL = v.GetInt64("providers.gcp.document_cache_ttl")

	if v.IsSet("providers.google.enabled") {
		sess.Providers.Google.Enabled = ToPtr(v.GetBool("providers.google.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Google provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.googlebot.enabled") {
		sess.Providers.Googlebot.Enabled = ToPtr(v.GetBool("providers.googlebot.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Googlebot provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.Googlebot.URL = v.GetString("providers.googlebot.url")

	if v.IsSet("providers.icloudpr.enabled") {
		sess.Providers.ICloudPR.Enabled = ToPtr(v.GetBool("providers.icloudpr.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "iCloud Private Relay provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.ICloudPR.URL = v.GetString("providers.icloudpr.url")
	sess.Providers.ICloudPR.DocumentCacheTTL = v.GetInt64("providers.icloudpr.document_cache_ttl")

	if v.IsSet("providers.ipurl.enabled") {
		sess.Providers.IPURL.Enabled = ToPtr(v.GetBool("providers.ipurl.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "IP URL provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	sess.Providers.IPURL.DocumentCacheTTL = v.GetInt64("providers.ipurl.document_cache_ttl")

	if v.IsSet("providers.linode.enabled") {
		sess.Providers.Linode.Enabled = ToPtr(v.GetBool("providers.linode.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Linode provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.Linode.DocumentCacheTTL = v.GetInt64("providers.linode.document_cache_ttl")
	sess.Providers.Linode.URL = v.GetString("providers.linode.url")
	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	if v.IsSet("providers.shodan.enabled") {
		sess.Providers.Shodan.Enabled = ToPtr(v.GetBool("providers.shodan.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Shodan provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.shodan.api_key") {
		sess.Providers.Shodan.APIKey = v.GetString("providers.shodan.api_key")
	}

	if v.IsSet("providers.ptr.enabled") {
		sess.Providers.PTR.Enabled = ToPtr(v.GetBool("providers.ptr.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "PTR provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.PTR.ResultCacheTTL = v.GetInt64("providers.ptr.result_cache_ttl")
	sess.Providers.PTR.Nameservers = v.GetStringSlice("providers.ptr.nameservers")

	if v.IsSet("providers.ipapi.enabled") {
		sess.Providers.IPAPI.Enabled = ToPtr(v.GetBool("providers.ipapi.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "IPAPI provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	sess.Providers.IPAPI.APIKey = v.GetString("providers.ipapi.api_key")
	sess.Providers.IPAPI.ResultCacheTTL = v.GetInt64("providers.ipapi.result_cache_ttl")
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
