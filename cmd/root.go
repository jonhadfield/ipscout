package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"

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

var ErrSilent = errors.New("ErrSilent")

//nolint:funlen
func newRootCommand() *cobra.Command {
	var (
		useTestData   bool
		ports         []string
		maxValueChars int32
		maxAge        string
		maxReports    int
		logLevel      string
		output        string
		style         string
		disableCache  bool
	)

	rootCmd := &cobra.Command{
		Use:           "ipscout [options] <ip address>",
		Short:         "ipscout [command]",
		Long:          `IPScout searches providers for information about hosts`,
		Args:          cobra.MinimumNArgs(0),
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
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

				os.Exit(1)
			}

			var err error

			if sess.Host, err = netip.ParseAddr(args[0]); err != nil {
				return fmt.Errorf("invalid host: %w", err)
			}

			processor, err := process.New(sess)
			if err != nil {
				fmt.Println(err.Error())

				os.Exit(1)
			}

			if err = processor.Run(); err != nil {
				fmt.Println(err.Error())

				os.Exit(1)
			}

			return nil
		},
	}

	cacheCommand := newCacheCommand()
	configCommand := newConfigCommand()
	rateCommand := newRateCommand()

	rootCmd.AddCommand(cacheCommand)
	rootCmd.AddCommand(configCommand)
	rootCmd.AddCommand(rateCommand)
	rootCmd.AddCommand(versionCmd)
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

		if err = processor.Run(); err != nil {
			fmt.Println(err.Error())

			os.Exit(1)
		}

		return nil
	}

	// Define cobra flags, the default value has the lowest (least significant) precedence
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARN", "set log level as: ERROR, WARN, INFO, DEBUG")
	rootCmd.PersistentFlags().StringVar(&output, "output", "table", "output format: table, json")
	rootCmd.PersistentFlags().StringVar(&style, "style", "", "output style: ascii, cyan, red, yellow, green, blue")
	rootCmd.PersistentFlags().StringVar(&maxAge, "max-age", "", "max age of data to consider")
	rootCmd.PersistentFlags().IntVar(&maxReports, "max-reports", session.DefaultMaxReports, "max reports to output for each provider")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().BoolVar(&disableCache, "disable-cache", false, "disable cache")
	rootCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "limit ports")
	rootCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")

	return rootCmd
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

func ToPtr[T any](v T) *T {
	return &v
}

const (
	defaultAbuseIPDBOutputPriority    = 50
	defaultAnnotatedOutputPriority    = 30
	defaultAWSOutputPriority          = 200
	defaultAzureOutputPriority        = 200
	defaultAzureWAFOutputPriority     = 20
	defaultBingbotOutputPriority      = 180
	defaultCriminalIPOutputPriority   = 60
	defaultDigitalOceanOutputPriority = 200
	defaultGCPOutputPriority          = 200
	defaultGoogleOutputPriority       = 200
	defaultGooglebotOutputPriority    = 190
	defaultiCloudPROutputPriority     = 100
	defaultIPAPIOutputPriority        = 90
	defaultIPURLOutputPriority        = 20
	defaultLinodeOutputPriority       = 140
	defaultPtrOutputPriority          = 120
	defaultShodanOutputPriority       = 70
	defaultVirusTotalOutputPriority   = 40
)

func initProviderConfig(sess *session.Session, v *viper.Viper) {
	// IP API
	sess.Providers.IPAPI.APIKey = v.GetString("providers.ipapi.api_key")
	sess.Providers.IPAPI.ResultCacheTTL = v.GetInt64("providers.ipapi.result_cache_ttl")

	// Abuse IPDB
	if v.IsSet("providers.abuseipdb.enabled") {
		sess.Providers.AbuseIPDB.Enabled = ToPtr(v.GetBool("providers.abuseipdb.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "AbuseIPDB provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.abuseipdb.output_priority") {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(v.GetInt32("providers.abuseipdb.output_priority"))
	} else {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(int32(defaultAbuseIPDBOutputPriority))
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

	if v.IsSet("providers.annotated.output_priority") {
		sess.Providers.Annotated.OutputPriority = ToPtr(v.GetInt32("providers.annotated.output_priority"))
	} else {
		sess.Providers.Annotated.OutputPriority = ToPtr(int32(defaultAnnotatedOutputPriority))
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

	if v.IsSet("providers.aws.output_priority") {
		sess.Providers.AWS.OutputPriority = ToPtr(v.GetInt32("providers.aws.output_priority"))
	} else {
		sess.Providers.AWS.OutputPriority = ToPtr(int32(defaultAWSOutputPriority))
	}

	sess.Providers.AWS.URL = v.GetString("providers.aws.url")
	sess.Providers.AWS.DocumentCacheTTL = v.GetInt64("providers.aws.document_cache_ttl")

	// Azure
	if v.IsSet("providers.azure.enabled") {
		sess.Providers.Azure.Enabled = ToPtr(v.GetBool("providers.azure.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Azure provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.azure.output_priority") {
		sess.Providers.Azure.OutputPriority = ToPtr(v.GetInt32("providers.azure.output_priority"))
	} else {
		sess.Providers.Azure.OutputPriority = ToPtr(int32(defaultAzureOutputPriority))
	}

	sess.Providers.Azure.URL = v.GetString("providers.azure.url")

	sess.Providers.Azure.DocumentCacheTTL = v.GetInt64("providers.azure.document_cache_ttl")

	// AzureWAF
	if v.IsSet("providers.azurewaf.enabled") {
		sess.Providers.AzureWAF.Enabled = ToPtr(v.GetBool("providers.azurewaf.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Azure WAF provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.azurewaf.output_priority") {
		sess.Providers.AzureWAF.OutputPriority = ToPtr(v.GetInt32("providers.azurewaf.output_priority"))
	} else {
		sess.Providers.AzureWAF.OutputPriority = ToPtr(int32(defaultAzureWAFOutputPriority))
	}

	sess.Providers.AzureWAF.ResourceIDs = v.GetStringSlice("providers.azurewaf.resource_ids")

	sess.Providers.AzureWAF.DocumentCacheTTL = v.GetInt64("providers.azurewaf.document_cache_ttl")

	// CriminalIP
	if v.IsSet("providers.criminalip.enabled") {
		sess.Providers.CriminalIP.Enabled = ToPtr(v.GetBool("providers.criminalip.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Criminal IP provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.criminalip.output_priority") {
		sess.Providers.CriminalIP.OutputPriority = ToPtr(v.GetInt32("providers.criminalip.output_priority"))
	} else {
		sess.Providers.CriminalIP.OutputPriority = ToPtr(int32(defaultCriminalIPOutputPriority))
	}

	sess.Providers.CriminalIP.ResultCacheTTL = v.GetInt64("providers.criminalip.result_cache_ttl")

	// BingBot
	if v.IsSet("providers.bingbot.enabled") {
		sess.Providers.Bingbot.Enabled = ToPtr(v.GetBool("providers.bingbot.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Bingbot provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.bingbot.output_priority") {
		sess.Providers.Bingbot.OutputPriority = ToPtr(v.GetInt32("providers.bingbot.output_priority"))
	} else {
		sess.Providers.Bingbot.OutputPriority = ToPtr(int32(defaultBingbotOutputPriority))
	}

	sess.Providers.Bingbot.URL = v.GetString("providers.bingbot.url")

	sess.Providers.Bingbot.DocumentCacheTTL = v.GetInt64("providers.bingbot.document_cache_ttl")

	// DigitalOcean
	if v.IsSet("providers.digitalocean.enabled") {
		sess.Providers.DigitalOcean.Enabled = ToPtr(v.GetBool("providers.digitalocean.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "DigitalOcean provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.digitalocean.output_priority") {
		sess.Providers.DigitalOcean.OutputPriority = ToPtr(v.GetInt32("providers.digitalocean.output_priority"))
	} else {
		sess.Providers.DigitalOcean.OutputPriority = ToPtr(int32(defaultDigitalOceanOutputPriority))
	}

	sess.Providers.DigitalOcean.URL = v.GetString("providers.digitalocean.url")
	sess.Providers.DigitalOcean.DocumentCacheTTL = v.GetInt64("providers.digitalocean.document_cache_ttl")

	// GCP
	if v.IsSet("providers.gcp.enabled") {
		sess.Providers.GCP.Enabled = ToPtr(v.GetBool("providers.gcp.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "GCP provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.gcp.output_priority") {
		sess.Providers.GCP.OutputPriority = ToPtr(v.GetInt32("providers.gcp.output_priority"))
	} else {
		sess.Providers.GCP.OutputPriority = ToPtr(int32(defaultGCPOutputPriority))
	}

	sess.Providers.GCP.URL = v.GetString("providers.gcp.url")
	sess.Providers.GCP.DocumentCacheTTL = v.GetInt64("providers.gcp.document_cache_ttl")

	// Google
	if v.IsSet("providers.google.enabled") {
		sess.Providers.Google.Enabled = ToPtr(v.GetBool("providers.google.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Google provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.google.output_priority") {
		sess.Providers.Google.OutputPriority = ToPtr(v.GetInt32("providers.google.output_priority"))
	} else {
		sess.Providers.Google.OutputPriority = ToPtr(int32(defaultGoogleOutputPriority))
	}

	// Googlebot
	if v.IsSet("providers.googlebot.enabled") {
		sess.Providers.Googlebot.Enabled = ToPtr(v.GetBool("providers.googlebot.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Googlebot provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.googlebot.output_priority") {
		sess.Providers.Googlebot.OutputPriority = ToPtr(v.GetInt32("providers.Googlebot.output_priority"))
	} else {
		sess.Providers.Googlebot.OutputPriority = ToPtr(int32(defaultGooglebotOutputPriority))
	}

	sess.Providers.Googlebot.URL = v.GetString("providers.googlebot.url")

	// iCloud Private Relay
	if v.IsSet("providers.icloudpr.enabled") {
		sess.Providers.ICloudPR.Enabled = ToPtr(v.GetBool("providers.icloudpr.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "iCloud Private Relay provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.icloudpr.output_priority") {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(v.GetInt32("providers.icloudpr.output_priority"))
	} else {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(int32(defaultiCloudPROutputPriority))
	}

	sess.Providers.ICloudPR.URL = v.GetString("providers.icloudpr.url")
	sess.Providers.ICloudPR.DocumentCacheTTL = v.GetInt64("providers.icloudpr.document_cache_ttl")

	// IP URL
	if v.IsSet("providers.ipurl.enabled") {
		sess.Providers.IPURL.Enabled = ToPtr(v.GetBool("providers.ipurl.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "IP URL provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.ipurl.output_priority") {
		sess.Providers.IPURL.OutputPriority = ToPtr(v.GetInt32("providers.ipurl.output_priority"))
	} else {
		sess.Providers.IPURL.OutputPriority = ToPtr(int32(defaultIPURLOutputPriority))
	}

	sess.Providers.IPURL.URLs = v.GetStringSlice("providers.ipurl.urls")
	sess.Providers.IPURL.DocumentCacheTTL = v.GetInt64("providers.ipurl.document_cache_ttl")

	// Linode
	if v.IsSet("providers.linode.enabled") {
		sess.Providers.Linode.Enabled = ToPtr(v.GetBool("providers.linode.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Linode provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.linode.output_priority") {
		sess.Providers.Linode.OutputPriority = ToPtr(v.GetInt32("providers.linode.output_priority"))
	} else {
		sess.Providers.Linode.OutputPriority = ToPtr(int32(defaultLinodeOutputPriority))
	}

	sess.Providers.Linode.DocumentCacheTTL = v.GetInt64("providers.linode.document_cache_ttl")
	sess.Providers.Linode.URL = v.GetString("providers.linode.url")
	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	// Shodan
	if v.IsSet("providers.shodan.enabled") {
		sess.Providers.Shodan.Enabled = ToPtr(v.GetBool("providers.shodan.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "Shodan provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.shodan.output_priority") {
		sess.Providers.Shodan.OutputPriority = ToPtr(v.GetInt32("providers.shodan.output_priority"))
	} else {
		sess.Providers.Shodan.OutputPriority = ToPtr(int32(defaultShodanOutputPriority))
	}

	if v.IsSet("providers.shodan.api_key") {
		sess.Providers.Shodan.APIKey = v.GetString("providers.shodan.api_key")
	}

	// PTR
	if v.IsSet("providers.ptr.enabled") {
		sess.Providers.PTR.Enabled = ToPtr(v.GetBool("providers.ptr.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "PTR provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.ptr.output_priority") {
		sess.Providers.PTR.OutputPriority = ToPtr(v.GetInt32("providers.ptr.output_priority"))
	} else {
		sess.Providers.PTR.OutputPriority = ToPtr(int32(defaultPtrOutputPriority))
	}

	sess.Providers.PTR.ResultCacheTTL = v.GetInt64("providers.ptr.result_cache_ttl")
	sess.Providers.PTR.Nameservers = v.GetStringSlice("providers.ptr.nameservers")

	// IPAPI
	if v.IsSet("providers.ipapi.enabled") {
		sess.Providers.IPAPI.Enabled = ToPtr(v.GetBool("providers.ipapi.enabled"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "IPAPI provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.ipapi.output_priority") {
		sess.Providers.IPAPI.OutputPriority = ToPtr(v.GetInt32("providers.ipapi.output_priority"))
	} else {
		sess.Providers.IPAPI.OutputPriority = ToPtr(int32(defaultIPAPIOutputPriority))
	}

	// VirusTotal
	if v.IsSet("providers.virustotal.enabled") {
		sess.Providers.VirusTotal.Enabled = ToPtr(v.GetBool("providers.virustotal.enabled"))
		sess.Providers.VirusTotal.ResultCacheTTL = v.GetInt64("providers.virustotal.result_cache_ttl")
		sess.Providers.VirusTotal.ShowProviders = ToPtr(v.GetBool("providers.virustotal.show_providers"))
		sess.Providers.VirusTotal.ShowUnrated = ToPtr(v.GetBool("providers.virustotal.show_unrated"))
		sess.Providers.VirusTotal.ShowHarmless = ToPtr(v.GetBool("providers.virustotal.show_harmless"))
		sess.Providers.VirusTotal.ShowClean = ToPtr(v.GetBool("providers.virustotal.show_clean"))
	} else {
		sess.Messages.Mu.Lock()
		sess.Messages.Info = append(sess.Messages.Info, "VirusTotal provider not defined in config")
		sess.Messages.Mu.Unlock()
	}

	if v.IsSet("providers.virustotal.output_priority") {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(v.GetInt32("providers.virustotal.output_priority"))
	} else {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(int32(defaultVirusTotalOutputPriority))
	}
}

func initHomeDirConfig(sess *session.Session, v *viper.Viper) error {
	var err error

	homeDir := v.GetString("home_dir")
	if homeDir == "" {
		homeDir, err = homedir.Dir()
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

func initSessionConfig(sess *session.Session, v *viper.Viper, configRoot string) error {
	initProviderConfig(sess, v)

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

	sess.Config.Global.RatingConfigPath = v.GetString("global.rating_config_path")

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
	sess.App.Version = version
	sess.App.SemVer = semver

	if _, err := session.CreateDefaultConfigIfMissing(configRoot); err != nil {
		return fmt.Errorf("cannot create default session: %w", err)
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

	if err := initSessionConfig(sess, v, configRoot); err != nil {
		return err
	}

	// initialise logging
	if err := initLogging(cmd); err != nil {
		return err
	}

	sess.HTTPClient = getHTTPClient()

	utd, err := cmd.Flags().GetBool("use-test-data")
	if err != nil {
		return fmt.Errorf("error getting use-test-data: %w", err)
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

func readProviderAuthKeys(v *viper.Viper) {
	// read provider auth keys from env if not set in session
	if sess.Providers.AbuseIPDB.APIKey == "" {
		sess.Providers.AbuseIPDB.APIKey = v.GetString("abuseipdb_api_key")
	}

	if sess.Providers.AbuseIPDB.APIKey == "" {
		sess.Providers.AbuseIPDB.Enabled = ToPtr(false)
	}

	if sess.Providers.Shodan.APIKey == "" {
		sess.Providers.Shodan.APIKey = v.GetString("shodan_api_key")
	}

	if sess.Providers.Shodan.APIKey == "" {
		sess.Providers.Shodan.Enabled = ToPtr(false)
	}

	if sess.Providers.CriminalIP.APIKey == "" {
		sess.Providers.CriminalIP.APIKey = v.GetString("criminal_ip_api_key")
	}

	if sess.Providers.CriminalIP.APIKey == "" {
		sess.Providers.CriminalIP.Enabled = ToPtr(false)
	}

	if sess.Providers.VirusTotal.APIKey == "" {
		sess.Providers.VirusTotal.APIKey = v.GetString("virustotal_api_key")
	}

	if sess.Providers.VirusTotal.APIKey == "" {
		sess.Providers.VirusTotal.Enabled = ToPtr(false)
	}
}
