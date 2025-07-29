package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/mitchellh/go-homedir"

	c "github.com/jonhadfield/ipscout/constants"
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

		if len(args) == 0 {
			_ = cmd.Help()

			os.Exit(0)
		}

		var err error

		if sess.Host, err = helpers.ParseHost(args[0]); err != nil {
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

func addProviderConfigMessage(sess *session.Session, provider string) {
	sess.Messages.Mu.Lock()
	sess.Messages.Info = append(sess.Messages.Info, fmt.Sprintf(c.ProviderNotDefinedFmt, provider))
	sess.Messages.Mu.Unlock()
}

const (
	defaultAbuseIPDBOutputPriority    = 50
	defaultAlibabaOutputPriority      = 60
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
	defaultGoogleSCOutputPriority     = 190
	defaultHetznerOutputPriority      = 70
	defaultiCloudPROutputPriority     = 100
	defaultIPAPIOutputPriority        = 90
	defaultIPQSOutputPriority         = 50
	defaultIPURLOutputPriority        = 20
	defaultLinodeOutputPriority       = 140
	defaultPtrOutputPriority          = 120
	defaultShodanOutputPriority       = 70
	defaultVirusTotalOutputPriority   = 40
	defaultZscalerOutputPriority      = 40
)

func initProviderConfig(sess *session.Session, v *viper.Viper) {
	// IP API
	sess.Providers.IPAPI.APIKey = v.GetString("providers.ipapi.api_key")
	sess.Providers.IPAPI.ResultCacheTTL = v.GetInt64("providers.ipapi.result_cache_ttl")

	// Abuse IPDB
	if v.IsSet("providers.abuseipdb.enabled") {
		sess.Providers.AbuseIPDB.Enabled = ToPtr(v.GetBool("providers.abuseipdb.enabled"))
	} else {
		addProviderConfigMessage(sess, "AbuseIPDB")
	}

	if v.IsSet("providers.abuseipdb.output_priority") {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(v.GetInt32("providers.abuseipdb.output_priority"))
	} else {
		sess.Providers.AbuseIPDB.OutputPriority = ToPtr(int32(defaultAbuseIPDBOutputPriority))
	}

	sess.Providers.AbuseIPDB.MaxAge = v.GetInt("providers.abuseipdb.max_age")
	sess.Providers.AbuseIPDB.ResultCacheTTL = v.GetInt64("providers.abuseipdb.result_cache_ttl")

	// Alibaba
	if v.IsSet("providers.alibaba.enabled") {
		sess.Providers.Alibaba.Enabled = ToPtr(v.GetBool("providers.alibaba.enabled"))
	} else {
		addProviderConfigMessage(sess, "Alibaba")
	}

	if v.IsSet("providers.alibaba.output_priority") {
		sess.Providers.Alibaba.OutputPriority = ToPtr(v.GetInt32("providers.alibaba.output_priority"))
	} else {
		sess.Providers.Alibaba.OutputPriority = ToPtr(int32(defaultAlibabaOutputPriority))
	}

	sess.Providers.Alibaba.URL = v.GetString("providers.alibaba.url")
	sess.Providers.Alibaba.DocumentCacheTTL = v.GetInt64("providers.alibaba.document_cache_ttl")

	if v.IsSet("providers.annotated.enabled") {
		sess.Providers.Annotated.Enabled = ToPtr(v.GetBool("providers.annotated.enabled"))
	} else {
		addProviderConfigMessage(sess, "Annotated")
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
		addProviderConfigMessage(sess, "AWS")
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
		addProviderConfigMessage(sess, "Azure")
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
		addProviderConfigMessage(sess, "Azure WAF")
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
		addProviderConfigMessage(sess, "Criminal IP")
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
		addProviderConfigMessage(sess, "Bingbot")
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
		addProviderConfigMessage(sess, "DigitalOcean")
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
		addProviderConfigMessage(sess, "GCP")
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
		addProviderConfigMessage(sess, "Google")
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
		addProviderConfigMessage(sess, "Googlebot")
	}

	if v.IsSet("providers.googlebot.output_priority") {
		sess.Providers.Googlebot.OutputPriority = ToPtr(v.GetInt32("providers.Googlebot.output_priority"))
	} else {
		sess.Providers.Googlebot.OutputPriority = ToPtr(int32(defaultGooglebotOutputPriority))
	}

	sess.Providers.Googlebot.URL = v.GetString("providers.googlebot.url")

	// GoogleSC
	if v.IsSet("providers.googlesc.enabled") {
		sess.Providers.GoogleSC.Enabled = ToPtr(v.GetBool("providers.googlesc.enabled"))
	} else {
		addProviderConfigMessage(sess, "GoogleSC")
	}

	if v.IsSet("providers.googlesc.output_priority") {
		sess.Providers.GoogleSC.OutputPriority = ToPtr(v.GetInt32("providers.GoogleSC.output_priority"))
	} else {
		sess.Providers.GoogleSC.OutputPriority = ToPtr(int32(defaultGoogleSCOutputPriority))
	}

	sess.Providers.GoogleSC.URL = v.GetString("providers.googlesc.url")

	// Hetzner
	if v.IsSet("providers.hetzner.enabled") {
		sess.Providers.Hetzner.Enabled = ToPtr(v.GetBool("providers.hetzner.enabled"))
	} else {
		addProviderConfigMessage(sess, "Hetzner")
	}

	if v.IsSet("providers.hetzner.output_priority") {
		sess.Providers.Hetzner.OutputPriority = ToPtr(v.GetInt32("providers.hetzner.output_priority"))
	} else {
		sess.Providers.Hetzner.OutputPriority = ToPtr(int32(defaultHetznerOutputPriority))
	}

	// iCloud Private Relay
	if v.IsSet("providers.icloudpr.enabled") {
		sess.Providers.ICloudPR.Enabled = ToPtr(v.GetBool("providers.icloudpr.enabled"))
	} else {
		addProviderConfigMessage(sess, "iCloud Private Relay")
	}

	if v.IsSet("providers.icloudpr.output_priority") {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(v.GetInt32("providers.icloudpr.output_priority"))
	} else {
		sess.Providers.ICloudPR.OutputPriority = ToPtr(int32(defaultiCloudPROutputPriority))
	}

	sess.Providers.ICloudPR.URL = v.GetString("providers.icloudpr.url")
	sess.Providers.ICloudPR.DocumentCacheTTL = v.GetInt64("providers.icloudpr.document_cache_ttl")

	// IPQS
	if v.IsSet("providers.ipqs.enabled") {
		sess.Providers.IPQS.Enabled = ToPtr(v.GetBool("providers.ipqs.enabled"))
	} else {
		addProviderConfigMessage(sess, "IPQS")
	}

	if v.IsSet("providers.ipqs.output_priority") {
		sess.Providers.IPQS.OutputPriority = ToPtr(v.GetInt32("providers.ipqs.output_priority"))
	} else {
		sess.Providers.IPQS.OutputPriority = ToPtr(int32(defaultIPQSOutputPriority))
	}

	if v.IsSet("providers.ipqs.api_key") {
		sess.Providers.IPQS.APIKey = v.GetString("providers.ipqs.api_key")
	}

	sess.Providers.IPQS.ResultCacheTTL = v.GetInt64("providers.ipqs.result_cache_ttl")

	// IP URL
	if v.IsSet("providers.ipurl.enabled") {
		sess.Providers.IPURL.Enabled = ToPtr(v.GetBool("providers.ipurl.enabled"))
	} else {
		addProviderConfigMessage(sess, "IP URL")
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
		addProviderConfigMessage(sess, "Linode")
	}

	if v.IsSet("providers.linode.output_priority") {
		sess.Providers.Linode.OutputPriority = ToPtr(v.GetInt32("providers.linode.output_priority"))
	} else {
		sess.Providers.Linode.OutputPriority = ToPtr(int32(defaultLinodeOutputPriority))
	}

	sess.Providers.Linode.DocumentCacheTTL = v.GetInt64("providers.linode.document_cache_ttl")
	sess.Providers.Linode.URL = v.GetString("providers.linode.url")
	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	// M247
	if v.IsSet("providers.m247.enabled") {
		sess.Providers.M247.Enabled = ToPtr(v.GetBool("providers.m247.enabled"))
	} else {
		addProviderConfigMessage(sess, "M247")
	}

	if v.IsSet("providers.m247.output_priority") {
		sess.Providers.M247.OutputPriority = ToPtr(v.GetInt32("providers.m247.output_priority"))
	} else {
		sess.Providers.M247.OutputPriority = ToPtr(int32(c.DefaultM247OutputPriority))
	}

	sess.Providers.M247.DocumentCacheTTL = v.GetInt64("providers.m247.document_cache_ttl")
	sess.Providers.M247.URL = v.GetString("providers.m247.url")

	// OVH
	if v.IsSet("providers.ovh.enabled") {
		sess.Providers.OVH.Enabled = ToPtr(v.GetBool("providers.ovh.enabled"))
	} else {
		addProviderConfigMessage(sess, "OVH")
	}

	if v.IsSet("providers.ovh.output_priority") {
		sess.Providers.OVH.OutputPriority = ToPtr(v.GetInt32("providers.ovh.output_priority"))
	} else {
		sess.Providers.OVH.OutputPriority = ToPtr(int32(c.DefaultOVHOutputPriority))
	}

	sess.Providers.OVH.DocumentCacheTTL = v.GetInt64("providers.ovh.document_cache_ttl")
	sess.Providers.OVH.URL = v.GetString("providers.ovh.url")
	sess.Providers.Shodan.ResultCacheTTL = v.GetInt64("providers.shodan.result_cache_ttl")

	// Shodan
	if v.IsSet("providers.shodan.enabled") {
		sess.Providers.Shodan.Enabled = ToPtr(v.GetBool("providers.shodan.enabled"))
	} else {
		addProviderConfigMessage(sess, "Shodan")
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
		addProviderConfigMessage(sess, "PTR")
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
		addProviderConfigMessage(sess, "IPAPI")
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
		addProviderConfigMessage(sess, "VirusTotal")
	}

	if v.IsSet("providers.virustotal.output_priority") {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(v.GetInt32("providers.virustotal.output_priority"))
	} else {
		sess.Providers.VirusTotal.OutputPriority = ToPtr(int32(defaultVirusTotalOutputPriority))
	}

	// Zscaler
	if v.IsSet("providers.zscaler.enabled") {
		sess.Providers.Zscaler.Enabled = ToPtr(v.GetBool("providers.zscaler.enabled"))
	} else {
		addProviderConfigMessage(sess, "Zscaler")
	}

	if v.IsSet("providers.zscaler.output_priority") {
		sess.Providers.Zscaler.OutputPriority = ToPtr(v.GetInt32("providers.zscaler.output_priority"))
	} else {
		sess.Providers.Zscaler.OutputPriority = ToPtr(int32(defaultZscalerOutputPriority))
	}

	sess.Providers.Zscaler.DocumentCacheTTL = v.GetInt64("providers.zscaler.document_cache_ttl")
	sess.Providers.Zscaler.URL = v.GetString("providers.zscaler.url")
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

func initSessionConfig(sess *session.Session, v *viper.Viper) error {
	initProviderConfig(sess, v)

	sess.Config.Global.Ports = v.GetStringSlice("global.ports")
	sess.Config.Global.MaxValueChars = v.GetInt32("global.max_value_chars")

	sess.Config.Global.MaxAge = v.GetString("global.max_age")
	sess.Config.Global.MaxReports = v.GetInt("global.max_reports")

	if len(sess.Config.Global.Ports) == 1 && sess.Config.Global.Ports[0] == "[]" {
		sess.Config.Global.Ports = nil
	}

	sess.Config.Global.MaxAge = v.GetString("global.max_age")

	sess.Config.Rating.ConfigPath = v.GetString("rating.config_path")
	sess.Config.Rating.UseAI = v.GetBool("rating.use_ai")
	sess.Config.Rating.OpenAIAPIKey = v.GetString("rating.openai_api_key")

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
		*enabled = ToPtr(false)
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
