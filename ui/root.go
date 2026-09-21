package ui

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jonhadfield/ipscout/config"
	c "github.com/jonhadfield/ipscout/constants"
	h "github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/session"
	"github.com/spf13/viper"
)

func ToPtr[T any](v T) *T {
	return config.ToPtr(v)
}

var sess *session.Session

func initSessionConfig(sess *session.Session, v *viper.Viper) {
	config.InitProviders(sess, v)

	sess.Config.Global.Ports = v.GetStringSlice("global.ports")
	sess.Config.Global.MaxValueChars = v.GetInt32("global.max_value_chars")
	sess.Config.Global.DisableTips = v.GetBool("global.disable_tips")

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
}

func initConfig(logLevel string) (*session.Session, error) {
	v := viper.New()

	// create session
	sess = session.New()

	// get home dir to be used for config and cache
	if err := h.InitHomeDirConfig(sess, v); err != nil {
		return sess, fmt.Errorf("home dir initialization error: %w", err)
	}

	configRoot := session.GetConfigRoot("", sess.Config.Global.HomeDir, c.AppName)
	sess.App.Version = h.Version
	sess.App.SemVer = h.SemVer

	if _, err := session.CreateDefaultConfigIfMissing(configRoot); err != nil {
		return sess, fmt.Errorf("cannot create default session: %w", err)
	}

	// add any providers introduced since the user's config was written, so
	// their config shows all no-config providers as enabled, and disable
	// keyed providers left enabled without a key
	config.UpdateConfigFile(sess, filepath.Join(configRoot, session.DefaultConfigFileName))

	v.AddConfigPath(configRoot)
	v.SetConfigName("config")

	if err := v.ReadInConfig(); err != nil {
		return sess, fmt.Errorf("cannot read session: %w", err)
	}

	v.AutomaticEnv()

	if err := session.CreateConfigPathStructure(configRoot); err != nil {
		return sess, fmt.Errorf("can't create cache directory: %w", err)
	}

	readProviderAuthKeys(v)

	sess.Target = os.Stderr

	initSessionConfig(sess, v)

	config.ReportMissingAPIKeys(sess)

	// initialise logging
	if err := initLogging(logLevel); err != nil {
		return sess, err
	}

	sess.HTTPClient = h.GetHTTPClient()

	// utd, err := cmd.Flags().GetBool("use-test-data")
	// if err != nil {
	// 	return sess, fmt.Errorf("error getting use-test-data: %w", err)
	// }
	//
	// sess.UseTestData = utd

	// ports, _ := cmd.Flags().GetStringSlice("ports")
	// if len(ports) == 1 && ports[0] == "[]" {
	// 	ports = nil
	// }
	// // if no ports specified on cli then default to global ports
	// if len(ports) > 0 {
	// 	sess.Config.Global.Ports = ports
	// }
	//
	// maxAge, _ := cmd.Flags().GetString("max-age")
	// if maxAge != "" {
	// 	sess.Config.Global.MaxAge = maxAge
	// }
	//
	// disableCache, _ := cmd.Flags().GetBool("disable-cache")
	// if disableCache {
	// 	sess.Config.Global.DisableCache = disableCache
	// }
	//
	// output, _ := cmd.Flags().GetString("output")
	// if output != "" {
	// 	sess.Config.Global.Output = output
	// }
	//
	// maxValueChars, _ := cmd.Flags().GetInt32("max-value-chars")
	// if maxValueChars > 0 {
	// 	sess.Config.Global.MaxValueChars = maxValueChars
	// }

	sess.Config.Global.IndentSpaces = c.DefaultIndentSpaces

	// default to config global style
	sess.Config.Global.Style = v.GetString("global.style")

	// override with cli flag if set
	// outputStyle, _ := cmd.Flags().GetString("style")
	// if outputStyle != "" {
	// 	sess.Config.Global.Style = outputStyle
	// }

	return sess, nil
}

var ProgramLevel = new(slog.LevelVar) // Info by default

func initLogging(logLevel string) error {
	hOptions := slog.HandlerOptions{AddSource: false}

	sess.Config.Global.LogLevel = logLevel

	// set log level
	switch strings.ToUpper(logLevel) {
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
	default:
		// match the CLI's default log level
		ProgramLevel.Set(slog.LevelWarn)

		sess.HideProgress = false
	}

	hOptions.Level = ProgramLevel

	// Open log file for session logger
	logFile, err := os.OpenFile(LogFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, LogFilePerms)
	if err != nil {
		return fmt.Errorf("failed to open log file for session logger: %w", err)
	}

	sess.Logger = slog.New(slog.NewTextHandler(logFile, &hOptions))

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
	setProviderAPIKey(v, "ipapi_api_key", &sess.Providers.IPAPI.APIKey, &sess.Providers.IPAPI.Enabled)
	setProviderAPIKey(v, "criminal_ip_api_key", &sess.Providers.CriminalIP.APIKey, &sess.Providers.CriminalIP.Enabled)
	setProviderAPIKey(v, "ipqs_api_key", &sess.Providers.IPQS.APIKey, &sess.Providers.IPQS.Enabled)
	setProviderAPIKey(v, "shodan_api_key", &sess.Providers.Shodan.APIKey, &sess.Providers.Shodan.Enabled)
	setProviderAPIKey(v, "virustotal_api_key", &sess.Providers.VirusTotal.APIKey, &sess.Providers.VirusTotal.Enabled)
}
