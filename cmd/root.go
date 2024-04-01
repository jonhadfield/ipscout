package cmd

import (
	_ "embed"
	"fmt"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/process"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"net/netip"
	"os"
)

const (
	appName = "crosscheck-ip"
)

var conf config.Config

var rootCmd = &cobra.Command{
	Use:   "crosscheck-ip",
	Short: "crosscheck-ip",
	Long:  `crosscheck-ip is a CLI application that does stuff.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if conf.Host, err = netip.ParseAddr(args[0]); err != nil {
			return fmt.Errorf("invalid host: %w", err)
		}

		processor, err := process.New(&conf)
		if err != nil {
			os.Exit(1)
		}

		processor.Run()

		return nil
	},
}

func Execute() {
	// setup config
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var (
	useTestData   bool
	ports         []string
	maxValueChars int32
)

func init() {
	cobra.OnInitialize(initConfig)

	// 	"config file (default is $HOME/.config/crosscheck-ip/config.yml)")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "debug", false, "show debug logging")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "l", []string{}, "limit ports")
	rootCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")

	if err := viper.BindPFlag("ports", rootCmd.Flag("ports")); err != nil {
		fmt.Println("error binding limit-ports flag:", err)
		os.Exit(1)
	}

	if err := viper.BindPFlag("max-value-chars", rootCmd.Flag("max-value-chars")); err != nil {
		fmt.Println("error binding max-value-chars flag:", err)
		os.Exit(1)
	}

	if err := viper.BindPFlag("debug", rootCmd.Flag("debug")); err != nil {
		fmt.Println("error binding debug flag:", err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().Bool("viper", true, "Use Viper for configuration")

	viper.SetDefault("author", "Jon Hadfield <jon@lessknown.co.uk>")
	// TODO: determine before release
	viper.SetDefault("license", "apache")
}

func initConfig() {
	viper.AutomaticEnv()

	configRoot := config.GetConfigRoot("", appName)

	if err := config.CreateDefaultConfigIfMissing(configRoot); err != nil {
		fmt.Printf("can't create default config: %v\n", err)

		os.Exit(1)
	}

	if err := config.CreateCachePathIfNotExist(configRoot); err != nil {
		fmt.Printf("can't create cache directory: %v\n", err)

		os.Exit(1)
	}

	viper.AddConfigPath(configRoot)
	viper.SetConfigName("config")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("can't read config:", err)
		os.Exit(1)
	}

	if err := viper.Unmarshal(&conf); err != nil {

		return
	}

	// read provider auth keys
	readProviderAuthKeys()

	conf.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		// AddSource:   false,
		Level: (map[bool]slog.Level{true: slog.LevelDebug, false: slog.LevelWarn})[viper.GetBool("debug")],
		// ReplaceAttr: nil,
	}))
	conf.HideProgress = (map[bool]bool{true: true, false: false})[viper.GetBool("debug")]
	conf.UseTestData = viper.GetBool("CCI_USE_TEST_DATA")
	conf.HttpClient = getHTTPClient()

	cliPorts := viper.GetStringSlice("ports")
	if len(cliPorts) > 0 {
		conf.Global.Ports = cliPorts
	}

	maxValueChars = viper.GetInt32("max-value-chars")

	if maxValueChars > 0 {
		conf.Global.MaxValueChars = maxValueChars
	}

	conf.Global.IndentSpaces = config.DefaultIndentSpaces
}

func readProviderAuthKeys() {
	// read provider auth keys from env if not set in config
	if conf.Providers.Shodan.APIKey == "" {
		conf.Providers.Shodan.APIKey = viper.GetString("shodan_api_key")
	}

	if conf.Providers.CriminalIP.APIKey == "" {
		conf.Providers.CriminalIP.APIKey = viper.GetString("criminal_ip_api_key")
	}
}
