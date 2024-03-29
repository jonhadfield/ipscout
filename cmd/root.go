package cmd

import (
	"fmt"
	"github.com/jonhadfield/noodle/config"
	"github.com/jonhadfield/noodle/process"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/netip"
	"os"
	"path"
)

const (
	defaultConfigPath = ".config/noodle/config.yaml"
)

var conf config.Config

var rootCmd = &cobra.Command{
	Use:   "noodle",
	Short: "noodle",
	Long:  `noodle is a CLI application that does stuff.`,
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
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var (
	cfgFile string

	useTestData bool

	ports []string
)

func getDefaultConfigPath() string {
	home, err := homedir.Dir()
	if err != nil {
		os.Exit(1)
	}

	return path.Join(home, defaultConfigPath)

}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", getDefaultConfigPath(),
		"config file (default is $HOME/.config/noodle/config.yml)")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "l", []string{}, "limit ports")

	if err := viper.BindPFlag("ports", rootCmd.Flag("ports")); err != nil {
		fmt.Println("error binding limit-ports flag:", err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().Bool("viper", true, "Use Viper for configuration")
	viper.SetDefault("author", "Jon Hadfield <jon@lessknown.co.uk>")
	viper.SetDefault("license", "apache")
}

func initConfig() {
	viper.AutomaticEnv()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			os.Exit(1)
		}

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(os.Getenv("PWD"))
		viper.AddConfigPath(home + "/.config/noodle")
		viper.SetConfigName("config.yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	if err := viper.Unmarshal(&conf); err != nil {

		return
	}

	// read provider auth keys
	readProviderAuthKeys()

	conf.UseTestData = viper.GetBool("NOODLE_USE_TEST_DATA")
	conf.HttpClient = getHTTPClient()

	cliPorts := viper.GetStringSlice("ports")
	if len(cliPorts) > 0 {
		conf.Global.Ports = cliPorts
	}

	conf.Global.MaxValueChars = viper.GetInt32("max-value-chars")
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
