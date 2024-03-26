package cmd

import (
	"fmt"
	"github.com/jonhadfield/noodle/process"
	"github.com/jonhadfield/noodle/providers/criminalip"
	"github.com/jonhadfield/noodle/providers/shodan"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/netip"
	"os"
	"path"
)

const (
	defaultConfigPath = ".config/noodle/config.yml"
)

var rootCmd = &cobra.Command{
	Use:   "noodle",
	Short: "noodle",
	Long:  `noodle is a CLI application that does stuff.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		var host netip.Addr

		if host, err = netip.ParseAddr(args[0]); err != nil {
			return fmt.Errorf("invalid host: %w", err)
		}

		pConfig := process.Config{
			Shodan:     shodan.Config{APIKey: viper.GetString("shodan_api_key")},
			CriminalIP: criminalip.Config{APIKey: viper.GetString("criminal_ip_api_key")},
		}

		pConfig.Host = host
		pConfig.UseTestData = viper.GetBool("NOODLE_USE_TEST_DATA")
		pConfig.HttpClient = getHTTPClient()
		pConfig.LimitPorts = viper.GetStringSlice("limit-ports")
		fmt.Println("Limiting ports", pConfig.LimitPorts)

		processor, err := process.New(&pConfig)
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

	limitPorts []string
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
	rootCmd.PersistentFlags().StringSliceVarP(&limitPorts, "limit-ports", "l", []string{"sss"}, "limit ports")

	if err := viper.BindPFlag("limit-ports", rootCmd.Flag("limit-ports")); err != nil {
		os.Exit(1)
	}

	rootCmd.PersistentFlags().Bool("viper", true, "Use Viper for configuration")
	viper.SetDefault("author", "Jon Hadfield <jon@lessknown.co.uk>")
	viper.SetDefault("license", "apache")

	// viper.SetEnvPrefix("noodle")
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
		viper.AddConfigPath(home)
		// viper.SetConfigName(".noodle")
	}

	_ = viper.ReadInConfig()
}
