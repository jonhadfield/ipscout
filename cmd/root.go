package cmd

import (
	"fmt"
	"github.com/jonhadfield/noodle/process"
	"github.com/jonhadfield/noodle/shodan"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/netip"
	"os"
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
			UseTestData: viper.GetBool("USE_TEST_DATA"),
			Host:        host,
			Shodan:      shodan.Config{APIKey: viper.GetString("shodan_api_key")},
		}

		processor, err := process.New(&pConfig)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		processor.Run()

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var cfgFile string

var useTestData bool

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.noodle.yaml)")
	rootCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	rootCmd.PersistentFlags().Bool("viper", true, "Use Viper for configuration")
	viper.SetDefault("author", "Jon Hadfield <jon@lessknown.co.uk>")
	viper.SetDefault("license", "apache")

	viper.SetEnvPrefix("noodle")
}

func initConfig() {
	viper.AutomaticEnv()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".noodle")
	}

	// TODO: read in config
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
	}

}
