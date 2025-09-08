package cmd

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/jonhadfield/ipscout/rate"
	"github.com/spf13/cobra"
)

func newRateCommand() *cobra.Command {
	var (
		useTestData  bool
		useAI        bool
		openAIAPIKey string
	)

	rateCmd := &cobra.Command{
		Use:   "rate",
		Short: "rate host",
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
				fmt.Printf(constants.MsgInvalidHostFmt, err.Error())

				os.Exit(1)
			}

			rater, err := rate.New(sess)
			if err != nil {
				fmt.Println(err.Error())

				os.Exit(1)
			}

			if useAI {
				rater.Session.Config.Rating.UseAI = true
			}

			if openAIAPIKey != "" {
				rater.Session.Config.Rating.OpenAIAPIKey = openAIAPIKey
			}

			if rater.Session.Config.Rating.UseAI {
				if rater.Session.Config.Rating.OpenAIAPIKey == "" {
					fmt.Println("use AI specified but OpenAI api key not set")

					os.Exit(1)
				}
			}

			if err = rater.Run(); err != nil {
				fmt.Println(err.Error())

				os.Exit(1)
			}

			return nil
		},
	}

	rateCmd.PersistentFlags().BoolVar(&useAI, "ai", false, "use AI to rate host")
	rateCmd.PersistentFlags().StringVar(&openAIAPIKey, "openai-api-key", "", "OpenAI api key")

	rateCmd.AddCommand(newRateConfigCommand())

	return rateCmd
}

func newRateConfigCommand() *cobra.Command {
	var (
		showDefault bool
		configPath  string
	)

	cmd := &cobra.Command{
		Use:   "config",
		Short: "output configuration",
		Long:  `output configuration.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			if showDefault {
				fmt.Println(rate.DefaultRatingConfigJSON)

				os.Exit(0)
			}

			path := cmd.Flag("path").Value.String()
			if path == "" {
				rater, err := rate.New(sess)
				if err != nil {
					os.Exit(1)
				}

				if rater.Session.Config.Rating.ConfigPath == "" {
					fmt.Println("rating configuration path not set")

					os.Exit(1)
				}

				path = rater.Session.Config.Rating.ConfigPath
			}

			ratingConfig, err := providers.ReadRatingConfigFile(path)
			if err != nil {
				fmt.Println(err.Error())

				os.Exit(1)
			}

			_, err = providers.LoadRatingConfig(ratingConfig)
			if err != nil {
				fmt.Printf("%s", err)

				os.Exit(1)
			}

			fmt.Println(string(ratingConfig))

			return nil
		},
	}

	cmd.Flags().BoolVar(&showDefault, "default", false, "show default configuration")
	cmd.Flags().StringVar(&configPath, "path", "", "load configuration from path")

	return cmd
}
