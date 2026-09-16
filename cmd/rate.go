package cmd

import (
	"errors"
	"fmt"
	"net/netip"

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

				return nil
			}

			var err error
			if sess.Host, err = netip.ParseAddr(args[0]); err != nil {
				return fmt.Errorf(constants.MsgInvalidHostFmt, err.Error())
			}

			rater, err := rate.New(sess)
			if err != nil {
				return fmt.Errorf("error creating rater: %w", err)
			}

			if useAI {
				rater.Session.Config.Rating.UseAI = true
			}

			if openAIAPIKey != "" {
				rater.Session.Config.Rating.OpenAIAPIKey = openAIAPIKey
			}

			if rater.Session.Config.Rating.UseAI {
				if rater.Session.Config.Rating.OpenAIAPIKey == "" {
					return errors.New("use AI specified but OpenAI api key not set")
				}
			}

			if err = rater.Run(); err != nil {
				return fmt.Errorf("error rating host: %w", err)
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
				fmt.Fprintln(cmd.OutOrStdout(), rate.DefaultRatingConfigJSON)

				return nil
			}

			path := cmd.Flag("path").Value.String()
			if path == "" {
				rater, err := rate.New(sess)
				if err != nil {
					return fmt.Errorf("error creating rater: %w", err)
				}

				if rater.Session.Config.Rating.ConfigPath == "" {
					return errors.New("rating configuration path not set")
				}

				path = rater.Session.Config.Rating.ConfigPath
			}

			ratingConfig, err := providers.ReadRatingConfigFile(path)
			if err != nil {
				return fmt.Errorf("error reading rating config: %w", err)
			}

			_, err = providers.LoadRatingConfig(ratingConfig)
			if err != nil {
				return fmt.Errorf("error loading rating config: %w", err)
			}

			fmt.Fprintln(cmd.OutOrStdout(), string(ratingConfig))

			return nil
		},
	}

	cmd.Flags().BoolVar(&showDefault, "default", false, "show default configuration")
	cmd.Flags().StringVar(&configPath, "path", "", "load configuration from path")

	return cmd
}
