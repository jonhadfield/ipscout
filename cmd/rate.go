package cmd

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/jonhadfield/ipscout/rate"
	"github.com/jonhadfield/ipscout/session"

	"github.com/spf13/cobra"
)

func newRateCommand() *cobra.Command {
	var useTestData bool

	cacheCmd := &cobra.Command{
		Use:   "rate",
		Short: "rate ip address",
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

			rater, err := rate.New(sess)
			if err != nil {
				os.Exit(1)
			}

			rater.Run()

			return nil
		},
	}

	cacheCmd.AddCommand(newDefaultRateCommand())

	return cacheCmd
}

func newDefaultRateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "default",
		Short: "output default configuration",
		Long:  `output default configuration.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			fmt.Println(session.DefaultConfig)

			return nil
		},
	}
}
