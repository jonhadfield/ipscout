package cmd

import (
	"fmt"
	"github.com/jonhadfield/ipscout/config"
	"os"

	"github.com/spf13/cobra"
)

func newConfigCommand() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use: "config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}

			return nil
		},
	}

	cacheCmd.AddCommand(newShowConfigCommand())

	return cacheCmd
}

func newShowConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "show configuration",
		Long:  `show configuration.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			client, err := config.NewClient(sess)
			if err != nil {
				os.Exit(1)
			}

			if err = client.Show(); err != nil {
				return fmt.Errorf("error listing cache items: %w", err)
			}

			return nil
		},
	}
}
