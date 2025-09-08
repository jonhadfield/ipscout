package cmd

import (
	"fmt"
	"os"

	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/session"

	"github.com/spf13/cobra"
)

func newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "manage configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()

				os.Exit(0)
			}

			return nil
		},
	}

	configCmd.AddCommand(newShowConfigCommand())
	configCmd.AddCommand(newDefaultConfigCommand())

	return configCmd
}

func newShowConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "show custom configuration",
		Long:  `show custom configuration.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
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

func newDefaultConfigCommand() *cobra.Command {
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
