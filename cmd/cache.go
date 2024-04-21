package cmd

import (
	_ "embed"
	"github.com/jonhadfield/ipscout/manager"
	"os"

	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use: "cache",
		// Short: "cache",
		Long: `cache stuff.`,
		// Args: cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// out := cmd.OutOrStdout()
			//

			return nil
		},
	}

	cacheCmd.AddCommand(newCacheListCommand())

	return cacheCmd
}

func newCacheListCommand() *cobra.Command {
	cacheListCmd := &cobra.Command{
		Use:   "list",
		Short: "ls",
		Long:  `cache stuff.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := manager.NewClient(conf)
			if err != nil {
				os.Exit(1)
			}

			if err = mgr.List(); err != nil {
				return err
			}

			return nil
		},
	}

	return cacheListCmd
}
