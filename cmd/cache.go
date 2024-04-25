package cmd

import (
	_ "embed"
	"os"

	"github.com/jonhadfield/ipscout/manager"

	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "manage cached data",
		Long:  `manage cached data.`,
		//PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		//	// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
		//	return initConfig(cmd)
		//},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}

			return nil
		},
	}

	cacheCmd.AddCommand(newCacheDelCommand())
	cacheCmd.AddCommand(newCacheListCommand())

	return cacheCmd
}

func newCacheListCommand() *cobra.Command {
	cacheListCmd := &cobra.Command{
		Use:   "list",
		Short: "list cached items",
		Long:  `list outputs all of the currently cached items.`,
		//PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		//	return initConfig(cmd)
		//},
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

func newCacheDelCommand() *cobra.Command {
	var keys []string

	cacheListCmd := &cobra.Command{
		Use:   "delete",
		Short: "delete items from cache",
		Long:  `delete one or more items from cache by specifying their keys.`,
		//PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		//	return initConfig(cmd)
		//},
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := manager.NewClient(conf)
			if err != nil {
				os.Exit(1)
			}

			if err = mgr.Delete(keys); err != nil {
				return err
			}

			return nil
		},
	}

	cacheListCmd.PersistentFlags().StringSliceVarP(&keys, "keys", "k", nil, "cache keys to delete")

	return cacheListCmd
}
