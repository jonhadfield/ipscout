package cmd

import (
	"fmt"
	"os"

	"github.com/jonhadfield/ipscout/manager"

	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "manage cached items",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}

			return nil
		},
	}

	cacheCmd.AddCommand(newCacheDelCommand())
	cacheCmd.AddCommand(newCacheGetCommand())
	cacheCmd.AddCommand(newCacheListCommand())

	return cacheCmd
}

func newCacheListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list cached items",
		Long:  `list outputs all of the currently cached items.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				os.Exit(1)
			}

			if err = mgr.List(); err != nil {
				return fmt.Errorf("error listing cache items: %w", err)
			}

			return nil
		},
	}
}

func newCacheDelCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "delete items from cache",
		Long:  `delete one or more items from cache by specifying their keys.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			return initConfig(cmd)
		},
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				os.Exit(1)
			}

			if err = mgr.Delete(args); err != nil {
				return fmt.Errorf("error deleting item from cache: %w", err)
			}

			return nil
		},
	}
}

func newCacheGetCommand() *cobra.Command {
	var raw bool

	cmd := &cobra.Command{
		Use:   "get",
		Short: "get item from cache",
		Long:  `get a cached item by providing its key.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			return initConfig(cmd)
		},
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { // nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				os.Exit(1)
			}

			if err = mgr.Get(args[0], raw); err != nil {
				return fmt.Errorf("error getting item from cache: %w", err)
			}

			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&raw, "raw", false, "raw data only")

	return cmd
}
