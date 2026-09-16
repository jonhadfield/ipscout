package cmd

import (
	"fmt"

	"github.com/jonhadfield/ipscout/manager"
	"github.com/jonhadfield/ipscout/process"
	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "manage cached items",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()

				return nil
			}

			return nil
		},
	}

	cacheCmd.AddCommand(newCacheDelCommand())
	cacheCmd.AddCommand(newCacheInitialiseCommand())
	cacheCmd.AddCommand(newCacheGetCommand())
	cacheCmd.AddCommand(newCacheListCommand())
	cacheCmd.AddCommand(newCacheGCCommand())

	return cacheCmd
}

func newCacheGCCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "gc",
		Short: "reclaim space from the cache",
		Long: `gc rewrites the cache's value log files to drop entries that have expired.

Badger only frees that space when the files are rewritten, so a long-lived cache
can hold far more on disk than its live entries account for. Closing the cache
does a little of this on every run; gc does the rest in one go.`,
		Args: cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				return fmt.Errorf("error creating cache manager: %w", err)
			}

			if err = mgr.GC(); err != nil {
				return fmt.Errorf("error reclaiming cache space: %w", err)
			}

			return nil
		},
	}
}

func newCacheListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list cached items",
		Long:  `list outputs all of the currently cached items.`,
		Args:  cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				return fmt.Errorf("error creating cache manager: %w", err)
			}

			if err = mgr.List(); err != nil {
				return fmt.Errorf("error listing cache items: %w", err)
			}

			return nil
		},
	}
}

func newCacheInitialiseCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "initialise cache",
		Long:  `initialise cache.`,
		Args:  cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			processor, err := process.New(sess)
			if err != nil {
				return fmt.Errorf("error creating processor: %w", err)
			}

			processor.Session.Config.Global.InitialiseCacheOnly = true

			if err = processor.Run(); err != nil {
				return fmt.Errorf("error initialising cache: %w", err)
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				return fmt.Errorf("error creating cache manager: %w", err)
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			return initConfig(cmd)
		},
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { //nolint:revive
			mgr, err := manager.NewClient(sess)
			if err != nil {
				return fmt.Errorf("error creating cache manager: %w", err)
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
