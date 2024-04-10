package cmd

import (
	_ "embed"
	"fmt"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/spf13/cobra"
	"os"
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
			fmt.Println("cache thigns")
			//
			// var err error
			//
			// if conf.Host, err = netip.ParseAddr(args[0]); err != nil {
			// 	return fmt.Errorf("invalid host: %w", err)
			// }
			//

			return nil
		},
	}

	// Define cobra flags, the default value has the lowest (least significant) precedence
	// cacheCmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARN", "set log level as: ERROR, WARN, INFO, DEBUG")
	// cacheCmd.PersistentFlags().StringVar(&maxAge, "max-age", "", "max age of data to consider")
	// cacheCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	// cacheCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "limit ports")
	// cacheCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")
	//
	cacheCmd.AddCommand(newCacheListCommand())

	return cacheCmd

}

func newCacheListCommand() *cobra.Command {
	cacheListCmd := &cobra.Command{
		Use:   "list",
		Short: "ls",
		Long:  `cache stuff.`,
		// Args:  cobra.ExactArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// out := cmd.OutOrStdout()
			fmt.Println("cache list thigns")
			//
			// var err error
			//
			// if conf.Host, err = netip.ParseAddr(args[0]); err != nil {
			// 	return fmt.Errorf("invalid host: %w", err)
			// }
			//
			// processor, err := process.New(&conf)
			// if err != nil {
			// 	os.Exit(1)
			// }
			//
			// processor.Run()
			cacher, err := cache.NewClient(conf)
			if err != nil {
				os.Exit(1)
			}

			cacher.List()

			return nil
		},
	}

	// Define cobra flags, the default value has the lowest (least significant) precedence
	// cacheCmd.PersistentFlags().StringVar(&logLevel, "log-level", "WARN", "set log level as: ERROR, WARN, INFO, DEBUG")
	// cacheCmd.PersistentFlags().StringVar(&maxAge, "max-age", "", "max age of data to consider")
	// cacheCmd.PersistentFlags().BoolVar(&useTestData, "use-test-data", false, "use test data")
	// cacheCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "limit ports")
	// cacheCmd.PersistentFlags().Int32Var(&maxValueChars, "max-value-chars", 0, "max characters to output for any value")
	//
	// cacheCmd.AddCommand(versionCmd)

	return cacheListCmd

}
