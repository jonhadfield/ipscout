package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version string
	semver  string
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of IPScout",
	Long:  `Print the version number of IPScout`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) { //nolint:revive
		fmt.Println("IPScout", version)
	},
}
