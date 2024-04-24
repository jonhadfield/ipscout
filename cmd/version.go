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
	Short: "Print the version number of IP Scout",
	Long:  `All software has versions. This is IP Scout's'`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ip scout", version)
	},
}
