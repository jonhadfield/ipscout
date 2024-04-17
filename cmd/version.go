package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// func init() {
// 	rootCmd.AddCommand(versionCmd)
// }

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of IP Scout",
	Long:  `All software has versions. This is IP Scout's'`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("IP Scout v0.0.1 -- HEAD")
	},
}
