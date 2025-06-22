package cmd

import (
	"fmt"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "Version",
	Short: "Print the Version number of IPScout",
	Long:  `Print the Version number of IPScout`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) { //nolint:revive
		fmt.Println("IPScout", helpers.Version)
	},
}
