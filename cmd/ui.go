package cmd

import (
	"github.com/jonhadfield/ipscout/ui"

	"github.com/spf13/cobra"
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Open the IPScout user interface",
	Long:  `Open the IPScout user interface`,
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) { //nolint:revive
		logLevel, err := cmd.Flags().GetString("log-level")
		if err != nil {
			logLevel = ""
		}

		if err := ui.OpenUI(logLevel); err != nil {
			cmd.PrintErrln(err)
		}
	},
}
