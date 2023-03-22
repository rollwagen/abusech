package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// threatfoxCmd represents the threatfox command to access the threatfox.abuse.ch API
var threatfoxCmd = &cobra.Command{
	Use:   "threatfox",
	Short: "CLI access to the threatfox.abuse.ch API.",
	Long: `ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs)
associated with malware with the infosec community, AV vendors and threat intelligence providers.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			_ = cmd.Help()
			os.Exit(0)
		}
	},
}

func init() {
	rootCmd.AddCommand(threatfoxCmd)
}
