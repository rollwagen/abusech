package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// threatfoxCmd represents the threatfox command to access the threatfox.abuse.ch API
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print information about the CLI and abuse.ch",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("                                                                   ╞▌                  ")
		fmt.Println("                                                                   ╞▌          █       ")
		fmt.Println("         ██       █████▄▄▄    ██      ██    ▄▄████▄    ████████    ╞▌    ▄▄▀▀  █▄▄▄▄   ")
		fmt.Println("        ████      ██    ██▌   ██      ██   ▐█▌         ██          ╞▌    █     █   █   ")
		fmt.Println("       ██  █▌     ██▄▄▄▄██    ██      ██    ██▄▄▄      ██▄▄▄▄▄     ╞▌    ▀▀▄▄  █   █   ")
		fmt.Println("      ██    █▌    ██▀▀▀▀▀█▌   ██      ██     ▀▀▀▀██▄   ██▀▀▀▀▀     ╞▌                  ")
		fmt.Println("     ██▌    ██▄   ██     ██    █▌     █▌          █▌   ██          ╞▌                  ")
		fmt.Println("    ██▀      ▀█   █████▀▀▀     ▀▀████▀▀     ▀████▀▀    ████████    ╞▌                  ")
		fmt.Println("                                                                   ╞▌                  ")
		fmt.Println("                                                                   ╞▌                  ")
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
