package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// infoCmd description of the company.
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print information about the CLI and abuse.ch",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("                                                                  ╞▌                 ")
		fmt.Println("                                                                  ╞▌         █       ")
		fmt.Println("         ██       █████▄▄▄    ██      ██    ▄▄████▄    ████████   ╞▌   ▄▄▀▀  █▄▄▄▄   ")
		fmt.Println("        ████      ██    ██▌   ██      ██   ▐█▌         ██         ╞▌   █     █   █   ")
		fmt.Println("       ██  █▌     ██▄▄▄▄██    ██      ██    ██▄▄▄      ██▄▄▄▄▄    ╞▌   ▀▀▄▄  █   █   ")
		fmt.Println("      ██    █▌    ██▀▀▀▀▀█▌   ██      ██     ▀▀▀▀██▄   ██▀▀▀▀▀    ╞▌                 ")
		fmt.Println("     ██▌     █▄   ██     ██    █      █           █▌   ██         ╞▌                 ")
		fmt.Println("    ██▀      ▀█   █████▀▀▀     ▀▀████▀▀     ▀████▀▀    ████████   ╞▌                 ")
		fmt.Println("                                                                  ╞▌                 ")
		fmt.Println(" ")
		fmt.Println(" ")
		fmt.Println("Abuse.ch is a community-driven threat intelligence provider that helps internet service providers and network")
		fmt.Println("operators protect their infrastructure from cyber threats, with a focus on malware and botnets.")
		fmt.Println(" ")
		fmt.Println("https://github.com/rollwagen/abusech")
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
