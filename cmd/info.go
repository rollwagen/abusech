package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// infoCmd information about the CLI and abuse.ch
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Output information about the CLI and abuse.ch",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("                                                       -              ")
		fmt.Println("                                                       -          #   ")
		fmt.Println("                                                       -          #   ")
		fmt.Println("    ##      ######     #*     #=    #####   -######.   -     ###  ###+")
		fmt.Println("   ####     ##   .##   #*     #=  *#.       -#-        -    *     #  #")
		fmt.Println("   ##*#     ##    ##   #*     #=  ##.       -#-        -     ###  #  #")
		fmt.Println("  ##  ##    #######    #*     #=   -#####   -######    -              ")
		fmt.Println(" .##  +#:   ##   .##   #*     #=      :##*  -#-        -              ")
		fmt.Println(" ##    ##   ##    ##   ##    +#=        ##  -#-        -              ")
		fmt.Println("-#=    -#+  #######    .#######   #######   -#######   -              ")
		fmt.Println("                                                       -              ")
		fmt.Println(" ")
		fmt.Println(" ")
		fmt.Println("Abuse.ch is a community-driven threat intelligence provider that helps")
		fmt.Println("internet service providers and network operators protect their infrastructure")
		fmt.Println("from cyber threats, with a focus on malware and botnets.")
		fmt.Println(" ")
		fmt.Println("For further information see https://abuse.ch and https://threatfox.abuse.ch/api/")
		fmt.Println(" ")
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
