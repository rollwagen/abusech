package cmd

import (
	"fmt"
	"os"

	"github.com/rollwagen/abusech/printer"

	"github.com/rollwagen/abusech/threatfox"
	"github.com/samber/lo"

	"github.com/spf13/cobra"
)

// flags
var (
	days   int
	filter string
	id     string
	limit  int
)

var tf = threatfox.New()

// queryCmd represents the query command
var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query recent IOCs",
	Run: func(cmd *cobra.Command, args []string) {
		if id != "" {
			detail, _ := tf.GetIOCByID(id)
			printer.PrintIOCByID(detail)
			return
		}

		iocs, _ := tf.GetIOCs(days)
		err := printer.PrintIOCs(iocs, limit, filter)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error printing IOC list: %s\n", err)
		}
	},
}

func init() {
	queryCmd.Flags().IntVarP(&limit, "limit", "l", 10, "Maximum number of IOCs to list")
	queryCmd.Flags().IntVarP(&days, "days", "d", 3, "Number of days to filter IOCs. Based on first_seen. (min 1, max 7)")
	queryCmd.Flags().StringVarP(&filter, "filter", "f", "", "IOC type to filter for e.g. 'ip:port'")

	queryCmd.Flags().StringVarP(&id, "id", "i", "", "Print details of IOC with given id (takes precedence over general query)")

	_ = queryCmd.RegisterFlagCompletionFunc("filter", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		types, _ := tf.GetIOCTypes()
		return lo.Map(types, func(t threatfox.IOCType, index int) string { return t.Type }), cobra.ShellCompDirectiveDefault
	})

	threatfoxCmd.AddCommand(queryCmd)
}
