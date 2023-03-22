package printer

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

	. "github.com/rollwagen/abusech/pkg/threatfox"
)

// PrintIOCs prints a table of IOC list returned by 'query' API call; filter can be any valid ioc type
func PrintIOCs(iocs []IOC, maxItems int, filter string) error {
	sort.Slice(iocs, func(i, j int) bool {
		return iocs[i].ID > iocs[j].ID
	})

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Type", "IOC", "Type", "First Seen"})

	table.SetColumnColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
	)

	counter := 0

	for _, ioc := range iocs {
		firstSeen := time.Time(ioc.FirstSeen).Format("2006-01-02 15:04:05 UTC")
		if ioc.IocType == filter && filter == "ip:port" {
			s := strings.Split(ioc.Ioc, ":")
			cyan := color.New(color.FgCyan).SprintFunc()
			blue := color.New(color.FgBlue).SprintFunc()
			ipPort := fmt.Sprintf("%s:%s", cyan(s[0]), blue(s[1]))
			table.Append([]string{ioc.ID, ioc.IocType, ipPort, ioc.ThreatType, firstSeen})
			counter++
		}

		if filter == ioc.IocType && filter != "ip:port" {
			table.Append([]string{ioc.ID, ioc.IocType, ioc.Ioc, ioc.ThreatType, firstSeen})
			counter++
		}

		if filter == "" {
			table.Append([]string{ioc.ID, ioc.IocType, ioc.Ioc, ioc.ThreatType, firstSeen})
			counter++
		}

		if counter == maxItems {
			break
		}
	}

	table.Render()

	return nil
}

func PrintIOCByID(detail IOCDetail) {
	firstSeen := time.Time(detail.FirstSeen).Format("2006-01-02 15:04:05 UTC")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"", detail.ID})
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Normal},
		tablewriter.Colors{tablewriter.Bold},
	)

	// table.Rich([]string{"Threat Type", detail.ThreatType}, []tablewriter.Colors{tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold}, tablewriter.Colors{tablewriter.FgCyanColor}})
	// table.Rich([]string{"Description", detail.ThreatTypeDesc}, []tablewriter.Colors{tablewriter.Colors{tablewriter.FgBlueColor, tablewriter.Bold}, tablewriter.Colors{tablewriter.FgBlueColor}})
	cyan := color.New(color.FgCyan).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()
	table.Append([]string{"IOC", detail.IocType + " " + cyan(detail.Ioc)})
	table.Append([]string{"Threat Type", bold(detail.ThreatType) + ": " + detail.ThreatTypeDesc})
	table.Append([]string{"Confidence Level", strconv.Itoa(detail.ConfidenceLevel) + "/100"})
	if detail.Reference != nil {
		table.Append([]string{"Reference", *detail.Reference})
	}
	table.Append([]string{"Malpedia", detail.MalwareMalpedia})
	table.Append([]string{"Reporter", detail.Reporter})
	table.Append([]string{"First seen", firstSeen})

	table.Render()
}
