package present

import (
	"fmt"
	"sort"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

// Tables renders a collection of provider results.
func Tables(c *session.Session, tws []providers.TableWithPriority) {
	outputTables(c, tws)
}

func outputTables(c *session.Session, tws []providers.TableWithPriority) {
	twOuter := table.NewWriter()

	twOuter.SetTitle("IPScout [v" + c.App.SemVer + "]")
	twOuter.SetColumnConfigs([]table.ColumnConfig{{Number: 1, AutoMerge: false, WidthMin: externalTableMinWidth}})

	twOuter.SetStyle(OuterTableStyle(*c))

	sort.Slice(tws, func(i, j int) bool {
		priorityI := tws[i].Priority

		if priorityI != nil && (tws[j].Priority == nil || *priorityI < *tws[j].Priority) {
			return true
		}

		return false
	})

	for _, tw := range tws {
		t := *tw.Table
		t.SetIndexColumn(1)
		t.SetStyle(InnerTableStyle(*c))
		twOuter.AppendRow([]interface{}{t.Render()})
	}

	fmt.Println(twOuter.Render())
}
