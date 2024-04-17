package present

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/shodan"
)

type Resulter interface {
	CreateTable() *table.Writer
}

func Tables(c *config.Config, tws []*table.Writer) error {
	outputTables(c, tws)

	return nil
}

type CombinedData struct {
	Shodan     shodan.HostSearchResult
	CriminalIP criminalip.HostSearchResult
}

func outputTables(c *config.Config, tws []*table.Writer) {
	twOuter := table.NewWriter()

	myOuterStyle := table.StyleColoredDark
	myOuterStyle.Title.Align = text.AlignCenter
	myOuterStyle.Title.Colors = text.Colors{text.FgRed, text.BgBlack}
	twOuter.SetTitle("IP Scout v0.0.1")
	twOuter.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMin: 60},
	})
	myOuterStyle.Box = table.StyleBoxRounded
	myOuterStyle.Options.SeparateRows = true
	myOuterStyle.Options.DrawBorder = true
	myOuterStyle.Options.DoNotColorBordersAndSeparators = true
	twOuter.SetStyle(myOuterStyle)

	myInnerStyle := table.StyleColoredDark
	myInnerStyle.Options = table.OptionsNoBordersAndSeparators
	myInnerColourOptions := table.ColorOptionsDark
	myInnerColourOptions.Row = text.Colors{text.FgWhite, text.BgBlack}
	myInnerColourOptions.IndexColumn = text.Colors{text.FgHiWhite, text.BgBlack}

	myInnerColourOptions.RowAlternate = table.ColorOptionsDefault.Row
	// myInnerColourOptions.Row = table.ColorOptionsDefault.Row
	myInnerStyle.Color = myInnerColourOptions

	for _, tw := range tws {
		t := *tw
		t.SetIndexColumn(1)
		t.SetStyle(myInnerStyle)
		twOuter.AppendRow([]interface{}{t.Render()})
	}

	fmt.Println(twOuter.Render())
}
