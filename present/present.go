package present

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
)

const (
	txtASCII              = "ascii"
	txtRed                = "red"
	txtYellow             = "yellow"
	txtGreen              = "green"
	txtBlue               = "blue"
	txtCyan               = "cyan"
	externalTableMinWidth = 60
)

type Resulter interface {
	CreateTable() *table.Writer
}

func Tables(c *session.Session, tws []providers.TableWithPriority) {
	outputTables(c, tws)
}

func JSON(jms *json.RawMessage) error {
	var out bytes.Buffer

	if err := json.Indent(&out, *jms, "", "  "); err != nil {
		return fmt.Errorf("error indenting JSON: %w", err)
	}

	fmt.Println(out.String())

	return nil
}

type CombinedData struct {
	Shodan     shodan.HostSearchResult
	CriminalIP criminalip.HostSearchResult
}

func OuterTableStyle(sess session.Session) table.Style {
	var tableStyle table.Style

	cyanStyle := table.StyleColoredDark
	cyanStyle.Title.Align = text.AlignCenter

	cyanStyle.Title.Colors = text.Colors{text.FgRed, text.BgBlack}
	cyanStyle.Box = table.StyleBoxRounded
	cyanStyle.Options.SeparateRows = true
	cyanStyle.Options.DrawBorder = true
	cyanStyle.Options.DoNotColorBordersAndSeparators = true

	switch sess.Config.Global.Style {
	case txtASCII:
		tableStyle = table.StyleDefault
		tableStyle.Title.Align = text.AlignCenter

		return tableStyle
	case txtYellow:
		tableStyle = table.StyleColoredYellowWhiteOnBlack
		tableStyle.Title.Colors = text.Colors{text.FgRed, text.BgBlack}
		tableStyle.Title.Align = text.AlignCenter
		tableStyle.Box = table.StyleBoxRounded
		tableStyle.Options.SeparateRows = true
		tableStyle.Options.DrawBorder = true
		tableStyle.Options.DoNotColorBordersAndSeparators = true

		return tableStyle
	case txtCyan:
		return cyanStyle
	default:
		return cyanStyle
	}
}

func InnerTableStyle(sess session.Session) table.Style {
	var tableStyle table.Style

	cyanStyle := table.StyleColoredDark
	cyanStyle.Options = table.OptionsNoBordersAndSeparators
	cyanStyleColorOptions := table.ColorOptionsDark
	cyanStyleColorOptions.Header = text.Colors{text.FgHiCyan, text.BgHiBlack}
	cyanStyleColorOptions.Row = text.Colors{text.FgWhite, text.BgBlack}
	cyanStyleColorOptions.IndexColumn = text.Colors{text.FgHiWhite, text.BgBlack}
	cyanStyleColorOptions.RowAlternate = table.ColorOptionsDefault.Row
	cyanStyle.Color = cyanStyleColorOptions

	switch sess.Config.Global.Style {
	case txtASCII:
		return table.StyleDefault
	case txtYellow:
		tableStyle = table.StyleColoredYellowWhiteOnBlack
		tableStyle.Options = table.OptionsNoBordersAndSeparators
		tableColorOptions := table.ColorOptionsDark
		tableColorOptions.Header = text.Colors{text.FgHiYellow, text.BgHiBlack}
		tableColorOptions.Row = text.Colors{text.FgWhite, text.BgBlack}
		tableColorOptions.IndexColumn = text.Colors{text.FgHiWhite, text.BgBlack}
		tableColorOptions.RowAlternate = table.ColorOptionsDefault.Row
		tableStyle.Color = tableColorOptions

		return tableStyle
	case txtRed:
		tableStyle = table.StyleColoredRedWhiteOnBlack
		tableColorOptions := table.ColorOptionsDark
		tableColorOptions.Row = text.Colors{text.FgWhite, text.BgBlack}
		tableColorOptions.Header = text.Colors{text.FgHiRed, text.BgHiBlack}
		tableColorOptions.IndexColumn = text.Colors{text.FgHiWhite, text.BgBlack}
		tableColorOptions.RowAlternate = table.ColorOptionsDefault.Row
		tableStyle.Color = tableColorOptions

		return tableStyle
	case txtGreen:
		tableStyle = table.StyleColoredGreenWhiteOnBlack
		tableStyle.Options = table.OptionsNoBordersAndSeparators
		tableColorOptions := table.ColorOptionsDark
		tableColorOptions.Header = text.Colors{text.FgHiGreen, text.BgHiBlack}
		tableColorOptions.Row = text.Colors{text.FgWhite, text.BgBlack}
		tableColorOptions.IndexColumn = text.Colors{text.FgHiWhite, text.BgBlack}
		tableColorOptions.RowAlternate = table.ColorOptionsDefault.Row
		tableStyle.Color = tableColorOptions

		return tableStyle
	case txtBlue:
		tableStyle = table.StyleColoredBlueWhiteOnBlack
		tableStyle.Options = table.OptionsNoBordersAndSeparators
		tableColorOptions := table.ColorOptionsDark
		tableColorOptions.Header = text.Colors{text.FgHiBlue, text.BgHiBlack}
		tableColorOptions.Row = text.Colors{text.FgWhite, text.BgBlack}
		tableColorOptions.IndexColumn = text.Colors{text.FgHiWhite, text.BgBlack}
		tableColorOptions.RowAlternate = table.ColorOptionsDefault.Row
		tableStyle.Color = tableColorOptions

		return tableStyle
	case txtCyan:
		return cyanStyle
	default:
		tableStyle = cyanStyle

		return tableStyle
	}
}

func outputTables(c *session.Session, tws []providers.TableWithPriority) {
	twOuter := table.NewWriter()

	twOuter.SetTitle("IPScout [v" + c.App.SemVer + "]")
	twOuter.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMin: externalTableMinWidth},
	})

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
