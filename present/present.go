package present

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
)

type Resulter interface {
	CreateTable() *table.Writer
}

func Tables(c *session.Session, tws []*table.Writer) {
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

func DashIfEmpty(value interface{}) string {
	switch v := value.(type) {
	case time.Time:
		if v.IsZero() || v == time.Date(0o001, time.January, 1, 0, 0, 0, 0, time.UTC) {
			return "-"
		}

		return v.Format(providers.TimeFormat)
	case string:
		trimmed := strings.TrimSpace(v)
		if len(trimmed) == 0 {
			return "-"
		}

		return v
	case *string:
		if v == nil || len(strings.TrimSpace(*v)) == 0 {
			return "-"
		}

		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}

type CombinedData struct {
	Shodan     shodan.HostSearchResult
	CriminalIP criminalip.HostSearchResult
}

func outputTables(c *session.Session, tws []*table.Writer) {
	twOuter := table.NewWriter()

	myOuterStyle := table.StyleColoredDark
	myOuterStyle.Title.Align = text.AlignCenter
	myOuterStyle.Title.Colors = text.Colors{text.FgRed, text.BgBlack}

	twOuter.SetTitle("IPScout [v" + c.App.SemVer + "]")
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
