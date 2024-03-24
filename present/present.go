package present

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jonhadfield/noodle/criminalip"
	"github.com/jonhadfield/noodle/shodan"
	"strings"
)

type Resulter interface {
	CreateTable() *table.Writer
}

func Tables(tws []*table.Writer) error {
	outputTables(tws)

	return nil
}

var (
	colTitleIndex     = "col1"
	colTitleFirstName = "col2"
	colTitleLastName  = "col3"
	colTitleSalary    = "col4"
	// rowHeader         = table.Row{colTitleIndex, colTitleFirstName, colTitleLastName, colTitleSalary}
	row1      = table.Row{"NAME", "Arya", "Stark", 3000}
	row2      = table.Row{20, "Jon", "Snow", 2000, "You know nothing, Jon Snow!"}
	row3      = table.Row{300, "Tyrion", "Lannister", 5000}
	rowFooter = table.Row{"", "", "Total", 10000}
)

type CombinedData struct {
	Shodan     shodan.ShodanHostSearchResult
	CriminalIP criminalip.CriminalIPHostSearchResult
}

var myStyle = table.Style{
	Name: "StyleColoredDark",
	Box:  table.StyleBoxDefault,
	Color: table.ColorOptions{
		Footer:       text.Colors{text.FgCyan, text.BgHiBlack},
		Header:       text.Colors{text.FgHiCyan, text.BgHiBlack},
		IndexColumn:  text.Colors{text.FgHiCyan, text.BgHiBlack},
		Row:          text.Colors{text.FgHiWhite, text.BgBlack},
		RowAlternate: text.Colors{text.FgWhite, text.BgBlack},
	},
	Format: table.FormatOptionsDefault,
	HTML:   table.DefaultHTMLOptions,
	// Options: table.OptionsNoBordersAndSeparators,
	Options: table.OptionsNoBordersAndSeparators,
	Title:   table.TitleOptionsDark}

func outputTables(tws []*table.Writer) {
	twOuter := table.NewWriter()
	// style := table.StyleColoredDark
	// style := table.StyleLight
	// tw.SetCaption(style.Name)
	// tw.SetStyle(style)
	// tw.Style().Title.Align = text.AlignCenter
	// tw.CreateTable()
	twOuter.SetStyle(myStyle)
	twOuter.Style().Title.Align = text.AlignCenter
	twOuter.SetTitle("NOODLE v0.1.0")
	// // twOuter.Style().Options.SeparateRows = true
	for _, tw := range tws {
		t := *tw
		twOuter.AppendRow([]interface{}{t.Render()})
	}
	// twOuter.AppendRow([]interface{}{tw.Render()})
	// twOuter.AppendRow([]interface{}{tw.Render()})
	fmt.Println(twOuter.Render())
}

func demoTableFeatures() {
	// ==========================================================================
	// Initialization
	// ==========================================================================
	t := table.NewWriter()
	// you can also instantiate the object directly
	tTemp := table.Table{}
	tTemp.Render() // just to avoid the compile error of not using the object
	// ==========================================================================

	// ==========================================================================
	// Append a few rows and render to console
	// ==========================================================================
	// a row need not be just strings
	t.AppendRow(table.Row{1, "Arya", "Stark", 3000})
	// all rows need not have the same number of columns
	t.AppendRow(table.Row{20, "Jon", "Snow", 2000, "You know nothing, Jon Snow!"})
	// table.Row is just a shorthand for []interface{}
	t.AppendRow([]interface{}{300, "Tyrion", "Lannister", 5000})
	// time to take a peek
	t.SetCaption("Simple CreateTable with 3 Rows.\n")
	fmt.Println(t.Render())
	// +-----+--------+-----------+------+-----------------------------+
	// |   1 | Arya   | Stark     | 3000 |                             |
	// |  20 | Jon    | Snow      | 2000 | You know nothing, Jon Snow! |
	// | 300 | Tyrion | Lannister | 5000 |                             |
	// +-----+--------+-----------+------+-----------------------------+
	// Simple CreateTable with 3 Rows and a separator.
	// ==========================================================================

	// ==========================================================================
	// Can you index the columns?
	// ==========================================================================
	t.SetAutoIndex(true)
	t.SetCaption("CreateTable with Auto-Indexing.\n")
	fmt.Println(t.Render())
	// +---+-----+--------+-----------+------+-----------------------------+
	// |   |  A  |    B   |     C     |   D  |              E              |
	// +---+-----+--------+-----------+------+-----------------------------+
	// | 1 |   1 | Arya   | Stark     | 3000 |                             |
	// | 2 |  20 | Jon    | Snow      | 2000 | You know nothing, Jon Snow! |
	// | 3 | 300 | Tyrion | Lannister | 5000 |                             |
	// +---+-----+--------+-----------+------+-----------------------------+
	// CreateTable with Auto-Indexing.
	//
	// t.AppendHeader(rowHeader)
	t.SetCaption("CreateTable with Auto-Indexing (columns-only).\n")
	fmt.Println(t.Render())
	// +---+-----+------------+-----------+--------+-----------------------------+
	// |   |   # | FIRST NAME | LAST NAME | SALARY |                             |
	// +---+-----+------------+-----------+--------+-----------------------------+
	// | 1 |   1 | Arya       | Stark     |   3000 |                             |
	// | 2 |  20 | Jon        | Snow      |   2000 | You know nothing, Jon Snow! |
	// | 3 | 300 | Tyrion     | Lannister |   5000 |                             |
	// +---+-----+------------+-----------+--------+-----------------------------+
	// ==========================================================================

	// ==========================================================================
	// A table needs to have a Header & Footer (for this demo at least!)
	// ==========================================================================
	t.SetAutoIndex(false)
	t.SetCaption("CreateTable with 3 Rows & and a Header.\n")
	fmt.Println(t.Render())
	// +-----+------------+-----------+--------+-----------------------------+
	// |   # | FIRST NAME | LAST NAME | SALARY |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// |   1 | Arya       | Stark     |   3000 |                             |
	// |  20 | Jon        | Snow      |   2000 | You know nothing, Jon Snow! |
	// | 300 | Tyrion     | Lannister |   5000 |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// CreateTable with 3 Rows & and a Header.
	//
	// and then add a footer
	t.AppendFooter(table.Row{"", "", "Total", 10000})
	// time to take a peek
	t.SetCaption("CreateTable with 3 Rows, a Header & a Footer.\n")
	fmt.Println(t.Render())
	// +-----+------------+-----------+--------+-----------------------------+
	// |   # | FIRST NAME | LAST NAME | SALARY |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// |   1 | Arya       | Stark     |   3000 |                             |
	// |  20 | Jon        | Snow      |   2000 | You know nothing, Jon Snow! |
	// | 300 | Tyrion     | Lannister |   5000 |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// |     |            | TOTAL     |  10000 |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// CreateTable with 3 Rows, a Header & a Footer.
	// ==========================================================================

	// ==========================================================================
	// Alignment?
	// ==========================================================================
	// did you notice that the numeric columns were auto-aligned? when you don't
	// specify alignment, all the columns default to text.AlignDefault - numbers
	// go right and everything else left. but what if you want the first name to
	// go right too? and the last column to be "justified"?
	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: colTitleFirstName, Align: text.AlignRight},
		// the 5th column does not have a title, so use the column number as the
		// identifier for the column
		{Number: 5, Align: text.AlignJustify},
	})
	// to show AlignJustify in action, lets add one more row
	t.AppendRow(table.Row{4, "Faceless", "Man", 0, "Needs a\tname."})
	// time to take a peek:
	t.SetCaption("CreateTable with Custom Alignment for 2 columns.\n")
	fmt.Println(t.Render())
	// +-----+------------+-----------+--------+-----------------------------+
	// |   # | FIRST NAME | LAST NAME | SALARY |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// |   1 |       Arya | Stark     |   3000 |                             |
	// |  20 |        Jon | Snow      |   2000 | You know nothing, Jon Snow! |
	// | 300 |     Tyrion | Lannister |   5000 |                             |
	// |   4 |   Faceless | Man       |      0 | Needs        a        name. |
	// +-----+------------+-----------+--------+-----------------------------+
	// |     |            | TOTAL     |  10000 |                             |
	// +-----+------------+-----------+--------+-----------------------------+
	// CreateTable with Custom Alignment for 2 columns.
	// ==========================================================================

	// ==========================================================================
	// Vertical Alignment?
	// ==========================================================================
	// horizontal alignment is fine... what about vertical? lets add a row with
	// a column having multiple lines; and then play with VAlign

	// ╔═════╦════════════╦═══════════╦════════╦═══════ ≈
	// ║   # ║ FIRST NAME ║ LAST NAME ║ SALARY ║        ≈
	// ╠═════╬════════════╬═══════════╬════════╬═══════ ≈
	// ║   1 ║ Arya       ║ Stark     ║   3000 ║        ≈
	// ║  20 ║ Jon        ║ Snow      ║   2000 ║ You kn ≈
	// ║ 300 ║ Tyrion     ║ Lannister ║   5000 ║        ≈
	// ╠═════╬════════════╬═══════════╬════════╬═══════ ≈
	// ║     ║            ║ TOTAL     ║  10000 ║        ≈
	// ╚═════╩════════════╩═══════════╩════════╩═══════ ≈
	// CreateTable with an Allowed Row Length of 50 in 'StyleDouble'.
	// ==========================================================================

	// ==========================================================================
	// But I want to see all the data!
	// ==========================================================================
	// ╭─────┬────────┬───────────┬────────┬────────────╮
	// │   # │ FIRST  │ LAST NAME │ SALARY │            │
	// │     │ NAME   │           │        │            │
	// ├─────┼────────┼───────────┼────────┼────────────┤
	// │   1 │ Arya   │ Stark     │   3000 │            │
	// │  20 │ Jon    │ Snow      │   2000 │ You know n │
	// │     │        │           │        │ othing, Jo │
	// │     │        │           │        │ n Snow!    │
	// │ 300 │ Tyrion │ Lannister │   5000 │            │
	// ├─────┼────────┼───────────┼────────┼────────────┤
	// │     │        │ TOTAL     │  10000 │            │
	// ╰─────┴────────┴───────────┴────────┴────────────╯
	// CreateTable on a diet.
	t.SetAllowedRowLength(0)
	// remove the width restrictions
	t.SetColumnConfigs([]table.ColumnConfig{})
	// ==========================================================================

	// ==========================================================================
	// ASCII is too simple for me.
	// ==========================================================================
	t.SetStyle(table.StyleLight)
	t.SetCaption("CreateTable using the style 'StyleLight'.\n")
	fmt.Println(t.Render())
	// ┌─────┬────────────┬───────────┬────────┬─────────────────────────────┐
	// │   # │ FIRST NAME │ LAST NAME │ SALARY │                             │
	// ├─────┼────────────┼───────────┼────────┼─────────────────────────────┤
	// │   1 │ Arya       │ Stark     │   3000 │                             │
	// │  20 │ Jon        │ Snow      │   2000 │ You know nothing, Jon Snow! │
	// │ 300 │ Tyrion     │ Lannister │   5000 │                             │
	// ├─────┼────────────┼───────────┼────────┼─────────────────────────────┤
	// │     │            │ TOTAL     │  10000 │                             │
	// └─────┴────────────┴───────────┴────────┴─────────────────────────────┘
	// CreateTable using the style 'StyleLight'.
	t.SetStyle(table.StyleDouble)
	t.SetCaption("CreateTable using the style '%s'.\n", t.Style().Name)
	fmt.Println(t.Render())
	// ╔═════╦════════════╦═══════════╦════════╦═════════════════════════════╗
	// ║   # ║ FIRST NAME ║ LAST NAME ║ SALARY ║                             ║
	// ╠═════╬════════════╬═══════════╬════════╬═════════════════════════════╣
	// ║   1 ║ Arya       ║ Stark     ║   3000 ║                             ║
	// ║  20 ║ Jon        ║ Snow      ║   2000 ║ You know nothing, Jon Snow! ║
	// ║ 300 ║ Tyrion     ║ Lannister ║   5000 ║                             ║
	// ╠═════╬════════════╬═══════════╬════════╬═════════════════════════════╣
	// ║     ║            ║ TOTAL     ║  10000 ║                             ║
	// ╚═════╩════════════╩═══════════╩════════╩═════════════════════════════╝
	// CreateTable using the style 'StyleDouble'.
	// ==========================================================================

	// ==========================================================================
	// I don't like any of the ready-made styles.
	// ==========================================================================

	// ==========================================================================
	// I need some color in my life!
	// ==========================================================================
	t.SetStyle(table.StyleBold)
	colorBOnW := text.Colors{text.BgWhite, text.FgBlack}
	// set colors using Colors/ColorsHeader/ColorsFooter
	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: colTitleIndex, Colors: text.Colors{text.FgYellow}, ColorsHeader: colorBOnW},
		{Name: colTitleFirstName, Colors: text.Colors{text.FgHiRed}, ColorsHeader: colorBOnW},
		{Name: colTitleLastName, Colors: text.Colors{text.FgHiRed}, ColorsHeader: colorBOnW, ColorsFooter: colorBOnW},
		{Name: colTitleSalary, Colors: text.Colors{text.FgGreen}, ColorsHeader: colorBOnW, ColorsFooter: colorBOnW},
		{Number: 5, Colors: text.Colors{text.FgCyan}, ColorsHeader: colorBOnW},
	})
	t.SetCaption("CreateTable with Colors.\n")
	fmt.Println(t.Render())
	// ┏━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
	// ┃   # ┃ FIRST NAME ┃ LAST NAME ┃ SALARY ┃                             ┃
	// ┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
	// ┃   1 ┃ Arya       ┃ Stark     ┃   3000 ┃                             ┃
	// ┃  20 ┃ Jon        ┃ Snow      ┃   2000 ┃ You know nothing, Jon Snow! ┃
	// ┃ 300 ┃ Tyrion     ┃ Lannister ┃   5000 ┃                             ┃
	// ┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
	// ┃     ┃            ┃ TOTAL     ┃  10000 ┃                             ┃
	// ┗━━━━━┻━━━━━━━━━━━━┻━━━━━━━━━━━┻━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
	// CreateTable with Colors.
	//
	// "CreateTable with Colors"??? where? i don't see any! well, you have to trust me
	// on this... the colors show on a terminal that supports it. to prove it,
	// lets print the same table line-by-line using "%#v" to see the control
	// sequences ...
	t.SetCaption("CreateTable with Colors in Raw Mode.\n")
	for _, line := range strings.Split(t.Render(), "\n") {
		if line != "" {
			fmt.Printf("%#v\n", line)
		}
	}
	fmt.Println()
	// "┏━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
	// "┃\x1b[47;30m   # \x1b[0m┃\x1b[47;30m FIRST NAME \x1b[0m┃\x1b[47;30m LAST NAME \x1b[0m┃\x1b[47;30m SALARY \x1b[0m┃\x1b[47;30m                             \x1b[0m┃"
	// "┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫"
	// "┃\x1b[33m   1 \x1b[0m┃\x1b[91m Arya       \x1b[0m┃\x1b[91m Stark     \x1b[0m┃\x1b[32m   3000 \x1b[0m┃\x1b[36m                             \x1b[0m┃"
	// "┃\x1b[33m  20 \x1b[0m┃\x1b[91m Jon        \x1b[0m┃\x1b[91m Snow      \x1b[0m┃\x1b[32m   2000 \x1b[0m┃\x1b[36m You know nothing, Jon Snow! \x1b[0m┃"
	// "┃\x1b[33m 300 \x1b[0m┃\x1b[91m Tyrion     \x1b[0m┃\x1b[91m Lannister \x1b[0m┃\x1b[32m   5000 \x1b[0m┃\x1b[36m                             \x1b[0m┃"
	// "┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫"
	// "┃     ┃            ┃\x1b[47;30m TOTAL     \x1b[0m┃\x1b[47;30m  10000 \x1b[0m┃                             ┃"
	// "┗━━━━━┻━━━━━━━━━━━━┻━━━━━━━━━━━┻━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
	// "CreateTable with Colors in Raw Mode."
	// ""
	// disable colors and revert to previous version of the column configs
	t.SetColumnConfigs([]table.ColumnConfig{})
	// ==========================================================================

	// ==========================================================================
	// How about not asking me to set colors in such a verbose way? And I don't
	// like wasting my terminal space with borders and separators.
	// ==========================================================================
	t.SetStyle(table.StyleColoredBright)
	t.SetCaption("CreateTable with style 'StyleColoredBright'.\n")
	fmt.Println(t.Render())
	//   #  FIRST NAME  LAST NAME  SALARY
	//   1  Arya        Stark        3000
	//  20  Jon         Snow         2000  You know nothing, Jon Snow!
	// 300  Tyrion      Lannister    5000
	//                  TOTAL       10000
	// CreateTable with style 'StyleColoredBright'.
	t.SetStyle(table.StyleBold)
	// ==========================================================================

	// ==========================================================================
	// I don't like borders!
	// ==========================================================================
	t.Style().Options.DrawBorder = false
	t.SetCaption("CreateTable without Borders.\n")
	fmt.Println(t.Render())
	//   # ┃ FIRST NAME ┃ LAST NAME ┃ SALARY ┃
	// ━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	//   1 ┃ Arya       ┃ Stark     ┃   3000 ┃
	//  20 ┃ Jon        ┃ Snow      ┃   2000 ┃ You know nothing, Jon Snow!
	// 300 ┃ Tyrion     ┃ Lannister ┃   5000 ┃
	// ━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	//     ┃            ┃ TOTAL     ┃  10000 ┃
	// CreateTable without Borders.
	// ==========================================================================

	// ==========================================================================
	// I like walls and borders everywhere!
	// ==========================================================================
	t.Style().Options.DrawBorder = true
	t.Style().Options.SeparateRows = true
	t.SetCaption("CreateTable with Borders Everywhere!\n")
	t.SetTitle("Divide!")
	fmt.Println(t.Render())
	// ┏━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
	// ┃   # ┃ FIRST NAME ┃ LAST NAME ┃ SALARY ┃                             ┃
	// ┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
	// ┃   1 ┃ Arya       ┃ Stark     ┃   3000 ┃                             ┃
	// ┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
	// ┃  20 ┃ Jon        ┃ Snow      ┃   2000 ┃ You know nothing, Jon Snow! ┃
	// ┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
	// ┃ 300 ┃ Tyrion     ┃ Lannister ┃   5000 ┃                             ┃
	// ┣━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
	// ┃     ┃            ┃ TOTAL     ┃  10000 ┃                             ┃
	// ┗━━━━━┻━━━━━━━━━━━━┻━━━━━━━━━━━┻━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
	// CreateTable with Borders Everywhere!
	// ==========================================================================

	// ==========================================================================
	// There is strength in Unity.
	// ==========================================================================
	t.Style().Options.DrawBorder = false
	t.Style().Options.SeparateColumns = false
	t.Style().Options.SeparateFooter = false
	t.Style().Options.SeparateHeader = false
	t.Style().Options.SeparateRows = false
	t.SetCaption("(c) No one!")
	t.SetTitle("Unite!")
	fmt.Println(t.Render())
	fmt.Println()
	//   #  FIRST NAME  LAST NAME  SALARY
	//   1  Arya        Stark        3000
	//  20  Jon         Snow         2000  You know nothing, Jon Snow!
	// 300  Tyrion      Lannister    5000
	//                  TOTAL       10000
	// CreateTable without Any Borders or Separators!
	// ==========================================================================

	// ==========================================================================
	// I want CSV.
	// ==========================================================================
	for _, line := range strings.Split(t.RenderCSV(), "\n") {
		fmt.Printf("[CSV] %s\n", line)
	}
	fmt.Println()
	// [CSV] #,First Name,Last Name,Salary,
	// [CSV] 1,Arya,Stark,3000,
	// [CSV] 20,Jon,Snow,2000,"You know nothing\, Jon Snow!"
	// [CSV] 300,Tyrion,Lannister,5000,
	// [CSV] ,,Total,10000,
	// ==========================================================================

	// ==========================================================================
	// Nope. I want a HTML CreateTable.
	// ==========================================================================
}

// func demoTableEmoji() {
// 	styles := []table.Style{
// 		table.StyleDefault,
// 		table.StyleLight,
// 		table.StyleColoredBright,
// 	}
// 	for _, style := range styles {
// 		tw := table.NewWriter()
// 		tw.AppendHeader(table.Row{"Key", "Value"})
// 		tw.AppendRows([]table.Row{
// 			{"Emoji 1 🥰", 1000},
// 			{"Emoji 2 ⚔️", 2000},
// 			{"Emoji 3 🎁", 3000},
// 			{"Emoji 4 ツ", 4000},
// 		})
// 		tw.AppendFooter(table.Row{"Total", 10000})
// 		tw.SetAutoIndex(true)
// 		tw.SetStyle(style)
//
// 		fmt.Println(tw.Render())
// 		fmt.Println()
// 	}
// }

// func main() {
// 	demoWhat := "features"
// 	if len(os.Args) > 1 {
// 		demoWhat = os.Args[1]
// 	}
//
// 	switch strings.ToLower(demoWhat) {
// 	case "colors":
// 		presentData(CombinedData{Shodan: shodan.ShodanHostSearchResult{}}, nil)
// 	case "emoji":
// 		demoTableEmoji()
// 	default:
// 		demoTableFeatures()
// 	}
// }
