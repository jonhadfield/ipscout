package ui

import (
	"encoding/json"
	"log/slog"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIPURL(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from IPURL", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IPURL", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ipurl", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ipurl")

	res, err := processor.Run(ipurl.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IPURL", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "ipurl", ip)}
	}

	slog.Info("Fetching data from IPURL", "ip", ip)

	// Parse IPURL JSON response
	var ipurlResult ipurl.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ipurlResult); err != nil {
		slog.Error("Failed to parse IPURL JSON", "error", err)

		return providerResult{text: simplifyError(err, "ipurl", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createIPURLTable(ip, &ipurlResult, false)

	return providerResult{table: table}
}

func createIPURLTable(ip string, result *ipurl.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " IP URL | Host: " + ip
	if isActive {
		headerText = " ▶ IP URL | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have any data
	if len(*result) == 0 {
		table.SetCell(row, 0, tview.NewTableCell(" No URL prefixes found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Prefixes summary
	table.SetCell(row, 0, tview.NewTableCell(" Prefixes").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(len(*result))).
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	row++

	// Display each prefix and its URLs
	for prefix, urls := range *result {
		table.SetCell(row, 0, tview.NewTableCell("   - Prefix").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(prefix.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		// Display URLs for this prefix
		if len(urls) > 0 {
			table.SetCell(row, 0, tview.NewTableCell("     - URLs").
				SetTextColor(tcell.ColorGray).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(len(urls))).
				SetTextColor(tcell.ColorGray).
				SetSelectable(false))

			row++

			for _, url := range urls {
				table.SetCell(row, 0, tview.NewTableCell("       |---").
					SetTextColor(tcell.ColorGray).
					SetSelectable(false))
				table.SetCell(row, 1, tview.NewTableCell(url).
					SetTextColor(tcell.ColorWhite).
					SetSelectable(false))

				row++
			}
		}
	}

	return table
}
