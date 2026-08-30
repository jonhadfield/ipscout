package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/fastly"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchFastly(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Fastly", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Fastly", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "fastly", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run fastly")

	res, err := processor.Run(fastly.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Fastly", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "fastly", ip)}
	}

	slog.Debug("fetched data from Fastly", "ip", ip)

	var fastlyResult fastly.HostSearchResult
	if err := json.Unmarshal([]byte(res), &fastlyResult); err != nil {
		slog.Error("Failed to parse Fastly JSON", "error", err)

		return providerResult{text: simplifyError(err, "fastly", ip)}
	}

	table := createFastlyTable(ip, &fastlyResult, false)

	return providerResult{table: table}
}

func createFastlyTable(ip string, result *fastly.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Fastly | Host: " + ip
	if isActive {
		headerText = " ▶ Fastly | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Fastly ranges").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Prefix").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.Prefix.String()).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	return table
}
