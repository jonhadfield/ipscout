package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/checkly"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCheckly(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Checkly", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Checkly", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, checkly.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(checkly.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Checkly", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, checkly.ProviderName, ip)}
	}

	slog.Debug("fetched data from Checkly", "ip", ip)

	var checklyResult checkly.HostSearchResult
	if err := json.Unmarshal([]byte(res), &checklyResult); err != nil {
		slog.Error("Failed to parse Checkly JSON", "error", err)

		return providerResult{text: simplifyError(err, checkly.ProviderName, ip)}
	}

	table := createChecklyTable(ip, &checklyResult, false)

	return providerResult{table: table}
}

func createChecklyTable(ip string, result *checkly.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Checkly | Host: " + ip
	if isActive {
		headerText = " ▶ Checkly | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Checkly prefix found").
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
