package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/xpanse"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchXpanse(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Cortex Xpanse", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Cortex Xpanse", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, xpanse.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run xpanse")

	res, err := processor.Run(xpanse.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Cortex Xpanse", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, xpanse.ProviderName, ip)}
	}

	slog.Debug("fetched data from Cortex Xpanse", "ip", ip)

	var result xpanse.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Cortex Xpanse JSON", "error", err)

		return providerResult{text: simplifyError(err, xpanse.ProviderName, ip)}
	}

	table := createXpanseTable(ip, &result, false)

	return providerResult{table: table}
}

func createXpanseTable(ip string, result *xpanse.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Cortex Xpanse | Host: " + ip
	if isActive {
		headerText = " ▶ Cortex Xpanse | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Cortex Xpanse ranges").
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
