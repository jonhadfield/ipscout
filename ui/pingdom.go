package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/pingdom"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchPingdom(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Pingdom", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Pingdom", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, pingdom.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run pingdom")

	res, err := processor.Run(pingdom.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Pingdom", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, pingdom.ProviderName, ip)}
	}

	slog.Debug("fetched data from Pingdom", "ip", ip)

	var pingdomResult pingdom.HostSearchResult
	if err := json.Unmarshal([]byte(res), &pingdomResult); err != nil {
		slog.Error("Failed to parse Pingdom JSON", "error", err)

		return providerResult{text: simplifyError(err, pingdom.ProviderName, ip)}
	}

	table := createPingdomTable(ip, &pingdomResult, false)

	return providerResult{table: table}
}

func createPingdomTable(ip string, result *pingdom.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Pingdom | Host: " + ip
	if isActive {
		headerText = " ▶ Pingdom | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Pingdom prefix found").
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
