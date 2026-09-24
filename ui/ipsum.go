package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ipsum"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIPsum(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from IPsum", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IPsum", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ipsum.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ipsum")

	res, err := processor.Run(ipsum.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IPsum", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ipsum.ProviderName, ip)}
	}

	slog.Debug("fetched data from IPsum", "ip", ip)

	var result ipsum.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse IPsum JSON", "error", err)

		return providerResult{text: simplifyError(err, ipsum.ProviderName, ip)}
	}

	table := createIPsumTable(ip, &result, false)

	return providerResult{table: table}
}

func createIPsumTable(ip string, result *ipsum.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " IPsum | Host: " + ip
	if isActive {
		headerText = " ▶ IPsum | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in IPsum ranges").
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
