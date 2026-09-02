package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/site24x7"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchSite24x7(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Site24x7", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Site24x7", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, site24x7.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run checkly")

	res, err := processor.Run(site24x7.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Site24x7", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, site24x7.ProviderName, ip)}
	}

	slog.Debug("fetched data from Site24x7", "ip", ip)

	var site24x7Result site24x7.HostSearchResult
	if err := json.Unmarshal([]byte(res), &site24x7Result); err != nil {
		slog.Error("Failed to parse Site24x7 JSON", "error", err)

		return providerResult{text: simplifyError(err, site24x7.ProviderName, ip)}
	}

	table := createSite24x7Table(ip, &site24x7Result, false)

	return providerResult{table: table}
}

func createSite24x7Table(ip string, result *site24x7.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Site24x7 | Host: " + ip
	if isActive {
		headerText = " ▶ Site24x7 | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Site24x7 prefix found").
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
