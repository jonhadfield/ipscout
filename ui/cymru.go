package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/cymru"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCymru(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Team Cymru Bogons", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Team Cymru Bogons", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, cymru.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run cymru")

	res, err := processor.Run(cymru.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Team Cymru Bogons", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, cymru.ProviderName, ip)}
	}

	slog.Debug("fetched data from Team Cymru Bogons", "ip", ip)

	var cymruResult cymru.HostSearchResult
	if err := json.Unmarshal([]byte(res), &cymruResult); err != nil {
		slog.Error("Failed to parse Team Cymru Bogons JSON", "error", err)

		return providerResult{text: simplifyError(err, cymru.ProviderName, ip)}
	}

	table := createCymruTable(ip, &cymruResult, false)

	return providerResult{table: table}
}

func createCymruTable(ip string, result *cymru.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Team Cymru Bogons | Host: " + ip
	if isActive {
		headerText = " ▶ Team Cymru Bogons | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Team Cymru Bogons prefix found").
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

	row++

	if !result.LastUpdated.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Last Updated").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.LastUpdated.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))
	}

	return table
}
