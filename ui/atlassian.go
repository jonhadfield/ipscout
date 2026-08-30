package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/atlassian"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAtlassian(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Atlassian", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Atlassian", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "atlassian", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run atlassian")

	res, err := processor.Run(atlassian.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Atlassian", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "atlassian", ip)}
	}

	slog.Debug("fetched data from Atlassian", "ip", ip)

	var atlassianResult atlassian.HostSearchResult
	if err := json.Unmarshal([]byte(res), &atlassianResult); err != nil {
		slog.Error("Failed to parse Atlassian JSON", "error", err)

		return providerResult{text: simplifyError(err, "atlassian", ip)}
	}

	table := createAtlassianTable(ip, &atlassianResult, false)

	return providerResult{table: table}
}

func createAtlassianTable(ip string, result *atlassian.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Atlassian | Host: " + ip
	if isActive {
		headerText = " ▶ Atlassian | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Atlassian ranges").
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
