package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/onetrust"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchOneTrust(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from OneTrust", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for OneTrust", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, onetrust.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run onetrust")

	res, err := processor.Run(onetrust.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from OneTrust", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, onetrust.ProviderName, ip)}
	}

	slog.Debug("fetched data from OneTrust", "ip", ip)

	var onetrustResult onetrust.HostSearchResult
	if err := json.Unmarshal([]byte(res), &onetrustResult); err != nil {
		slog.Error("Failed to parse OneTrust JSON", "error", err)

		return providerResult{text: simplifyError(err, onetrust.ProviderName, ip)}
	}

	table := createOneTrustTable(ip, &onetrustResult, false)

	return providerResult{table: table}
}

func createOneTrustTable(ip string, result *onetrust.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " OneTrust | Host: " + ip
	if isActive {
		headerText = " ▶ OneTrust | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No OneTrust prefix found").
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
