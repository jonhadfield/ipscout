package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/greensnow"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchGreenSnow(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from GreenSnow", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for GreenSnow", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, greensnow.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run greensnow")

	res, err := processor.Run(greensnow.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from GreenSnow", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, greensnow.ProviderName, ip)}
	}

	slog.Debug("fetched data from GreenSnow", "ip", ip)

	var greensnowResult greensnow.HostSearchResult
	if err := json.Unmarshal([]byte(res), &greensnowResult); err != nil {
		slog.Error("Failed to parse GreenSnow JSON", "error", err)

		return providerResult{text: simplifyError(err, greensnow.ProviderName, ip)}
	}

	table := createGreenSnowTable(ip, &greensnowResult, false)

	return providerResult{table: table}
}

func createGreenSnowTable(ip string, result *greensnow.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " GreenSnow | Host: " + ip
	if isActive {
		headerText = " ▶ GreenSnow | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No GreenSnow prefix found").
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
