package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/cinsscore"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCINSScore(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from CINS Army List", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for CINS Army List", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, cinsscore.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run cinsscore")

	res, err := processor.Run(cinsscore.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from CINS Army List", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, cinsscore.ProviderName, ip)}
	}

	slog.Debug("fetched data from CINS Army List", "ip", ip)

	var cinsscoreResult cinsscore.HostSearchResult
	if err := json.Unmarshal([]byte(res), &cinsscoreResult); err != nil {
		slog.Error("Failed to parse CINS Army List JSON", "error", err)

		return providerResult{text: simplifyError(err, cinsscore.ProviderName, ip)}
	}

	table := createCINSScoreTable(ip, &cinsscoreResult, false)

	return providerResult{table: table}
}

func createCINSScoreTable(ip string, result *cinsscore.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " CINS Army List | Host: " + ip
	if isActive {
		headerText = " ▶ CINS Army List | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No CINS Army List prefix found").
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
