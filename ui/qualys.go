package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/qualys"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchQualys(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Qualys", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Qualys", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, qualys.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run qualys")

	res, err := processor.Run(qualys.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Qualys", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, qualys.ProviderName, ip)}
	}

	slog.Debug("fetched data from Qualys", "ip", ip)

	var result qualys.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Qualys JSON", "error", err)

		return providerResult{text: simplifyError(err, qualys.ProviderName, ip)}
	}

	table := createQualysTable(ip, &result, false)

	return providerResult{table: table}
}

func createQualysTable(ip string, result *qualys.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Qualys | Host: " + ip
	if isActive {
		headerText = " ▶ Qualys | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Qualys ranges").
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
