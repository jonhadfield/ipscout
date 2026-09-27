package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ohdear"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchOhDear(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Oh Dear", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Oh Dear", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ohdear.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ohdear")

	res, err := processor.Run(ohdear.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Oh Dear", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ohdear.ProviderName, ip)}
	}

	slog.Debug("fetched data from Oh Dear", "ip", ip)

	var result ohdear.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse Oh Dear JSON", "error", err)

		return providerResult{text: simplifyError(err, ohdear.ProviderName, ip)}
	}

	table := createOhDearTable(ip, &result, false)

	return providerResult{table: table}
}

func createOhDearTable(ip string, result *ohdear.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Oh Dear | Host: " + ip
	if isActive {
		headerText = " ▶ Oh Dear | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Oh Dear ranges").
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
