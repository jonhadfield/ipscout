package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/asndrop"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchASNDrop(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from ASN-DROP", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for ASN-DROP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, asndrop.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run asndrop")

	res, err := processor.Run(asndrop.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from ASN-DROP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, asndrop.ProviderName, ip)}
	}

	slog.Debug("fetched data from ASN-DROP", "ip", ip)

	var result asndrop.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse ASN-DROP JSON", "error", err)

		return providerResult{text: simplifyError(err, asndrop.ProviderName, ip)}
	}

	table := createASNDropTable(ip, &result, false)

	return providerResult{table: table}
}

func createASNDropTable(ip string, result *asndrop.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " ASN-DROP | Host: " + ip
	if isActive {
		headerText = " ▶ ASN-DROP | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if result.ASN == 0 {
		table.SetCell(row, 0, tview.NewTableCell(" AS not on ASN-DROP ").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" ASN").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("AS%d", result.ASN)).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	table.SetCell(row, 0, tview.NewTableCell(" AS Name").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(result.ASName).
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	return table
}
