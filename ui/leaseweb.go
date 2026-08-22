package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/leaseweb"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchLeaseweb(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Leaseweb", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Leaseweb", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "leaseweb", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run leaseweb")

	res, err := processor.Run(leaseweb.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Leaseweb", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "leaseweb", ip)}
	}

	slog.Debug("fetched data from Leaseweb", "ip", ip)

	var leasewebResult leaseweb.HostSearchResult
	if err := json.Unmarshal([]byte(res), &leasewebResult); err != nil {
		slog.Error("Failed to parse Leaseweb JSON", "error", err)

		return providerResult{text: simplifyError(err, "leaseweb", ip)}
	}

	table := createLeasewebTable(ip, &leasewebResult, false)

	return providerResult{table: table}
}

func createLeasewebTable(ip string, result *leaseweb.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Leaseweb | Host: " + ip
	if isActive {
		headerText = " ▶ Leaseweb | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Leaseweb ranges").
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
