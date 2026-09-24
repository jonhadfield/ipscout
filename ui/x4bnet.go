package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/x4bnet"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchX4BNet(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from X4BNet", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for X4BNet", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, x4bnet.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run x4bnet")

	res, err := processor.Run(x4bnet.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from X4BNet", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, x4bnet.ProviderName, ip)}
	}

	slog.Debug("fetched data from X4BNet", "ip", ip)

	var result x4bnet.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse X4BNet JSON", "error", err)

		return providerResult{text: simplifyError(err, x4bnet.ProviderName, ip)}
	}

	table := createX4BNetTable(ip, &result, false)

	return providerResult{table: table}
}

func createX4BNetTable(ip string, result *x4bnet.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " X4BNet | Host: " + ip
	if isActive {
		headerText = " ▶ X4BNet | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in X4BNet ranges").
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
