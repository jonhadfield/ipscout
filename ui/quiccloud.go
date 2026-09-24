package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/quiccloud"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchQuicCloud(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from QUIC.cloud", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for QUIC.cloud", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, quiccloud.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run quiccloud")

	res, err := processor.Run(quiccloud.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from QUIC.cloud", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, quiccloud.ProviderName, ip)}
	}

	slog.Debug("fetched data from QUIC.cloud", "ip", ip)

	var result quiccloud.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse QUIC.cloud JSON", "error", err)

		return providerResult{text: simplifyError(err, quiccloud.ProviderName, ip)}
	}

	table := createQuicCloudTable(ip, &result, false)

	return providerResult{table: table}
}

func createQuicCloudTable(ip string, result *quiccloud.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " QUIC.cloud | Host: " + ip
	if isActive {
		headerText = " ▶ QUIC.cloud | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in QUIC.cloud ranges").
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
