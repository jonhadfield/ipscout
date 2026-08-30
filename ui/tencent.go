package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/tencent"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchTencent(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Tencent Cloud", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Tencent Cloud", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "tencent", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run tencent")

	res, err := processor.Run(tencent.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Tencent Cloud", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "tencent", ip)}
	}

	slog.Debug("fetched data from Tencent Cloud", "ip", ip)

	var tencentResult tencent.HostSearchResult
	if err := json.Unmarshal([]byte(res), &tencentResult); err != nil {
		slog.Error("Failed to parse Tencent Cloud JSON", "error", err)

		return providerResult{text: simplifyError(err, "tencent", ip)}
	}

	table := createTencentTable(ip, &tencentResult, false)

	return providerResult{table: table}
}

func createTencentTable(ip string, result *tencent.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Tencent Cloud | Host: " + ip
	if isActive {
		headerText = " ▶ Tencent Cloud | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Tencent Cloud ranges").
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
