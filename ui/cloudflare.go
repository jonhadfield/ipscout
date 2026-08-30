package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/cloudflare"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCloudflare(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Cloudflare", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Cloudflare", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "cloudflare", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run cloudflare")

	res, err := processor.Run(cloudflare.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Cloudflare", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "cloudflare", ip)}
	}

	slog.Debug("fetched data from Cloudflare", "ip", ip)

	var cloudflareResult cloudflare.HostSearchResult
	if err := json.Unmarshal([]byte(res), &cloudflareResult); err != nil {
		slog.Error("Failed to parse Cloudflare JSON", "error", err)

		return providerResult{text: simplifyError(err, "cloudflare", ip)}
	}

	table := createCloudflareTable(ip, &cloudflareResult, false)

	return providerResult{table: table}
}

func createCloudflareTable(ip string, result *cloudflare.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Cloudflare | Host: " + ip
	if isActive {
		headerText = " ▶ Cloudflare | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Cloudflare prefix found").
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

	row++

	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Hosted by Cloudflare").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
