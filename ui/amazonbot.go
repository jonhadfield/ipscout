package ui

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/amazonbot"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAmazonbot(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Amazonbot", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Amazonbot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, amazonbot.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run amazonbot")

	res, err := processor.Run(amazonbot.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Amazonbot", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, amazonbot.ProviderName, ip)}
	}

	slog.Debug("fetched data from Amazonbot", "ip", ip)

	var amazonbotResult amazonbot.HostSearchResult
	if err := json.Unmarshal([]byte(res), &amazonbotResult); err != nil {
		slog.Error("Failed to parse Amazonbot JSON", "error", err)

		return providerResult{text: simplifyError(err, amazonbot.ProviderName, ip)}
	}

	table := createAmazonbotTable(ip, &amazonbotResult, false)

	return providerResult{table: table}
}

func createAmazonbotTable(ip string, result *amazonbot.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Amazonbot | Host: " + ip
	if isActive {
		headerText = " ▶ Amazonbot | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Amazonbot prefix found").
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

	table.SetCell(row, 0, tview.NewTableCell(" Lists").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(strings.Join(result.Lists, ", ")).
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	return table
}
