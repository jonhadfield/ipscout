package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/iptoasn"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIPToASN(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from IPtoASN", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for IPtoASN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "iptoasn", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run iptoasn")

	res, err := processor.Run(iptoasn.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from IPtoASN", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "iptoasn", ip)}
	}

	slog.Debug("fetched data from IPtoASN", "ip", ip)

	var iptoasnResult iptoasn.HostSearchResult
	if err := json.Unmarshal([]byte(res), &iptoasnResult); err != nil {
		slog.Error("Failed to parse IPtoASN JSON", "error", err)

		return providerResult{text: simplifyError(err, "iptoasn", ip)}
	}

	table := createIPToASNTable(ip, &iptoasnResult, false)

	return providerResult{table: table}
}

func createIPToASNTable(ip string, result *iptoasn.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " IPtoASN | Host: " + ip
	if isActive {
		headerText = " ▶ IPtoASN | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Announced {
		table.SetCell(row, 0, tview.NewTableCell(" IP not announced by any AS").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" ASN").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("AS%d", result.ASNumber)).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if result.ASDescription != "" {
		table.SetCell(row, 0, tview.NewTableCell(" AS Name").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.ASDescription).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	if result.ASCountryCode != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Country").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.ASCountryCode).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.FirstIP != "" && result.LastIP != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Range").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.FirstIP+" - "+result.LastIP).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
