package ui

import (
	"encoding/json"
	"log/slog"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/dshield"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchDShield(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from DShield", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for DShield", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, dshield.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run dshield")

	res, err := processor.Run(dshield.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from DShield", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, dshield.ProviderName, ip)}
	}

	slog.Debug("fetched data from DShield", "ip", ip)

	var dshieldResult dshield.HostSearchResult
	if err := json.Unmarshal([]byte(res), &dshieldResult); err != nil {
		slog.Error("Failed to parse DShield JSON", "error", err)

		return providerResult{text: simplifyError(err, dshield.ProviderName, ip)}
	}

	table := createDShieldTable(ip, &dshieldResult, false)

	return providerResult{table: table}
}

func createDShieldTable(ip string, result *dshield.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " DShield | Host: " + ip
	if isActive {
		headerText = " ▶ DShield | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No DShield prefix found").
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

	table.SetCell(row, 0, tview.NewTableCell(" Attacks").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Attacks)).
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	row++

	if result.Name != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Network Name").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Name).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Country != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Country").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Country).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Email != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Abuse Contact").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Email).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if !result.Updated.IsZero() {
		table.SetCell(row, 0, tview.NewTableCell(" Updated").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Updated.String()).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
