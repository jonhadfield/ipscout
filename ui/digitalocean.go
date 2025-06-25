package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/digitalocean"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchDigitalOcean(ip string, sess *session.Session) providerResult { // nolint:dupl
	slog.Info("Fetching data from DigitalOcean", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for DigitalOcean", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "digitalocean", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run digitalocean")

	res, err := processor.Run(digitalocean.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from DigitalOcean", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "digitalocean", ip)}
	}

	var doResult digitalocean.HostSearchResult
	if err := json.Unmarshal([]byte(res), &doResult); err != nil {
		slog.Error("Failed to parse DigitalOcean JSON", "error", err)

		return providerResult{text: simplifyError(err, "digitalocean", ip)}
	}

	table := createDigitalOceanTable(ip, &doResult, false)

	return providerResult{table: table}
}

func createDigitalOceanTable(ip string, result *digitalocean.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " DigitalOcean | Host: " + ip
	if isActive {
		headerText = " ▶ DigitalOcean | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if result.Record.Network.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" Network").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Record.Network.String()).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		if result.Record.CountryCode != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Country Code").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Record.CountryCode).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Record.CityName != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - City").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Record.CityName).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if result.Record.ZipCode != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Zip Code").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(result.Record.ZipCode).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}
	}

	if !result.Record.Network.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No DigitalOcean network found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("DigitalOcean Service").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
