package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/akamai"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAkamai(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Akamai", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Akamai", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "akamai", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run akamai")

	res, err := processor.Run(akamai.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Akamai", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "akamai", ip)}
	}

	slog.Debug("fetched data from Akamai", "ip", ip)

	var akamaiResult akamai.HostSearchResult
	if err := json.Unmarshal([]byte(res), &akamaiResult); err != nil {
		slog.Error("Failed to parse Akamai JSON", "error", err)

		return providerResult{text: simplifyError(err, "akamai", ip)}
	}

	table := createAkamaiTable(ip, &akamaiResult, false)

	return providerResult{table: table}
}

func createAkamaiTable(ip string, result *akamai.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Akamai | Host: " + ip
	if isActive {
		headerText = " ▶ Akamai | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No Akamai range found").
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
	table.SetCell(row, 1, tview.NewTableCell("Akamai CDN").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
