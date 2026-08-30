package ui

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/oci"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchOCI(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from OCI", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for OCI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "oci", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run oci")

	res, err := processor.Run(oci.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from OCI", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "oci", ip)}
	}

	slog.Debug("fetched data from OCI", "ip", ip)

	var ociResult oci.HostSearchResult
	if err := json.Unmarshal([]byte(res), &ociResult); err != nil {
		slog.Error("Failed to parse OCI JSON", "error", err)

		return providerResult{text: simplifyError(err, "oci", ip)}
	}

	table := createOCITable(ip, &ociResult, false)

	return providerResult{table: table}
}

func createOCITable(ip string, result *oci.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Oracle Cloud (OCI) | Host: " + ip
	if isActive {
		headerText = " ▶ Oracle Cloud (OCI) | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" No matching Oracle Cloud (OCI) prefix").
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

	if result.Region != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Region").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(result.Region).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	if len(result.Tags) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Tags").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strings.Join(result.Tags, ", ")).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
	}

	return table
}
