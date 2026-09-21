package ui

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/internetdb"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchInternetDB(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from InternetDB", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for InternetDB", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, internetdb.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run internetdb")

	res, err := processor.Run(internetdb.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from InternetDB", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, internetdb.ProviderName, ip)}
	}

	slog.Debug("fetched data from InternetDB", "ip", ip)

	var result internetdb.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse InternetDB JSON", "error", err)

		return providerResult{text: simplifyError(err, internetdb.ProviderName, ip)}
	}

	table := createInternetDBTable(ip, &result, false)

	return providerResult{table: table}
}

func createInternetDBTable(ip string, result *internetdb.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " InternetDB | Host: " + ip
	if isActive {
		headerText = " ▶ InternetDB | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	ports := make([]string, 0, len(result.Ports))
	for _, p := range result.Ports {
		ports = append(ports, strconv.Itoa(p))
	}

	rows := []struct {
		label  string
		value  string
		colour tcell.Color
	}{
		{" Open Ports", strings.Join(ports, ", "), tcell.ColorWhite},
		{" Hostnames", strings.Join(result.Hostnames, ", "), tcell.ColorWhite},
		{" Tags", strings.Join(result.Tags, ", "), tcell.ColorYellow},
		{" Software", strings.Join(result.CPEs, ", "), tcell.ColorWhite},
		{" Vulns", strings.Join(result.Vulns, ", "), tcell.ColorRed},
	}

	var shown bool

	for _, r := range rows {
		if r.value == "" {
			continue
		}

		table.SetCell(row, 0, tview.NewTableCell(r.label).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(r.value).
			SetTextColor(r.colour).
			SetSelectable(false))

		row++

		shown = true
	}

	if !shown {
		table.SetCell(row, 0, tview.NewTableCell(" No InternetDB data for this IP").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))
	}

	return table
}
