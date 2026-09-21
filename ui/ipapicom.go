package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/ipapicom"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchIPAPICom(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from ip-api.com", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for ip-api.com", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ipapicom.ProviderName, ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run ipapicom")

	res, err := processor.Run(ipapicom.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from ip-api.com", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, ipapicom.ProviderName, ip)}
	}

	slog.Debug("fetched data from ip-api.com", "ip", ip)

	var result ipapicom.HostSearchResult
	if err := json.Unmarshal([]byte(res), &result); err != nil {
		slog.Error("Failed to parse ip-api.com JSON", "error", err)

		return providerResult{text: simplifyError(err, ipapicom.ProviderName, ip)}
	}

	table := createIPAPIComTable(ip, &result, false)

	return providerResult{table: table}
}

func createIPAPIComTable(ip string, result *ipapicom.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " ip-api.com | Host: " + ip
	if isActive {
		headerText = " ▶ ip-api.com | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	rows := []struct{ label, value string }{
		{" Country", result.Country},
		{" Region", result.RegionName},
		{" City", result.City},
		{" Postal", result.Zip},
		{" Timezone", result.Timezone},
		{" ISP", result.ISP},
		{" Organisation", result.Org},
		{" AS", result.AS},
		{" Reverse DNS", result.Reverse},
	}

	for _, r := range rows {
		if r.value == "" {
			continue
		}

		table.SetCell(row, 0, tview.NewTableCell(r.label).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(r.value).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	flags := []struct {
		label string
		set   bool
	}{
		{" Proxy/VPN/Tor", result.Proxy},
		{" Hosting", result.Hosting},
		{" Mobile", result.Mobile},
	}

	for _, f := range flags {
		value, colour := "no", tcell.ColorWhite
		if f.set {
			value, colour = "yes", tcell.ColorYellow
		}

		table.SetCell(row, 0, tview.NewTableCell(f.label).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(value).
			SetTextColor(colour).
			SetSelectable(false))

		row++
	}

	return table
}
