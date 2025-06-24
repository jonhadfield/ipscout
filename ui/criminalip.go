package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchCriminalIP(ip string, sess *session.Session) providerResult {
	slog.Info("Fetching data from CriminalIP", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for CriminalIP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "criminalip", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run criminalip")

	res, err := processor.Run(criminalip.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from CriminalIP", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "criminalip", ip)}
	}

	var criminalIPResult criminalip.HostSearchResult
	if err := json.Unmarshal([]byte(res), &criminalIPResult); err != nil {
		slog.Error("Failed to parse CriminalIP JSON", "error", err)

		return providerResult{text: simplifyError(err, "criminalip", ip)}
	}

	table := createCriminalIPTable(ip, &criminalIPResult, false)

	return providerResult{table: table}
}

func createCriminalIPTable(ip string, result *criminalip.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " CriminalIP | Host: " + ip
	if isActive {
		headerText = " ▶ CriminalIP | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if result.Score.Inbound != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Inbound Score").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		table.SetCell(row, 1, tview.NewTableCell(result.Score.Inbound).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	if result.Score.Outbound != "" {
		table.SetCell(row, 0, tview.NewTableCell(" Outbound Score").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		table.SetCell(row, 1, tview.NewTableCell(result.Score.Outbound).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++
	}

	var issues []string
	if result.Issues.IsVpn {
		issues = append(issues, "VPN")
	}

	if result.Issues.IsCloud {
		issues = append(issues, "Cloud")
	}
	if result.Issues.IsTor {
		issues = append(issues, "Tor")
	}
	if result.Issues.IsProxy {
		issues = append(issues, "Proxy")
	}
	if result.Issues.IsHosting {
		issues = append(issues, "Hosting")
	}

	if result.Issues.IsScanner {
		issues = append(issues, "Scanner")
	}
	if result.Issues.IsAnonymousVpn {
		issues = append(issues, "Anonymous VPN")
	}

	if len(issues) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Issues").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(strings.Join(issues, ", ")).
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		row++
	}

	if len(result.Honeypot.Data) > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Honeypot Attacks").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d attacks", len(result.Honeypot.Data))).
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		row++
	}

	if result.Port.Count > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Open Ports").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d ports", result.Port.Count)).
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))

		row++
	}

	if result.Vulnerability.Count > 0 {
		table.SetCell(row, 0, tview.NewTableCell(" Vulnerabilities").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d vulnerabilities", result.Vulnerability.Count)).
			SetTextColor(tcell.ColorRed).
			SetSelectable(false))

		row++
	}

	if len(issues) == 0 && result.Score.Inbound == "" && result.Score.Outbound == "" {
		table.SetCell(row, 0, tview.NewTableCell(" No threat indicators found").
			SetTextColor(tcell.ColorGreen).
			SetSelectable(false))

		return table
	}

	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))

	statusColor := tcell.ColorGreen
	statusText := "Clean"

	if len(issues) > 0 || result.Score.Inbound != "" || result.Score.Outbound != "" {
		statusColor = tcell.ColorRed
		statusText = "Threats Detected"
	}

	table.SetCell(row, 1, tview.NewTableCell(statusText).
		SetTextColor(statusColor).
		SetSelectable(false))

	return table
}
