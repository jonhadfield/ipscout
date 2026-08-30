package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/stripe"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchStripe(ip string, sess *session.Session) providerResult {
	slog.Debug("Fetching data from Stripe", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Stripe", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "stripe", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run stripe")

	res, err := processor.Run(stripe.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Stripe", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "stripe", ip)}
	}

	slog.Debug("fetched data from Stripe", "ip", ip)

	var stripeResult stripe.HostSearchResult
	if err := json.Unmarshal([]byte(res), &stripeResult); err != nil {
		slog.Error("Failed to parse Stripe JSON", "error", err)

		return providerResult{text: simplifyError(err, "stripe", ip)}
	}

	table := createStripeTable(ip, &stripeResult, false)

	return providerResult{table: table}
}

func createStripeTable(ip string, result *stripe.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	headerText := " Stripe | Host: " + ip
	if isActive {
		headerText = " ▶ Stripe | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	if !result.Prefix.IsValid() {
		table.SetCell(row, 0, tview.NewTableCell(" IP not in Stripe ranges").
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

	return table
}
