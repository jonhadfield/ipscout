package ui

import (
	"encoding/json"
	"log/slog"

	"github.com/gdamore/tcell/v2"
	"github.com/jonhadfield/ipscout/helpers"
	"github.com/jonhadfield/ipscout/providers/azurewaf"
	"github.com/jonhadfield/ipscout/session"
	"github.com/rivo/tview"
)

func fetchAzureWAF(ip string, sess *session.Session) providerResult { // nolint:dupl
	slog.Info("Fetching data from Azure WAF", "ip", ip)

	var err error

	sess.Host, err = helpers.ParseHost(ip)
	if err != nil {
		slog.Error("Error parsing host for Azure WAF", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "azurewaf", ip)}
	}

	processor := New(sess)
	sess.Logger.Debug("processor.Run azurewaf")

	res, err := processor.Run(azurewaf.ProviderName)
	if err != nil {
		slog.Error("Error fetching data from Azure WAF", "ip", ip, "error", err)

		return providerResult{text: simplifyError(err, "azurewaf", ip)}
	}

	slog.Info("Fetching data from Azure WAF", "ip", ip)

	// Parse Azure WAF JSON response
	var azureWAFResult azurewaf.HostSearchResult
	if err := json.Unmarshal([]byte(res), &azureWAFResult); err != nil {
		slog.Error("Failed to parse Azure WAF JSON", "error", err)

		return providerResult{text: simplifyError(err, "azurewaf", ip)}
	}

	// Create tview table without arrow (arrow will be added at display time if active)
	table := createAzureWAFTable(ip, &azureWAFResult, false)

	return providerResult{table: table}
}

func createAzureWAFTable(ip string, result *azurewaf.HostSearchResult, isActive bool) *tview.Table {
	table := tview.NewTable()
	table.SetBorder(false)
	table.SetBackgroundColor(tcell.ColorBlack)

	row := 0

	// Header with active indicator
	headerText := " Azure WAF | Host: " + ip
	if isActive {
		headerText = " ▶ Azure WAF | Host: " + ip
	}

	table.SetCell(row, 0, tview.NewTableCell(headerText).
		SetTextColor(tcell.ColorLightCyan).
		SetSelectable(false))

	row++

	// Check if we have policy matches
	if len(result.PolicyMatches) == 0 {
		table.SetCell(row, 0, tview.NewTableCell(" No Azure WAF policy matches found").
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false))

		return table
	}

	// Display policy matches
	for _, policyMatch := range result.PolicyMatches {
		table.SetCell(row, 0, tview.NewTableCell(" Policy").
			SetTextColor(tcell.ColorWhite).
			SetSelectable(false))
		table.SetCell(row, 1, tview.NewTableCell(policyMatch.RID.Name).
			SetTextColor(tcell.ColorLightCyan).
			SetSelectable(false))

		row++

		if policyMatch.RID.SubscriptionID != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Subscription ID").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(policyMatch.RID.SubscriptionID).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		if policyMatch.RID.ResourceGroup != "" {
			table.SetCell(row, 0, tview.NewTableCell("   - Resource Group").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(policyMatch.RID.ResourceGroup).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++
		}

		// Display custom rule matches
		for _, customRule := range policyMatch.CustomRuleMatches {
			table.SetCell(row, 0, tview.NewTableCell("   - Rule").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(customRule.RuleName).
				SetTextColor(tcell.ColorLightCyan).
				SetSelectable(false))

			row++

			table.SetCell(row, 0, tview.NewTableCell("     - Action").
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))
			table.SetCell(row, 1, tview.NewTableCell(customRule.Action).
				SetTextColor(tcell.ColorWhite).
				SetSelectable(false))

			row++

			for _, prefix := range customRule.Prefixes {
				table.SetCell(row, 0, tview.NewTableCell("     - Prefix").
					SetTextColor(tcell.ColorWhite).
					SetSelectable(false))
				table.SetCell(row, 1, tview.NewTableCell(prefix.String()).
					SetTextColor(tcell.ColorLightCyan).
					SetSelectable(false))

				row++
			}
		}
	}

	// Status
	table.SetCell(row, 0, tview.NewTableCell(" Status").
		SetTextColor(tcell.ColorWhite).
		SetSelectable(false))
	table.SetCell(row, 1, tview.NewTableCell("Azure WAF Match").
		SetTextColor(tcell.ColorBlue).
		SetSelectable(false))

	return table
}
