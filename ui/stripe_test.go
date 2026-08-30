package ui

import (
	"net/netip"
	"testing"

	"github.com/jonhadfield/ipscout/providers/stripe"
	"github.com/stretchr/testify/require"
)

const (
	testIPStripe     = "3.18.12.63"
	testPrefixStripe = "3.18.12.0/24"
)

func TestCreateStripeTable(t *testing.T) {
	result := &stripe.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStripe),
	}

	table := createStripeTable(testIPStripe, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Stripe | Host: "+testIPStripe, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixStripe, table.GetCell(1, 1).Text)
}

func TestCreateStripeTableActiveState(t *testing.T) {
	result := &stripe.HostSearchResult{
		Prefix: netip.MustParsePrefix(testPrefixStripe),
	}

	table := createStripeTable(testIPStripe, result, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ Stripe | Host: "+testIPStripe, table.GetCell(0, 0).Text)
}

func TestCreateStripeTableNoMatch(t *testing.T) {
	// An invalid (zero) prefix means the IP was not found in Stripe ranges.
	table := createStripeTable(testIPExample, &stripe.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, " Stripe | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " IP not in Stripe ranges", table.GetCell(1, 0).Text)
}
