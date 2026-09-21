package ui

import (
	"testing"

	"github.com/jonhadfield/ipscout/providers/ipapicom"
	"github.com/stretchr/testify/require"
)

func TestCreateIPAPIComTable(t *testing.T) {
	result := &ipapicom.HostSearchResult{
		Status:  "success",
		Country: "United States",
		City:    "Ashburn",
		ISP:     "Google LLC",
		Hosting: true,
	}

	table := createIPAPIComTable(testIPExample, result, false)

	require.NotNil(t, table)
	require.Equal(t, " ip-api.com | Host: "+testIPExample, table.GetCell(0, 0).Text)
	require.Equal(t, " Country", table.GetCell(1, 0).Text)
	require.Equal(t, "United States", table.GetCell(1, 1).Text)
	require.Equal(t, " City", table.GetCell(2, 0).Text)
	require.Equal(t, " ISP", table.GetCell(3, 0).Text)
	// flags always render: proxy, hosting, mobile
	require.Equal(t, " Proxy/VPN/Tor", table.GetCell(4, 0).Text)
	require.Equal(t, "no", table.GetCell(4, 1).Text)
	require.Equal(t, " Hosting", table.GetCell(5, 0).Text)
	require.Equal(t, "yes", table.GetCell(5, 1).Text)
}

func TestCreateIPAPIComTableActiveState(t *testing.T) {
	table := createIPAPIComTable(testIPExample, &ipapicom.HostSearchResult{}, true)

	require.Equal(t, " ▶ ip-api.com | Host: "+testIPExample, table.GetCell(0, 0).Text)
}
