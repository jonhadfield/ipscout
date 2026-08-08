package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/ahrefs"
	"github.com/stretchr/testify/require"
)

const (
	testIPAhrefs     = "54.36.148.1"
	testPrefixAhrefs = "54.36.148.0/23"
	testHeaderAhrefs = " AhrefsBot | Host: "
)

func TestCreateAhrefsTable(t *testing.T) {
	creationTime := time.Date(2024, 11, 14, 0, 0, 0, 0, time.UTC)

	result := &ahrefs.HostSearchResult{
		Prefix:       netip.MustParsePrefix(testPrefixAhrefs),
		CreationTime: creationTime,
	}

	table := createAhrefsTable(testIPAhrefs, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderAhrefs+testIPAhrefs, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixAhrefs, table.GetCell(1, 1).Text)
	require.Equal(t, " Creation Time", table.GetCell(2, 0).Text)
	require.Equal(t, creationTime.String(), table.GetCell(2, 1).Text)
}

func TestCreateAhrefsTableNoMatch(t *testing.T) {
	table := createAhrefsTable(testIPAhrefs, &ahrefs.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderAhrefs+testIPAhrefs, table.GetCell(0, 0).Text)
	require.Equal(t, " No AhrefsBot prefix found", table.GetCell(1, 0).Text)
}
