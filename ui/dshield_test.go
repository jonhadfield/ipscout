package ui

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/providers/dshield"
	"github.com/stretchr/testify/require"
)

const (
	testIPDShield      = "198.51.100.42"
	testPrefixDShield  = "198.51.100.0/24"
	testAttacksDShield = 4096
	testNameDShield    = "EXAMPLE-NET"
	testCountryDShield = "ZZ"
	testEmailDShield   = "abuse@example.com"
	testHeaderDShield  = " DShield | Host: "
)

func TestCreateDShieldTable(t *testing.T) {
	updated := time.Date(2026, 8, 20, 14, 0, 24, 0, time.UTC)

	result := &dshield.HostSearchResult{
		Prefix:  netip.MustParsePrefix(testPrefixDShield),
		Attacks: testAttacksDShield,
		Name:    testNameDShield,
		Country: testCountryDShield,
		Email:   testEmailDShield,
		Updated: updated,
	}

	table := createDShieldTable(testIPDShield, result, false)
	require.NotNil(t, table)
	require.NotZero(t, table.GetRowCount())

	require.Equal(t, testHeaderDShield+testIPDShield, table.GetCell(0, 0).Text)
	require.Equal(t, " Prefix", table.GetCell(1, 0).Text)
	require.Equal(t, testPrefixDShield, table.GetCell(1, 1).Text)
	require.Equal(t, " Attacks", table.GetCell(2, 0).Text)
	require.Equal(t, "4096", table.GetCell(2, 1).Text)
	require.Equal(t, " Network Name", table.GetCell(3, 0).Text)
	require.Equal(t, testNameDShield, table.GetCell(3, 1).Text)
	require.Equal(t, " Country", table.GetCell(4, 0).Text)
	require.Equal(t, testCountryDShield, table.GetCell(4, 1).Text)
	require.Equal(t, " Abuse Contact", table.GetCell(5, 0).Text)
	require.Equal(t, testEmailDShield, table.GetCell(5, 1).Text)
	require.Equal(t, " Updated", table.GetCell(6, 0).Text)
	require.Equal(t, updated.String(), table.GetCell(6, 1).Text)
}

func TestCreateDShieldTableOptionalFieldsOmitted(t *testing.T) {
	result := &dshield.HostSearchResult{
		Prefix:  netip.MustParsePrefix(testPrefixDShield),
		Attacks: testAttacksDShield,
	}

	table := createDShieldTable(testIPDShield, result, false)
	require.NotNil(t, table)

	require.Equal(t, " Attacks", table.GetCell(2, 0).Text)
	require.Empty(t, table.GetCell(3, 0).Text)
}

func TestCreateDShieldTableActiveHeader(t *testing.T) {
	table := createDShieldTable(testIPDShield, &dshield.HostSearchResult{}, true)
	require.NotNil(t, table)

	require.Equal(t, " ▶ DShield | Host: "+testIPDShield, table.GetCell(0, 0).Text)
}

func TestCreateDShieldTableNoMatch(t *testing.T) {
	table := createDShieldTable(testIPDShield, &dshield.HostSearchResult{}, false)
	require.NotNil(t, table)

	require.Equal(t, testHeaderDShield+testIPDShield, table.GetCell(0, 0).Text)
	require.Equal(t, " No DShield prefix found", table.GetCell(1, 0).Text)
}
