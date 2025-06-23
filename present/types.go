package present

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/shodan"
)

// CombinedData is used to aggregate results from multiple providers.
type CombinedData struct {
	Shodan     shodan.HostSearchResult
	CriminalIP criminalip.HostSearchResult
}

// Resulter defines types that can produce a table representation.
type Resulter interface {
	CreateTable() *table.Writer
}
