package process

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/noodle/present"
	"github.com/jonhadfield/noodle/shodan"
	"net/netip"
	"os"
)

type TableClient interface {
	CreateTable() (*table.Writer, error)
}

func genRunners(config *Config) (map[string]TableClient, error) {
	runners := make(map[string]TableClient)

	// only returns errors on initialisation if provided information is invalid
	// returns nil runner if not defined
	shodanClient, err := shodan.NewTableClient(config.Shodan)
	if err != nil {
		return nil, err
	}

	if shodanClient != nil {
		runners["shodan"] = shodanClient
	}

	if shodanClient != nil {
		runners["shodan"] = shodanClient
	}

	return runners, nil
}

type Config struct {
	UseTestData bool
	Host        netip.Addr
	Shodan      shodan.Config
}

type Processor struct {
	Config *Config
}

func (p *Processor) Run() {
	runners, err := genRunners(p.Config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tables, err := generateTables(runners)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// present data
	if err = present.Tables(tables); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func generateTables(runners map[string]TableClient) ([]*table.Writer, error) {
	var tables []*table.Writer

	for _, runner := range runners {
		tbl, err := runner.CreateTable()
		if err != nil {
			return nil, err
		}

		tables = append(tables, tbl)
	}

	return tables, nil

}

func New(config *Config) (Processor, error) {
	p := Processor{
		Config: config,
	}
	return p, nil
}
