package process

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/noodle/config"
	"github.com/jonhadfield/noodle/present"
	"github.com/jonhadfield/noodle/providers/criminalip"
	"github.com/jonhadfield/noodle/providers/shodan"
	"os"
)

type TableClient interface {
	CreateTable() (*table.Writer, error)
}

func genRunners(config *Config) (map[string]TableClient, error) {
	runners := make(map[string]TableClient)

	if config.Shodan.APIKey != "" || config.UseTestData {
		shodanConfig := shodan.Config{
			Default: config.Default,
			Host:    config.Host,
			APIKey:  config.Shodan.APIKey,
		}

		shodanClient, err := shodan.NewTableClient(shodanConfig)
		if err != nil {
			return nil, err
		}

		runners["shodan"] = shodanClient
	}

	if config.CriminalIP.APIKey != "" || config.UseTestData {
		criminalIPConfig := criminalip.Config{
			Default: config.Default,
			Host:    config.Host,
			APIKey:  config.CriminalIP.APIKey,
		}
		criminalIPClient, err := criminalip.NewTableClient(criminalIPConfig)
		if err != nil {
			return nil, err
		}

		if criminalIPClient != nil {
			runners["criminalip"] = criminalIPClient
		}
	}

	return runners, nil
}

type Config struct {
	config.Default
	Shodan     shodan.Config
	CriminalIP criminalip.Config
}

type Processor struct {
	Config *Config
}

func (p *Processor) Run() {
	runners, err := genRunners(p.Config)
	if err != nil {
		fmt.Printf("error generating runners: %v", err)
		os.Exit(1)
	}

	tables, err := generateTables(runners)
	if err != nil {
		fmt.Printf("error generating tables: %v", err)
		os.Exit(1)
	}
	// present data
	if err = present.Tables(tables); err != nil {
		fmt.Printf("error presenting tables: %v", err)
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

	p.Config.Default = config.Default

	return p, nil
}
