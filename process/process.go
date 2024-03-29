package process

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/noodle/config"
	"github.com/jonhadfield/noodle/present"
	"github.com/jonhadfield/noodle/providers/criminalip"
	"github.com/jonhadfield/noodle/providers/shodan"
	"os"
	"sync"
)

type TableClient interface {
	CreateTable() (*table.Writer, error)
}

func genRunners(config config.Config) (map[string]TableClient, error) {
	runners := make(map[string]TableClient)

	if config.Providers.Shodan.APIKey != "" || config.UseTestData {
		shodanClient, err := shodan.NewTableClient(config)
		if err != nil {
			return nil, err
		}

		runners["shodan"] = shodanClient
	}

	if config.Providers.CriminalIP.APIKey != "" || config.UseTestData {
		criminalIPClient, err := criminalip.NewTableClient(config)
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
	config.Config
	Shodan     shodan.Config
	CriminalIP criminalip.Config
}

type Processor struct {
	Config *config.Config
}

func (p *Processor) Run() {
	runners, err := genRunners(*p.Config)
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

	var w sync.WaitGroup

	for name, runner := range runners {
		_, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines
		w.Add(1)
		go func() {
			defer w.Done()

			tbl, err := runner.CreateTable()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			tables = append(tables, tbl)
		}()
	}

	w.Wait()

	return tables, nil
}

func New(config *config.Config) (Processor, error) {
	p := Processor{
		Config: config,
	}

	return p, nil
}
