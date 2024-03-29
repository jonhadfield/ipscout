package process

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/noodle/config"
	"github.com/jonhadfield/noodle/present"
	"github.com/jonhadfield/noodle/providers/criminalip"
	"github.com/jonhadfield/noodle/providers/shodan"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	"os"
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

	generate := func(ctx context.Context) ([]*table.Writer, error) {
		g, _ := errgroup.WithContext(ctx)

		results := make([]*table.Writer, len(runners))

		var x int

		for name, runner := range runners {
			_, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines
			g.Go(func() error {
				result, err := runner.CreateTable()
				if err == nil {
					results[x] = result
				}

				x++

				return err
			})
		}

		if err := g.Wait(); err != nil {
			return nil, err
		}

		return results, nil
	}

	results, err := generate(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}
	for _, result := range results {
		tables = append(tables, result)
	}

	// for _, runner := range runners {
	// 	tbl, err := runner.CreateTable()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	//
	// 	tables = append(tables, tbl)
	// }

	return tables, nil

}

func New(config *config.Config) (Processor, error) {
	p := Processor{
		Config: config,
	}

	return p, nil
}
