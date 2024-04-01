package process

import (
	"errors"
	"fmt"
	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/present"
	"github.com/jonhadfield/crosscheck-ip/providers"
	"github.com/jonhadfield/crosscheck-ip/providers/aws"
	"github.com/jonhadfield/crosscheck-ip/providers/criminalip"
	"github.com/jonhadfield/crosscheck-ip/providers/digitalocean"
	"github.com/jonhadfield/crosscheck-ip/providers/shodan"
	"golang.org/x/sync/errgroup"
	"os"
	"sync"
	"time"
)

type ProviderClient interface {
	Initialise() error
	FindHost() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

func getProviderClients(c config.Config) (map[string]ProviderClient, error) {
	runners := make(map[string]ProviderClient)
	c.Logger.Info("creating provider clients")
	if c.Providers.Shodan.APIKey != "" || c.UseTestData {
		c.Logger.Info("creating shodan client")
		shodanClient, err := shodan.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating shodan client: %w", err)
		}

		runners[shodan.ProviderName] = shodanClient
	}

	if c.Providers.CriminalIP.APIKey != "" || c.UseTestData {
		criminalIPClient, err := criminalip.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating criminalip client: %w", err)
		}

		if criminalIPClient != nil {
			runners[criminalip.ProviderName] = criminalIPClient
		}
	}

	if c.Providers.AWS.Enabled || c.UseTestData {
		awsIPClient, err := aws.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating aws client: %w", err)
		}

		if awsIPClient != nil {
			runners[aws.ProviderName] = awsIPClient
		}
	}

	if c.Providers.DigitalOcean.Enabled || c.UseTestData {
		digitaloceanIPClient, err := digitalocean.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating digitalocean client: %w", err)
		}

		if digitaloceanIPClient != nil {
			runners[digitalocean.ProviderName] = digitaloceanIPClient
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
	db, err := cache.Create()
	if err != nil {
		p.Config.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	p.Config.Cache = db

	defer db.Close()

	// get provider clients
	providerClients, err := getProviderClients(*p.Config)
	if err != nil {
		p.Config.Logger.Error("failed to generate provider clients", "error", err)

		os.Exit(1)
	}

	// initialise providers
	err = initialiseProviders(providerClients, p.Config.HideProgress)
	if err != nil {
		p.Config.Logger.Error("failed to initialise providers", "error", err)

		os.Exit(1)
	}

	// generate tables
	results, err := findHosts(providerClients, p.Config.HideProgress)
	if err != nil {
		p.Config.Logger.Error("failed to find hosts", "error", err)

		os.Exit(1)
	}

	p.Config.Logger.Info("host matching results", "providers queried", len(providerClients), "matching results", len(results))

	tables, err := generateTables(providerClients, results, p.Config.HideProgress)
	if err != nil {
		p.Config.Logger.Error("failed to generate tables", "error", err)

		os.Exit(1)
	}

	// fmt.Printf("generated %d result tables\n", len(results))

	// present data
	if err = present.Tables(tables); err != nil {
		fmt.Printf("error presenting tables: %v", err)
		os.Exit(1)
	}
}

func initialiseProviders(runners map[string]ProviderClient, hideProgress bool) error {
	var err error

	var g errgroup.Group

	if !hideProgress {
		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
		s.Start() // Start the spinner
		// time.Sleep(4 * time.Second) // Run for some time to simulate work
		s.Suffix = " initialising providers..."

		defer s.Stop()
	}
	for name, runner := range runners {
		_, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			err = runner.Initialise()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}

			return nil
		})
	}

	if err = g.Wait(); err != nil {
		return nil
	}
	// allow time to output spinner
	time.Sleep(100 * time.Millisecond)

	return nil
}

func findHosts(runners map[string]ProviderClient, hideProgress bool) (map[string][]byte, error) {
	results := make(map[string][]byte)

	var w sync.WaitGroup

	if !hideProgress {
		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
		s.Start() // Start the spinner
		// time.Sleep(4 * time.Second) // Run for some time to simulate work
		s.Suffix = " searching providers..."

		defer s.Stop()
	}

	for name, runner := range runners {
		name, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines
		w.Add(1)
		go func() {
			defer w.Done()

			result, err := runner.FindHost()
			if err != nil && !errors.Is(err, providers.ErrNoMatchFound) {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			if result != nil {
				// fmt.Printf("found result for %s\n", name)
				results[name] = result
			}
		}()
	}

	w.Wait()
	// allow time to output spinner
	time.Sleep(100 * time.Millisecond)

	return results, nil
}

func generateTables(runners map[string]ProviderClient, results map[string][]byte, hideProgress bool) ([]*table.Writer, error) {
	if len(results) == 0 {
		panic("oops")
	}
	var tables []*table.Writer

	var w sync.WaitGroup

	if !hideProgress {
		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
		s.Start() // Start the spinner
		// time.Sleep(4 * time.Second) // Run for some time to simulate work
		s.Suffix = " generating output..."

		defer s.Stop()
	}

	for name, runner := range runners {
		name, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines
		w.Add(1)
		go func() {
			defer w.Done()
			// fmt.Printf("data is: %s\n", results[name])
			if results[name] == nil {
				// fmt.Printf("skipping %s as no data returned\n", name)
				return
			}

			// fmt.Printf("generating table for %s with data: %d\n", name, len(results[name]))
			tbl, err := runner.CreateTable(results[name])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			if tbl != nil {
				tables = append(tables, tbl)
			}
		}()
	}

	w.Wait()
	// allow time to output spinner
	time.Sleep(100 * time.Millisecond)

	return tables, nil
}

func New(config *config.Config) (Processor, error) {
	p := Processor{
		Config: config,
	}

	return p, nil
}
