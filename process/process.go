package process

import (
	"fmt"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/providers/azure"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/digitalocean"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/sync/errgroup"
)

type ProviderClient interface {
	Enabled() bool
	GetConfig() *config.Config
	Initialise() error
	FindHost() ([]byte, error)
	CreateTable([]byte) (*table.Writer, error)
}

func getProviderClients(c config.Config) (map[string]ProviderClient, error) {
	runners := make(map[string]ProviderClient)
	c.Logger.Info("creating provider clients")

	if c.Providers.AbuseIPDB.APIKey != "" || c.Providers.AbuseIPDB.Enabled || c.UseTestData {
		AbuseIPDBClient, err := abuseipdb.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating abuseipdb client: %w", err)
		}

		if AbuseIPDBClient != nil {
			runners[abuseipdb.ProviderName] = AbuseIPDBClient
		}
	}

	if len(c.Providers.Annotated.Paths) > 0 || c.Providers.Annotated.Enabled || c.UseTestData {
		AnnotatedClient, err := annotated.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating abuseipdb client: %w", err)
		}

		if AnnotatedClient != nil {
			runners[abuseipdb.ProviderName] = AnnotatedClient
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

	if c.Providers.Azure.Enabled || c.UseTestData {
		azureIPClient, err := azure.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating azure client: %w", err)
		}

		if azureIPClient != nil {
			runners[azure.ProviderName] = azureIPClient
		}
	}

	if c.Providers.CriminalIP.APIKey != "" || c.Providers.CriminalIP.Enabled || c.UseTestData {
		criminalIPClient, err := criminalip.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating criminalip client: %w", err)
		}

		if criminalIPClient != nil {
			runners[criminalip.ProviderName] = criminalIPClient
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

	if c.Providers.IPURL.Enabled || c.UseTestData {
		IPURLClient, err := ipurl.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating ipurl client: %w", err)
		}

		if IPURLClient != nil {
			runners[ipurl.ProviderName] = IPURLClient
		}
	}

	if c.Providers.Shodan.APIKey != "" || c.Providers.Shodan.Enabled || c.UseTestData {
		shodanClient, err := shodan.NewProviderClient(c)
		if err != nil {
			return nil, fmt.Errorf("error creating shodan client: %w", err)
		}

		runners[shodan.ProviderName] = shodanClient
	}

	return runners, nil
}

func getEnabledProviders(runners map[string]ProviderClient) []string {
	keys := make([]string, len(runners))

	i := 0
	for k := range runners {
		keys[i] = k
		i++
	}

	return keys
}

type Config struct {
	config.Config
	Shodan     shodan.Config
	CriminalIP criminalip.Config
	IPURL      ipurl.Config
}

type Processor struct {
	Config *config.Config
}

func (p *Processor) Run() {
	homeDir, err := homedir.Dir()
	if err != nil {
		p.Config.Logger.Error("failed to get home directory", "error", err)

		os.Exit(1)
	}

	db, err := cache.Create(p.Config.Logger, filepath.Join(homeDir, ".config", "ipscout"))
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

	enabledProviders := getEnabledProviders(providerClients)

	// initialise providers
	err = initialiseProviders(providerClients, p.Config.HideProgress)
	if err != nil {
		p.Config.Logger.Error("failed to initialise providers", "error", err)

		os.Exit(1)
	}

	if strings.EqualFold(p.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Config.Stats.InitialiseDuration {
			p.Config.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	// find hosts
	results, err := findHosts(providerClients, p.Config.HideProgress)
	if err != nil {
		p.Config.Logger.Error("failed to find hosts", "error", err)

		os.Exit(1)
	}

	if strings.EqualFold(p.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Config.Stats.FindHostDuration {
			p.Config.Logger.Debug("find hosts timing", "provider", provider, "duration", dur.String())
		}

		for provider, uc := range p.Config.Stats.FindHostUsedCache {
			p.Config.Logger.Debug("find hosts data load", "provider", provider, "cache", uc)
		}
	}

	results.RLock()
	matchingResults := len(results.m)
	results.RUnlock()

	p.Config.Logger.Info("host matching results", "providers queried", len(providerClients), "matching results", matchingResults)
	if matchingResults == 0 {
		p.Config.Logger.Warn("no results found", "host", p.Config.Host.String(), "providers checked", strings.Join(enabledProviders, ", "))

		return
	}

	tables, err := generateTables(p.Config, providerClients, results)
	if err != nil {
		p.Config.Logger.Error("failed to generate tables", "error", err)

		os.Exit(1)
	}

	if strings.EqualFold(p.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Config.Stats.CreateTableDuration {
			p.Config.Logger.Debug("create tables timing", "provider", provider, "duration", dur.String())
		}
	}

	// present data
	if err = present.Tables(p.Config, tables); err != nil {
		p.Config.Logger.Error("failed to present tables", "error", err)
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
			iErr := runner.Initialise()
			if iErr != nil {
				return iErr
			}

			return nil
		})
	}

	if err = g.Wait(); err != nil {
		return nil
	}
	// allow time to output spinner
	time.Sleep(50 * time.Millisecond)

	return nil
}

type findHostsResults struct {
	sync.RWMutex
	m map[string][]byte
}

type generateTablesResults struct {
	sync.RWMutex
	m []*table.Writer
}

func findHosts(runners map[string]ProviderClient, hideProgress bool) (*findHostsResults, error) {
	var results findHostsResults
	results.Lock()
	results.m = make(map[string][]byte)
	results.Unlock()

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
			if err != nil {
				runner.GetConfig().Logger.Debug(err.Error())
				return
			}

			if result != nil {
				results.Lock()
				results.m[name] = result
				results.Unlock()
			}
		}()
	}

	w.Wait()
	// allow time to output spinner
	time.Sleep(50 * time.Millisecond)

	return &results, nil
}

func generateTables(conf *config.Config, runners map[string]ProviderClient, results *findHostsResults) ([]*table.Writer, error) {
	var tables generateTablesResults

	var w sync.WaitGroup
	if !conf.HideProgress {
		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriterFile(conf.Output))
		s.Start() // Start the spinner

		s.Suffix = " generating output..."

		defer s.Stop()
	}

	for name, runner := range runners {
		name, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines
		w.Add(1)
		go func() {
			defer w.Done()
			results.RLock()
			if results.m[name] == nil {
				return
			}

			createTableData := results.m[name]
			results.RUnlock()

			tbl, err := runner.CreateTable(createTableData)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}

			// fmt.Println(tbl, err)

			if tbl != nil {
				tables.RWMutex.Lock()
				tables.m = append(tables.m, tbl)
				tables.RWMutex.Unlock()
			}
		}()
	}

	w.Wait()
	// allow time to output spinner
	time.Sleep(50 * time.Millisecond)

	return tables.m, nil
}

func New(config *config.Config) (Processor, error) {
	p := Processor{
		Config: config,
	}

	return p, nil
}
