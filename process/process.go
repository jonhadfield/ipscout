package process

import (
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/ipscout/providers/google"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/jonhadfield/ipscout/providers/googlebot"

	"github.com/jonhadfield/ipscout/providers/ipapi"

	"github.com/jonhadfield/ipscout/providers/icloudpr"

	"github.com/jonhadfield/ipscout/providers/gcp"
	"github.com/jonhadfield/ipscout/providers/linode"

	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/azure"
	"github.com/jonhadfield/ipscout/providers/digitalocean"
	"github.com/jonhadfield/ipscout/providers/ptr"

	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/sync/errgroup"
)

type Provider struct {
	Name      string
	Enabled   *bool
	APIKey    string
	NewClient func(c session.Session) (providers.ProviderClient, error)
}

func getProviderClients(sess session.Session) (map[string]providers.ProviderClient, error) {
	runners := make(map[string]providers.ProviderClient)

	pros := []Provider{
		{Name: abuseipdb.ProviderName, Enabled: sess.Providers.AbuseIPDB.Enabled, APIKey: sess.Providers.AbuseIPDB.APIKey, NewClient: abuseipdb.NewClient},
		{Name: annotated.ProviderName, Enabled: sess.Providers.Annotated.Enabled, APIKey: "", NewClient: annotated.NewProviderClient},
		{Name: aws.ProviderName, Enabled: sess.Providers.AWS.Enabled, APIKey: "", NewClient: aws.NewProviderClient},
		{Name: azure.ProviderName, Enabled: sess.Providers.Azure.Enabled, APIKey: "", NewClient: azure.NewProviderClient},
		{Name: criminalip.ProviderName, Enabled: sess.Providers.CriminalIP.Enabled, APIKey: sess.Providers.CriminalIP.APIKey, NewClient: criminalip.NewProviderClient},
		{Name: digitalocean.ProviderName, Enabled: sess.Providers.DigitalOcean.Enabled, APIKey: "", NewClient: digitalocean.NewProviderClient},
		{Name: gcp.ProviderName, Enabled: sess.Providers.GCP.Enabled, APIKey: "", NewClient: gcp.NewProviderClient},
		{Name: google.ProviderName, Enabled: sess.Providers.Google.Enabled, APIKey: "", NewClient: google.NewProviderClient},
		{Name: googlebot.ProviderName, Enabled: sess.Providers.Googlebot.Enabled, APIKey: "", NewClient: googlebot.NewProviderClient},
		{Name: ipapi.ProviderName, Enabled: sess.Providers.IPAPI.Enabled, APIKey: "", NewClient: ipapi.NewProviderClient},
		{Name: ipurl.ProviderName, Enabled: sess.Providers.IPURL.Enabled, APIKey: "", NewClient: ipurl.NewProviderClient},
		{Name: icloudpr.ProviderName, Enabled: sess.Providers.ICloudPR.Enabled, APIKey: "", NewClient: icloudpr.NewProviderClient},
		{Name: linode.ProviderName, Enabled: sess.Providers.Linode.Enabled, APIKey: "", NewClient: linode.NewProviderClient},
		{Name: shodan.ProviderName, Enabled: sess.Providers.Shodan.Enabled, APIKey: sess.Providers.Shodan.APIKey, NewClient: shodan.NewProviderClient},
		{Name: ptr.ProviderName, Enabled: sess.Providers.PTR.Enabled, APIKey: "", NewClient: ptr.NewProviderClient},
	}

	for _, provider := range pros {
		if provider.Enabled == nil {
			sess.Logger.Debug("provider not in configuration", "name", provider.Name)

			continue
		}

		if *provider.Enabled || sess.UseTestData || provider.APIKey != "" {
			client, err := provider.NewClient(sess)
			if err != nil {
				return nil, fmt.Errorf("error creating %s client: %w", provider.Name, err)
			}

			if client != nil {
				runners[provider.Name] = client
			}
		}
	}

	return runners, nil
}

func getEnabledProviders(runners map[string]providers.ProviderClient) map[string]providers.ProviderClient {
	var res map[string]providers.ProviderClient

	for k := range runners {
		if runners[k].Enabled() {
			if res == nil {
				res = make(map[string]providers.ProviderClient)
			}

			res[k] = runners[k]
		}
	}

	return res
}

type Config struct {
	session.Session
	Shodan     shodan.Config
	CriminalIP criminalip.Config
	IPURL      ipurl.Config
}

type Processor struct {
	Session *session.Session
}

func (p *Processor) Run() {
	homeDir, err := homedir.Dir()
	if err != nil {
		p.Session.Logger.Error("failed to get home directory", "error", err)

		os.Exit(1)
	}

	db, err := cache.Create(p.Session.Logger, filepath.Join(homeDir, ".config", "ipscout"))
	if err != nil {
		p.Session.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	p.Session.Cache = db

	defer db.Close()

	// get provider clients
	providerClients, err := getProviderClients(*p.Session)
	if err != nil {
		p.Session.Logger.Error("failed to generate provider clients", "error", err)

		// close here as exit prevents defer from running
		_ = db.Close()

		os.Exit(1) // nolint:gocritic
	}

	enabledProviders := getEnabledProviders(providerClients)

	// initialise providers
	initialiseProviders(p.Session.Logger, enabledProviders, p.Session.HideProgress)

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.InitialiseDuration {
			p.Session.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	// find hosts
	results := findHosts(enabledProviders, p.Session.HideProgress)

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.FindHostDuration {
			p.Session.Logger.Debug("find hosts timing", "provider", provider, "duration", dur.String())
		}

		for provider, uc := range p.Session.Stats.FindHostUsedCache {
			p.Session.Logger.Debug("find hosts data load", "provider", provider, "cache", uc)
		}
	}

	results.RLock()
	matchingResults := len(results.m)
	results.RUnlock()

	p.Session.Logger.Info("host matching results", "providers queried", len(enabledProviders), "matching results", matchingResults)

	if matchingResults == 0 {
		p.Session.Logger.Warn("no results found", "host", p.Session.Host.String(), "providers checked", strings.Join(mapsKeys(enabledProviders), ", "))

		return
	}

	// output data
	if err = output(p.Session, providerClients, results); err != nil {
		p.Session.Logger.Error("failed to output data", "error", err)

		os.Exit(1)
	}
}

func mapsKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))

	for key := range m {
		keys = append(keys, key)
	}

	return keys

}

func initialiseProviders(l *slog.Logger, runners map[string]providers.ProviderClient, hideProgress bool) {
	var err error

	var g errgroup.Group

	s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriter(os.Stderr))

	if !hideProgress {
		s.Start() // Start the spinner
		// time.Sleep(4 * time.Second) // Run for some time to simulate work
		s.Suffix = " initialising providers..."

		defer func() {
			stopSpinnerIfActive(s)
		}()
	}

	for name, runner := range runners {
		_, runner := name, runner // https://golang.org/doc/faq#closures_and_goroutines

		g.Go(func() error {
			name := name

			gErr := runner.Initialise()
			if gErr != nil {
				stopSpinnerIfActive(s)
				l.Error("failed to initialise", "provider", name, "error", gErr.Error())

				if !hideProgress {
					s.Start()
				}
			}

			return nil
		})
	}

	if err = g.Wait(); err != nil {
		stopSpinnerIfActive(s)

		return
	}
	// allow time to output spinner
	time.Sleep(50 * time.Millisecond)
}

func stopSpinnerIfActive(s *spinner.Spinner) {
	if s != nil && s.Active() {
		s.Stop()
	}
}

type findHostsResults struct {
	sync.RWMutex
	m map[string][]byte
}

type generateTablesResults struct {
	sync.RWMutex
	m []*table.Writer
}

func findHosts(runners map[string]providers.ProviderClient, hideProgress bool) *findHostsResults {
	var results findHostsResults

	results.Lock()
	results.m = make(map[string][]byte)
	results.Unlock()

	var w sync.WaitGroup

	if !hideProgress {
		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
		s.Start() // Start the spinner
		s.Suffix = " searching providers..."

		defer s.Stop()
	}

	for name, runner := range runners {
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

	return &results
}

// func generateOutput(conf *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) error {
func output(sess *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) error {
	switch sess.Config.Global.Output {
	case "table":
		tables := generateTables(sess, runners, results)

		if strings.EqualFold(sess.Config.Global.LogLevel, "debug") {
			for provider, dur := range sess.Stats.CreateTableDuration {
				sess.Logger.Debug("create tables timing", "provider", provider, "duration", dur.String())
			}
		}

		present.Tables(sess, tables)

		outputMessages(sess)
	case "json":
		jo, err := generateJSON(results)
		if err != nil {
			return err
		}

		if err = present.JSON(&jo); err != nil {
			return fmt.Errorf("error outputting JSON: %w", err)
		}

		outputMessages(sess)
	default:
		return fmt.Errorf("unsupported output format: %s", sess.Config.Global.Output)
	}

	return nil
}

func outputMessages(sess *session.Session) {
	for x := range sess.Messages.Error {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgRed.Sprint("[ERROR]"), sess.Messages.Error[x])
	}

	for x := range sess.Messages.Warning {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgYellow.Sprint("[WARN]"), sess.Messages.Warning[x])
	}

	for x := range sess.Messages.Info {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgGreen.Sprint("[INFO]"), sess.Messages.Info[x])
	}
}

func generateTables(conf *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) []*table.Writer {
	var tables generateTablesResults

	var w sync.WaitGroup

	if !conf.HideProgress {
		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriterFile(conf.Target))
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

	return tables.m
}

func generateJSON(results *findHostsResults) (json.RawMessage, error) {
	var counter int64

	var out json.RawMessage

	for name := range results.m {
		results.RLock()

		if results.m[name] == nil {
			return nil, fmt.Errorf("no data found for %s", name)
		}

		if counter == 0 {
			out = json.RawMessage([]byte("["))
		}

		cj := json.RawMessage(results.m[name])
		out = append(out, json.RawMessage([]byte("{\""+name+"\":"))...)
		out = append(out, cj...)
		out = append(out, json.RawMessage([]byte("}"))...)

		if counter == int64(len(results.m)-1) {
			out = append(out, json.RawMessage([]byte("]"))...)
		} else {
			out = append(out, json.RawMessage([]byte(","))...)
		}

		counter++

		results.RUnlock()
	}

	return out, nil
}

func New(sess *session.Session) (Processor, error) {
	p := Processor{
		Session: sess,
	}

	return p, nil
}
