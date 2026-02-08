package process

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/briandowns/spinner"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"golang.org/x/sync/errgroup"
)

const spinnerIntervalMS = 100

func getEnabledProviderClients(sess session.Session) (map[string]providers.ProviderClient, error) {
	runners := make(map[string]providers.ProviderClient)

	var enabled int

	for _, entry := range registry.All() {
		entryEnabled := entry.Enabled(sess)
		if entryEnabled == nil || !*entryEnabled {
			continue
		}

		enabled++

		client, err := entry.NewClient(sess)
		if err != nil {
			return nil, fmt.Errorf("error creating %s client: %w", entry.Name, err)
		}

		if client != nil && client.Enabled() || sess.UseTestData {
			runners[entry.Name] = client
		}
	}

	if enabled == 0 {
		return nil, errors.New("no providers enabled")
	}

	return runners, nil
}

func getEnabledProviders(runners map[string]providers.ProviderClient) map[string]providers.ProviderClient {
	res := make(map[string]providers.ProviderClient)

	for k, r := range runners {
		if r.Enabled() {
			res[k] = r
		}
	}

	if len(res) == 0 {
		return nil
	}

	return res
}

type Processor struct {
	Session *session.Session
}

func (p *Processor) Run() error {
	db, err := cache.Create(p.Session.Logger, filepath.Join(p.Session.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	p.Session.Cache = db

	defer db.Close()

	// get provider clients
	providerClients, err := getEnabledProviderClients(*p.Session)
	if err != nil {
		_ = db.Close()

		return fmt.Errorf("failed to generate provider clients: %w", err)
	}

	enabledProviders := getEnabledProviders(providerClients)

	// apply provider filter if specified
	if len(p.Session.Config.Global.FilterProviders) > 0 {
		enabledProviders = filterProvidersByName(enabledProviders, p.Session.Config.Global.FilterProviders)
		if len(enabledProviders) == 0 {
			return fmt.Errorf("no matching providers found for filter: %s", strings.Join(p.Session.Config.Global.FilterProviders, ", "))
		}
	}

	// initialise providers
	initialiseProviders(p.Session.Logger, enabledProviders, p.Session.HideProgress)

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.InitialiseDuration {
			p.Session.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	if p.Session.Config.Global.InitialiseCacheOnly {
		fmt.Fprintln(p.Session.Target, "cache initialisation complete")

		return nil
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

		return nil
	}

	// output data
	if err = output(p.Session, providerClients, results); err != nil {
		return fmt.Errorf("failed to output data: %w", err)
	}

	return nil
}

func filterProvidersByName(runners map[string]providers.ProviderClient, names []string) map[string]providers.ProviderClient {
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[strings.ToLower(n)] = true
	}

	filtered := make(map[string]providers.ProviderClient)

	for k, v := range runners {
		if nameSet[strings.ToLower(k)] {
			filtered[k] = v
		}
	}

	return filtered
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

	s := spinner.New(spinner.CharSets[11], spinnerIntervalMS*time.Millisecond, spinner.WithWriter(os.Stderr))

	if !hideProgress {
		s.Start() // Start the spinner
		// time.Sleep(4 * time.Second) // Run for some time to simulate work
		s.Suffix = " initialising providers..."

		defer func() {
			stopSpinnerIfActive(s)
		}()
	}

	for name, runner := range runners {
		if !runner.Enabled() {
			continue
		}

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
	m []providers.TableWithPriority
}

func findHosts(runners map[string]providers.ProviderClient, hideProgress bool) *findHostsResults {
	var results findHostsResults

	results.Lock()
	results.m = make(map[string][]byte)
	results.Unlock()

	var w sync.WaitGroup

	if !hideProgress {
		s := spinner.New(spinner.CharSets[11], spinnerIntervalMS*time.Millisecond, spinner.WithWriter(os.Stderr))
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
				runner.GetConfig().Logger.Info(err.Error())

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

	return &results
}

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
	case "csv":
		jo, err := generateJSON(results)
		if err != nil {
			return err
		}

		if err = present.CSV(&jo); err != nil {
			return fmt.Errorf("error outputting CSV: %w", err)
		}

		outputMessages(sess)
	default:
		return fmt.Errorf("unsupported output format: %s", sess.Config.Global.Output)
	}

	return nil
}

func outputMessages(sess *session.Session) {
	for _, msg := range sess.Messages.Error {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgRed.Sprint("[ERROR]"), msg)
	}

	for _, msg := range sess.Messages.Warning {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgYellow.Sprint("[WARN]"), msg)
	}

	for _, msg := range sess.Messages.Info {
		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgGreen.Sprint("[INFO]"), msg)
	}
}

func generateTables(conf *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) []providers.TableWithPriority {
	var tables generateTablesResults

	var w sync.WaitGroup

	if !conf.HideProgress {
		s := spinner.New(spinner.CharSets[11], spinnerIntervalMS*time.Millisecond, spinner.WithWriterFile(conf.Target))
		s.Start() // Start the spinner

		s.Suffix = " generating output..."

		defer s.Stop()
	}

	for name, runner := range runners {
		w.Add(1)

		go func() {
			defer w.Done()

			results.RLock()
			createTableData := results.m[name]
			results.RUnlock()

			if createTableData == nil {
				return
			}

			tbl, err := runner.CreateTable(createTableData)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)

				return
			}

			if tbl != nil {
				tables.Lock()
				tables.m = append(tables.m, providers.TableWithPriority{
					Table:    tbl,
					Priority: runner.Priority(),
				})
				tables.Unlock()
			}
		}()
	}

	w.Wait()

	return tables.m
}

func generateJSON(results *findHostsResults) (json.RawMessage, error) {
	data := make(map[string]json.RawMessage)

	for name, b := range results.m {
		results.RLock()

		if b == nil {
			results.RUnlock()

			return nil, fmt.Errorf("no data found for %s", name)
		}

		data[name] = json.RawMessage(b)

		results.RUnlock()
	}

	out, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("json marshalling failed: %w", err)
	}

	return json.RawMessage(out), nil
}

func New(sess *session.Session) (Processor, error) {
	p := Processor{
		Session: sess,
	}

	return p, nil
}
