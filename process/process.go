package process

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/runner"
	"github.com/jonhadfield/ipscout/session"
)

const spinnerIntervalMS = 100

type Processor struct {
	Session *session.Session
}

func (p *Processor) Run() error {
	db, err := cache.Create(p.Session.Logger, filepath.Join(p.Session.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	p.Session.Cache = db

	defer func() { _ = cache.Close(p.Session.Logger, db) }()

	// get provider clients
	providerClients, err := runner.GetEnabledProviderClients(*p.Session, runner.ClientOptions{RequireEnabled: true})
	if err != nil {
		_ = cache.Close(p.Session.Logger, db)

		return fmt.Errorf("failed to generate provider clients: %w", err)
	}

	enabledProviders := runner.GetEnabledProviders(providerClients)

	// apply provider filter if specified
	if len(p.Session.Config.Global.FilterProviders) > 0 {
		enabledProviders = filterProvidersByName(enabledProviders, p.Session.Config.Global.FilterProviders)
		if len(enabledProviders) == 0 {
			return fmt.Errorf("no matching providers found for filter: %s", strings.Join(p.Session.Config.Global.FilterProviders, ", "))
		}
	}

	// initialise providers
	runner.InitialiseProviders(p.Session, enabledProviders, p.Session.HideProgress)

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.InitialiseDuration {
			p.Session.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	if p.Session.Config.Global.InitialiseCacheOnly {
		fmt.Fprintln(p.Session.Target, "cache initialisation complete")

		runner.OutputMessages(p.Session)

		return nil
	}

	// find hosts
	results := runner.FindHosts(enabledProviders, p.Session.HideProgress)

	if strings.EqualFold(p.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range p.Session.Stats.FindHostDuration {
			p.Session.Logger.Debug("find hosts timing", "provider", provider, "duration", dur.String())
		}

		for provider, uc := range p.Session.Stats.FindHostUsedCache {
			p.Session.Logger.Debug("find hosts data load", "provider", provider, "cache", uc)
		}
	}

	results.RLock()
	matchingResults := len(results.Data)
	results.RUnlock()

	p.Session.Logger.Info("host matching results", "providers queried", len(enabledProviders), "matching results", matchingResults)

	if tip := runner.SignupTip(p.Session, matchingResults); tip != "" {
		p.Session.Messages.AddTip(tip)
	}

	if matchingResults == 0 {
		p.Session.Logger.Warn("no results found", "host", p.Session.Host.String(), "providers checked", strings.Join(runner.MapsKeys(enabledProviders), ", "))

		// there is no results table to print below, but a fetch failure is
		// the most likely reason there is nothing to show, so still report it
		runner.OutputMessages(p.Session)

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

type generateTablesResults struct {
	sync.RWMutex
	m []providers.TableWithPriority
}

func output(sess *session.Session, runners map[string]providers.ProviderClient, results *runner.HostResults) error {
	switch sess.Config.Global.Output {
	case "table":
		tables := generateTables(sess, runners, results)

		if strings.EqualFold(sess.Config.Global.LogLevel, "debug") {
			for provider, dur := range sess.Stats.CreateTableDuration {
				sess.Logger.Debug("create tables timing", "provider", provider, "duration", dur.String())
			}
		}

		present.Tables(sess, tables)

		runner.OutputMessages(sess)
	case "json":
		jo, err := generateJSON(results)
		if err != nil {
			return err
		}

		if err = present.JSON(&jo); err != nil {
			return fmt.Errorf("error outputting JSON: %w", err)
		}

		runner.OutputMessages(sess)
	case "csv":
		jo, err := generateJSON(results)
		if err != nil {
			return err
		}

		if err = present.CSV(&jo); err != nil {
			return fmt.Errorf("error outputting CSV: %w", err)
		}

		runner.OutputMessages(sess)
	default:
		return fmt.Errorf("unsupported output format: %s", sess.Config.Global.Output)
	}

	return nil
}

func generateTables(conf *session.Session, runners map[string]providers.ProviderClient, results *runner.HostResults) []providers.TableWithPriority {
	var tables generateTablesResults

	var w sync.WaitGroup

	if !conf.HideProgress {
		s := spinner.New(spinner.CharSets[11], spinnerIntervalMS*time.Millisecond, spinner.WithWriterFile(conf.Target))
		s.Start() // Start the spinner

		s.Suffix = " generating output..."

		defer s.Stop()
	}

	for name, runnerClient := range runners {
		w.Add(1)

		go func() {
			defer w.Done()

			results.RLock()
			createTableData := results.Data[name]
			results.RUnlock()

			if createTableData == nil {
				return
			}

			tbl, err := runnerClient.CreateTable(createTableData)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)

				return
			}

			if tbl != nil {
				tables.Lock()
				tables.m = append(tables.m, providers.TableWithPriority{
					Table:    tbl,
					Priority: runnerClient.Priority(),
				})
				tables.Unlock()
			}
		}()
	}

	w.Wait()

	return tables.m
}

func generateJSON(results *runner.HostResults) (json.RawMessage, error) {
	data := make(map[string]json.RawMessage)

	results.RLock()
	defer results.RUnlock()

	for name, b := range results.Data {
		if b == nil {
			return nil, fmt.Errorf("no data found for %s", name)
		}

		data[name] = json.RawMessage(b)
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
