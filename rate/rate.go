package rate

import (
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"

	"github.com/jonhadfield/ipscout/providers/ipapi"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/jonhadfield/ipscout/providers/bingbot"

	"github.com/jonhadfield/ipscout/providers/virustotal"

	"github.com/jonhadfield/ipscout/providers/google"

	"github.com/jonhadfield/ipscout/providers/googlebot"

	"github.com/jonhadfield/ipscout/providers/icloudpr"

	"github.com/jonhadfield/ipscout/providers/gcp"
	"github.com/jonhadfield/ipscout/providers/linode"

	"github.com/briandowns/spinner"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/providers/abuseipdb"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/providers/aws"
	"github.com/jonhadfield/ipscout/providers/azure"
	"github.com/jonhadfield/ipscout/providers/criminalip"
	"github.com/jonhadfield/ipscout/providers/digitalocean"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/providers/shodan"
	"github.com/jonhadfield/ipscout/session"
	"golang.org/x/sync/errgroup"
)

//go:embed defaultRatingConfig.json
var defaultRatingConfigJSON string

const (
	txtAllow = "allow"
	txtBlock = "block"
)

type Provider struct {
	Name      string
	Enabled   *bool
	APIKey    string
	NewClient func(c session.Session) (providers.ProviderClient, error)
}

func getEnabledProviderClients(sess session.Session) (map[string]providers.ProviderClient, error) {
	runners := make(map[string]providers.ProviderClient)

	pros := []Provider{
		{Name: abuseipdb.ProviderName, Enabled: sess.Providers.AbuseIPDB.Enabled, APIKey: sess.Providers.AbuseIPDB.APIKey, NewClient: abuseipdb.NewClient},
		{Name: annotated.ProviderName, Enabled: sess.Providers.Annotated.Enabled, APIKey: "", NewClient: annotated.NewProviderClient},
		{Name: aws.ProviderName, Enabled: sess.Providers.AWS.Enabled, APIKey: "", NewClient: aws.NewProviderClient},
		{Name: azure.ProviderName, Enabled: sess.Providers.Azure.Enabled, APIKey: "", NewClient: azure.NewProviderClient},
		// {Name: azurewaf.ProviderName, Enabled: sess.Providers.AzureWAF.Enabled, APIKey: "", NewClient: azurewaf.NewProviderClient},
		{Name: bingbot.ProviderName, Enabled: sess.Providers.Bingbot.Enabled, APIKey: "", NewClient: bingbot.NewProviderClient},
		{Name: criminalip.ProviderName, Enabled: sess.Providers.CriminalIP.Enabled, APIKey: sess.Providers.CriminalIP.APIKey, NewClient: criminalip.NewProviderClient},
		{Name: digitalocean.ProviderName, Enabled: sess.Providers.DigitalOcean.Enabled, APIKey: "", NewClient: digitalocean.NewProviderClient},
		{Name: gcp.ProviderName, Enabled: sess.Providers.GCP.Enabled, APIKey: "", NewClient: gcp.NewProviderClient},
		{Name: google.ProviderName, Enabled: sess.Providers.Google.Enabled, APIKey: "", NewClient: google.NewProviderClient},
		{Name: googlebot.ProviderName, Enabled: sess.Providers.Googlebot.Enabled, APIKey: "", NewClient: googlebot.NewProviderClient},
		{Name: ipapi.ProviderName, Enabled: sess.Providers.IPAPI.Enabled, APIKey: "", NewClient: ipapi.NewProviderClient},
		{Name: ipurl.ProviderName, Enabled: sess.Providers.IPURL.Enabled, APIKey: "", NewClient: ipurl.NewProviderClient},
		{Name: icloudpr.ProviderName, Enabled: sess.Providers.ICloudPR.Enabled, APIKey: "", NewClient: icloudpr.NewProviderClient},
		{Name: linode.ProviderName, Enabled: sess.Providers.Linode.Enabled, APIKey: "", NewClient: linode.NewProviderClient},
		// PTR does not help us determine if an IP is malicious?
		// {Name: ptr.ProviderName, Enabled: sess.Providers.PTR.Enabled, APIKey: "", NewClient: ptr.NewProviderClient},
		{Name: shodan.ProviderName, Enabled: sess.Providers.Shodan.Enabled, APIKey: sess.Providers.Shodan.APIKey, NewClient: shodan.NewProviderClient},
		{Name: virustotal.ProviderName, Enabled: sess.Providers.VirusTotal.Enabled, APIKey: sess.Providers.VirusTotal.APIKey, NewClient: virustotal.NewProviderClient},
	}

	for _, provider := range pros {
		client, err := provider.NewClient(sess)
		if err != nil {
			return nil, fmt.Errorf("error creating %s client: %w", provider.Name, err)
		}

		if client != nil && client.Enabled() || sess.UseTestData {
			runners[provider.Name] = client
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

type Rater struct {
	Session *session.Session
}

func (r *Rater) Run() {
	// validate rating config
	_, err := providers.LoadRatingConfig(defaultRatingConfigJSON)
	if err != nil {
		r.Session.Logger.Error("failed to load rating config", "error", err)

		os.Exit(1)
	}

	db, err := cache.Create(r.Session.Logger, filepath.Join(r.Session.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		r.Session.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	r.Session.Cache = db

	defer func() {
		if err = db.Close(); err != nil {
			fmt.Printf("error: %s", err.Error())
			os.Exit(1)
		}
	}()

	// get provider clients
	providerClients, err := getEnabledProviderClients(*r.Session)
	if err != nil {
		r.Session.Logger.Error("failed to generate provider clients", "error", err)

		// close here as exit prevents defer from running
		_ = db.Close()

		os.Exit(1) //nolint:gocritic
	}

	enabledProviders := getEnabledProviders(providerClients)

	// initialise providers
	initialiseProviders(r.Session.Logger, enabledProviders, r.Session.HideProgress)

	if strings.EqualFold(r.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range r.Session.Stats.InitialiseDuration {
			r.Session.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	if r.Session.Config.Global.InitialiseCacheOnly {
		_, _ = fmt.Fprintln(r.Session.Target, "cache initialisation complete")

		return
	}

	// find hosts
	results := findHosts(enabledProviders, r.Session.HideProgress)

	// output timings when debug logging
	if strings.EqualFold(r.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range r.Session.Stats.FindHostDuration {
			r.Session.Logger.Debug("find hosts timing", "provider", provider, "duration", dur.String())
		}

		for provider, uc := range r.Session.Stats.FindHostUsedCache {
			r.Session.Logger.Debug("find hosts data load", "provider", provider, "cache", uc)
		}
	}

	results.RLock()
	matchingResults := len(results.m)
	results.RUnlock()

	r.Session.Logger.Info("host matching results", "providers queried", len(enabledProviders), "matching results", matchingResults)

	if matchingResults == 0 {
		r.Session.Logger.Warn("no results found", "host", r.Session.Host.String(), "providers checked", strings.Join(mapsKeys(enabledProviders), ", "))

		return
	}

	// rate results
	rrs, err := rateFindHostsResults(r.Session, enabledProviders, results, []byte(defaultRatingConfigJSON))
	if err != nil {
		r.Session.Logger.Error("failed to rate results", "error", err)

		os.Exit(1)
	}
	// generate table from rate results
	tables, err := r.CreateResultsTable(rrs)
	if err != nil {
		r.Session.Logger.Error("failed to create table", "error", err)

		os.Exit(1)
	}
	// present table
	present.Tables(r.Session, []providers.TableWithPriority{
		{
			Table: tables,
			// Priority: 0,
		},
	})

	color.White("Recommendation: %s", rrs.Recommendation)
}

type rateResultsOutputItem struct {
	Provider string
	Detected bool
	Score    float64
	Reason   string
	NoBlock  bool
}

type RatingOutput struct {
	AverageScore          float64
	ProvidersThatDetected int
	Results               []rateResultsOutputItem
	Recommendation        string
	// Reason             string
	Reasons []string
}

func rateFindHostsResults(sess *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults, ratingConfigJSON []byte) (RatingOutput, error) {
	sess.Logger.Debug("rating results")

	runningTotal := 0.0

	providersThatDetected := 0

	var rateOutput RatingOutput

	for k := range results.m {
		rateResult, err := runners[k].RateHostData(results.m[k], ratingConfigJSON)
		if err != nil {
			return RatingOutput{}, fmt.Errorf("error rating %s: %w", k, err)
		}

		// recommend early if provider's output trumps others
		// we'll later check if this recommendation is already set
		switch rateResult.Threat {
		case "noblock":
			rateOutput.Recommendation = txtAllow
			rateOutput.Reasons = append(rateOutput.Reasons, fmt.Sprintf("%s - %s", k, strings.Join(rateResult.Reasons, " | ")))
		default:
			if rateResult.Detected {
				rateOutput.Reasons = append(rateOutput.Reasons, fmt.Sprintf("%s - %s", k, strings.Join(rateResult.Reasons, " | ")))
			}
		}

		if rateResult.Detected {
			providersThatDetected++

			sess.Logger.Debug("detected", "provider", k, "score", rateResult.Score, "reasons", rateResult.Reasons)

			runningTotal += rateResult.Score
		}

		rateOutput.Results = append(rateOutput.Results, rateResultsOutputItem{
			Provider: k,
			Detected: rateResult.Detected,
			Score:    rateResult.Score,
			Reason:   strings.Join(rateResult.Reasons, " | "),
		})
	}

	if providersThatDetected == 0 {
		return RatingOutput{}, fmt.Errorf("no providers detected")
	}

	aggregateScore := runningTotal / float64(providersThatDetected)
	rateOutput.AverageScore = aggregateScore

	// if we don't have a recommendation already, then set one based on the aggregate score
	if rateOutput.Recommendation == "" {
		switch {
		case aggregateScore >= 10:
			rateOutput.Recommendation = txtBlock
		case aggregateScore >= 7:
			rateOutput.Recommendation = txtBlock
		case aggregateScore >= 5:
			rateOutput.Recommendation = txtBlock
		case aggregateScore >= 3:
			rateOutput.Recommendation = txtAllow
		case aggregateScore >= 1:
			rateOutput.Recommendation = txtAllow
		}
	}

	rateOutput.ProvidersThatDetected = providersThatDetected

	return rateOutput, nil
}

func (r *Rater) CreateResultsTable(info RatingOutput) (*table.Writer, error) {
	tw := table.NewWriter()

	if len(info.Results) == 0 {
		tw.AppendRow(table.Row{"no results found"})
		tw.SetAutoIndex(false)

		return &tw, nil
	}

	tw.AppendHeader(table.Row{"Provider", "Detected", "Score", "Reasons                      "})
	tw.AppendFooter(table.Row{"Average", "", fmt.Sprintf("%.2f", info.AverageScore), ""})

	results := info.Results

	sort.Slice(results, func(i, j int) bool {
		return results[i].Detected && !results[j].Detected
	})

	for _, x := range info.Results {
		score := "-"
		if x.Score != -1 {
			score = fmt.Sprintf("%.2f", x.Score)
		}

		tw.AppendRow(table.Row{x.Provider, x.Detected, score, x.Reason})
	}

	tw.SetAutoIndex(false)
	tw.SetTitle("RATING: " + r.Session.Host.String())

	return &tw, nil
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

// type generateTablesResults struct {
// 	sync.RWMutex
// 	m []providers.TableWithPriority
// }

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

// func output(sess *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) error {
// 	switch sess.Config.Global.Output {
// 	case "table":
// 		tables := generateTables(sess, runners, results)
//
// 		if strings.EqualFold(sess.Config.Global.LogLevel, "debug") {
// 			for provider, dur := range sess.Stats.CreateTableDuration {
// 				sess.Logger.Debug("create tables timing", "provider", provider, "duration", dur.String())
// 			}
// 		}
//
// 		present.Tables(sess, tables)
//
// 		outputMessages(sess)
// 	case "json":
// 		jo, err := generateJSON(results)
// 		if err != nil {
// 			return err
// 		}
//
// 		if err = present.JSON(&jo); err != nil {
// 			return fmt.Errorf("error outputting JSON: %w", err)
// 		}
//
// 		outputMessages(sess)
// 	default:
// 		return fmt.Errorf("unsupported output format: %s", sess.Config.Global.Output)
// 	}
//
// 	return nil
// }
//
// func outputMessages(sess *session.Session) {
// 	for x := range sess.Messages.Error {
// 		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgRed.Sprint("[ERROR]"), sess.Messages.Error[x])
// 	}
//
// 	for x := range sess.Messages.Warning {
// 		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgYellow.Sprint("[WARN]"), sess.Messages.Warning[x])
// 	}
//
// 	for x := range sess.Messages.Info {
// 		_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", text.FgGreen.Sprint("[INFO]"), sess.Messages.Info[x])
// 	}
// }

// func generateTables(conf *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) []providers.TableWithPriority {
// 	var tables generateTablesResults
//
// 	var w sync.WaitGroup
//
// 	if !conf.HideProgress {
// 		s := spinner.New(spinner.CharSets[11], 100*time.Millisecond, spinner.WithWriterFile(conf.Target))
// 		s.Start() // Start the spinner
//
// 		s.Suffix = " generating output..."
//
// 		defer s.Stop()
// 	}
//
// 	for name, runner := range runners {
// 		w.Add(1)
//
// 		go func() {
// 			defer w.Done()
// 			results.RLock()
// 			if results.m[name] == nil {
// 				return
// 			}
//
// 			createTableData := results.m[name]
// 			results.RUnlock()
//
// 			tbl, err := runner.CreateTable(createTableData)
// 			if err != nil {
// 				_, _ = fmt.Fprintln(os.Stderr, err)
//
// 				return
// 			}
//
// 			if tbl != nil {
// 				tables.RWMutex.Lock()
// 				tables.m = append(tables.m, providers.TableWithPriority{
// 					Table:    tbl,
// 					Priority: runner.Priority(),
// 				})
// 				tables.RWMutex.Unlock()
// 			}
// 		}()
// 	}
//
// 	w.Wait()
// 	// allow time to output spinner
// 	time.Sleep(50 * time.Millisecond)
//
// 	return tables.m
// }
//
// func generateJSON(results *findHostsResults) (json.RawMessage, error) {
// 	var counter int64
//
// 	var out json.RawMessage
//
// 	for name := range results.m {
// 		results.RLock()
//
// 		if results.m[name] == nil {
// 			return nil, fmt.Errorf("no data found for %s", name)
// 		}
//
// 		if counter == 0 {
// 			out = json.RawMessage([]byte("["))
// 		}
//
// 		cj := json.RawMessage(results.m[name])
// 		out = append(out, json.RawMessage([]byte("{\""+name+"\":"))...)
// 		out = append(out, cj...)
// 		out = append(out, json.RawMessage([]byte("}"))...)
//
// 		if counter == int64(len(results.m)-1) {
// 			out = append(out, json.RawMessage([]byte("]"))...)
// 		} else {
// 			out = append(out, json.RawMessage([]byte(","))...)
// 		}
//
// 		counter++
//
// 		results.RUnlock()
// 	}
//
// 	return out, nil
// }

func New(sess *session.Session) (Rater, error) {
	p := Rater{
		Session: sess,
	}

	return p, nil
}