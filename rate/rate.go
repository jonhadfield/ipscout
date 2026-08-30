package rate

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sashabaranov/go-openai"

	"github.com/fatih/color"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jonhadfield/ipscout/cache"
	c "github.com/jonhadfield/ipscout/constants"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
	"golang.org/x/sync/errgroup"
)

//go:embed defaultRatingConfig.json
var DefaultRatingConfigJSON string

const (
	txtAllow            = "allow"
	txtBlock            = "block"
	spinnerStartupMS    = 50
	spinnerIntervalMS   = 100
	maxCompletionTokens = 1024
	aiModel             = openai.GPT4oMini
)

func getEnabledProviderClients(sess session.Session) (map[string]providers.ProviderClient, error) {
	runners := make(map[string]providers.ProviderClient)

	for _, entry := range registry.All() {
		if !entry.SupportsRating {
			continue
		}

		entryEnabled := entry.Enabled(sess)
		if entryEnabled == nil || !*entryEnabled {
			continue
		}

		client, err := entry.NewClient(sess)
		if err != nil {
			return nil, fmt.Errorf("error creating %s client: %w", entry.Name, err)
		}

		if client != nil && (client.Enabled() || sess.UseTestData) {
			runners[entry.Name] = client
		}
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

// ChatCompleter is the subset of the OpenAI client used for AI rating. It lets
// the completion backend be injected so the rating flow can be tested offline.
type ChatCompleter interface {
	CreateChatCompletion(context.Context, openai.ChatCompletionRequest) (openai.ChatCompletionResponse, error)
}

type Rater struct {
	Session  *session.Session
	AIClient ChatCompleter
}

func GetRatingConfig(path string) ([]byte, error) {
	var err error

	ratingConfigJSON := []byte(DefaultRatingConfigJSON)

	if path != "" {
		ratingConfigJSON, err = providers.ReadRatingConfigFile(path)
		if err != nil {
			// the shipped config always sets a rating config path, but the
			// file itself is never written, so treating an absent file as
			// fatal would leave rating unusable until the user created one by
			// hand. A file that exists but cannot be read is still an error.
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%w", err)
			}

			ratingConfigJSON = []byte(DefaultRatingConfigJSON)
		}
	}

	// try loading the rating config to validate it
	_, err = providers.LoadRatingConfig(ratingConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to load rating config: %w", err)
	}

	return ratingConfigJSON, nil
}

func (r *Rater) Run() error {
	var err error

	if path := r.Session.Config.Rating.ConfigPath; path != "" {
		if _, sErr := os.Stat(path); errors.Is(sErr, os.ErrNotExist) {
			r.Session.Logger.Warn("rating config not found, using built-in defaults",
				"path", path, "hint", "write one with: ipscout rate config --default")
		}
	}

	ratingConfig, err := GetRatingConfig(r.Session.Config.Rating.ConfigPath)
	if err != nil {
		return err
	}

	db, err := cache.Create(r.Session.Logger, filepath.Join(r.Session.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	r.Session.Cache = db

	defer func() {
		if err = db.Close(); err != nil {
			fmt.Printf("error: %s", err.Error())
			os.Exit(1)
		}
	}()

	providerClients, err := getEnabledProviderClients(*r.Session)
	if err != nil {
		r.Session.Logger.Error("failed to generate provider clients", "error", err)

		// close here as exit prevents defer from running
		_ = db.Close()

		return fmt.Errorf("failed to generate provider clients: %w", err)
	}

	enabledProviders := getEnabledProviders(providerClients)

	initialiseProviders(r.Session, enabledProviders, r.Session.HideProgress)

	if strings.EqualFold(r.Session.Config.Global.LogLevel, "debug") {
		for provider, dur := range r.Session.Stats.InitialiseDuration {
			r.Session.Logger.Debug("initialise timing", "provider", provider, "duration", dur.String())
		}
	}

	if r.Session.Config.Global.InitialiseCacheOnly {
		_, _ = fmt.Fprintln(r.Session.Target, "cache initialisation complete")

		outputMessages(r.Session)

		return nil
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

		// there is no rating to print below, but a fetch failure is the most
		// likely reason there is nothing to show, so still report it
		outputMessages(r.Session)

		return nil
	}

	defer outputMessages(r.Session)

	if r.Session.Config.Rating.UseAI {
		return aiRate(r, enabledProviders, results)
	}

	return staticRate(r, enabledProviders, results, ratingConfig)
}

func aiRate(r *Rater, enabledProviders map[string]providers.ProviderClient, results *findHostsResults) error {
	// rate results
	combinedThreatIndicators, err := extractThreatIndicators(r.Session, enabledProviders, results)
	if err != nil {
		return fmt.Errorf("failed to rate results: %w", err)
	}

	mj, err := json.MarshalIndent(combinedThreatIndicators, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling threat indicators: %w", err)
	}

	// generate table from rate results
	tables, err := r.CreateThreatIndicatorsTable(combinedThreatIndicators)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	present.Tables(r.Session, []providers.TableWithPriority{
		{
			Table: tables,
		},
	})

	client := r.AIClient
	if client == nil {
		client = openai.NewClient(r.Session.Config.Rating.OpenAIAPIKey)
	}

	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model:               aiModel,
			MaxCompletionTokens: maxCompletionTokens,
			Messages: []openai.ChatCompletionMessage{
				{
					Role: openai.ChatMessageRoleSystem,
					Content: "You are a cybersecurity analyst evaluating threat indicators from various providers. " +
						"Provide a single paragraph summary and recommendation on whether the source should be blocked. " +
						"You do not need to mention every indicator. " +
						"An annotated indicator containing 'threat:noblock' means you will recommend the source is not blocked.",
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: "Evaluate the following threat indicators and provide your recommendation:\n\n" + string(mj),
				},
			},
		},
	)
	if err != nil {
		return fmt.Errorf("OpenAI chat completion error: %w", err)
	}

	if len(resp.Choices) == 0 {
		return errors.New("OpenAI returned no choices")
	}

	color.White("Recommendation: %s", resp.Choices[0].Message.Content)

	return nil
}

func extractThreatIndicators(sess *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults) ([]providers.ThreatIndicators, error) {
	sess.Logger.Debug("extracting threat indicators")

	combinedThreatIndicators := make([]providers.ThreatIndicators, 0)

	for k := range results.m {
		tis, err := runners[k].ExtractThreatIndicators(results.m[k])
		if err != nil {
			return nil, fmt.Errorf("error rating %s: %w", k, err)
		}

		if tis != nil && tis.Indicators != nil {
			combinedThreatIndicators = append(combinedThreatIndicators, providers.ThreatIndicators{
				Provider:   tis.Provider,
				Indicators: tis.Indicators,
			})
		}
	}

	return combinedThreatIndicators, nil
}

func (r *Rater) CreateThreatIndicatorsTable(ctis []providers.ThreatIndicators) (*table.Writer, error) {
	tw := table.NewWriter()

	if len(ctis) == 0 {
		tw.AppendRow(table.Row{"no threat indicators found"})
		tw.SetAutoIndex(false)

		return &tw, nil
	}

	tw.AppendHeader(table.Row{"Provider", "Indicator", "  "})

	var lastProvider string

	for _, ti := range ctis {
		for k, v := range ti.Indicators {
			provider := ""
			if lastProvider != ti.Provider {
				provider = ti.Provider
				lastProvider = ti.Provider
			}

			tw.AppendRow(table.Row{provider, k, v})
		}
	}

	tw.SetAutoIndex(false)
	tw.SetTitle("RATING: " + r.Session.Host.String())

	return &tw, nil
}

func staticRate(r *Rater, enabledProviders map[string]providers.ProviderClient, results *findHostsResults, ratingConfig []byte) error {
	rrs, err := staticRateFindHostsResults(r.Session, enabledProviders, results, ratingConfig)
	if err != nil {
		return fmt.Errorf("failed to rate results: %w", err)
	}

	tables, err := r.CreateResultsTable(rrs)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	present.Tables(r.Session, []providers.TableWithPriority{
		{
			Table: tables,
		},
	})

	color.White("Recommendation: %s", rrs.Recommendation)

	return nil
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

func staticRateFindHostsResults(sess *session.Session, runners map[string]providers.ProviderClient, results *findHostsResults, ratingConfigJSON []byte) (RatingOutput, error) {
	sess.Logger.Debug("rating results")

	runningTotal := 0.0

	providersThatDetected := 0

	var rateOutput RatingOutput

	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return RatingOutput{}, fmt.Errorf("error unmarshalling rating config: %w", err)
	}

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
		return RatingOutput{}, errors.New("no providers detected")
	}

	aggregateScore := runningTotal / float64(providersThatDetected)
	rateOutput.AverageScore = aggregateScore

	// if we don't have a recommendation already, then set one based on the aggregate score
	if rateOutput.Recommendation == "" {
		switch {
		case aggregateScore < ratingConfig.Global.BlockScoreThreshold:
			rateOutput.Recommendation = txtAllow
		default:
			rateOutput.Recommendation = txtBlock
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

func initialiseProviders(sess *session.Session, runners map[string]providers.ProviderClient, hideProgress bool) {
	var err error

	var g errgroup.Group

	// failures are collected rather than logged as they happen, so a slow
	// download is not interrupted by output, and reported as one line after
	// the results
	var (
		failedMu sync.Mutex
		failed   []string
	)

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
		g.Go(func() error {
			name := name

			gErr := runner.Initialise()
			if gErr != nil {
				sess.Logger.Debug("failed to initialise", "provider", name, "error", gErr.Error())

				failedMu.Lock()

				failed = append(failed, name)

				failedMu.Unlock()
			}

			return nil
		})
	}

	if err = g.Wait(); err != nil {
		stopSpinnerIfActive(s)

		return
	}

	reportFailedProviders(sess, failed)

	// allow time to output spinner
	time.Sleep(spinnerStartupMS * time.Millisecond)
}

// reportFailedProviders records a single message naming every provider whose
// data could not be fetched. It is buffered on the session so it prints below
// the results rather than over the progress spinner.
func reportFailedProviders(sess *session.Session, failed []string) {
	if len(failed) == 0 {
		return
	}

	sort.Strings(failed)

	sess.Messages.AddError(fmt.Sprintf(c.MsgFetchFailedFmt, strings.Join(failed, ", ")))
}

// outputMessages prints the messages buffered during the run, below the
// results.
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

func stopSpinnerIfActive(s *spinner.Spinner) {
	if s != nil && s.Active() {
		s.Stop()
	}
}

type findHostsResults struct {
	sync.RWMutex
	m map[string][]byte
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
	time.Sleep(spinnerStartupMS * time.Millisecond)

	return &results
}

func New(sess *session.Session) (Rater, error) {
	p := Rater{
		Session:  sess,
		AIClient: openai.NewClient(sess.Config.Rating.OpenAIAPIKey),
	}

	return p, nil
}
