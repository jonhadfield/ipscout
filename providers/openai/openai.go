package openai

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/openai"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "openai"
	// OpenAI publishes three lists and revises them on a scale of weeks, not
	// days: at the time of review chatgpt-user.json had last changed 15 days
	// earlier, gptbot.json 24 days, and searchbot.json in January. A week of
	// staleness is a fair trade for a quarter of the fetches.
	//
	// Sized on Last-Modified rather than the creationTime field in the JSON,
	// which is not maintained in step with the file: gptbot.json carried a
	// creationTime ten months older than its own Last-Modified.
	//
	// The lists are served with Cache-Control: max-age=0, must-revalidate.
	// Honouring that would mean conditional requests, which ipscout does not
	// do; against a fetch-and-cache client the choice is only how long to
	// hold, and the observed cadence says a week beats a day.
	DocTTL = 7 * 24 * time.Hour
)

type Config struct {
	_ struct{}
	session.Session
	Host   netip.Addr
	APIKey string
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating openai client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.OpenAI.Enabled != nil && *c.Providers.OpenAI.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.OpenAI.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	var doc HostSearchResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return nil, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	threatIndicators := providers.ThreatIndicators{
		Provider: ProviderName,
	}

	indicators := make(map[string]string)

	if len(doc.Matches) > 0 {
		indicators["ReputableBot"] = "true"
	}

	threatIndicators.Indicators = indicators

	return &threatIndicators, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig
	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf("error unmarshalling OpenAI find result: %w", err)
	}

	if len(doc.Matches) == 0 {
		return rateResult, errors.New("no matches found in OpenAI data")
	}

	rateResult.Score = ratingConfig.ProviderRatingsConfigs.OpenAI.DefaultMatchScore
	rateResult.Detected = true

	for _, match := range doc.Matches {
		rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("source is OpenAI %s", match.Name))
	}

	return rateResult, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	res.Raw = rBody

	return res, nil
}

func unmarshalProviderData(data []byte) (*openai.Doc, error) {
	var res *openai.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling openai data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	openaiClient := openai.New()
	openaiClient.Client = c.HTTPClient

	if c.Providers.OpenAI.GPTBotURL != "" {
		openaiClient.GPTBotURL = c.Providers.OpenAI.GPTBotURL
		c.Logger.Debug("overriding openai gptbot source", "url", openaiClient.GPTBotURL)
	}

	if c.Providers.OpenAI.SearchBotURL != "" {
		openaiClient.SearchBotURL = c.Providers.OpenAI.SearchBotURL
		c.Logger.Debug("overriding openai searchbot source", "url", openaiClient.SearchBotURL)
	}

	if c.Providers.OpenAI.ChatGPTUserURL != "" {
		openaiClient.ChatGPTUserURL = c.Providers.OpenAI.ChatGPTUserURL
		c.Logger.Debug("overriding openai chatgpt-user source", "url", openaiClient.ChatGPTUserURL)
	}

	doc, err := openaiClient.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching openai data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling openai provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.OpenAI.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.OpenAI.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Version:    doc.GPTBot.CreationTime.String(),
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting openai data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising openai client")

	// load provider data into cache if not already present and fresh
	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking openai cache: %w", err)
	}

	if ok {
		c.Logger.Debug("openai provider data found in cache")

		return nil
	}

	c.Logger.Debug("loading openai provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading openai api response: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*openai.Doc, error) {
	c.Logger.Debug("loading openai provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *openai.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached openai provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading openai cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/openai/testdata/openai_20_171_206_1_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting openai test data file path: %w", err)
	}

	tdf, err := loadResultsFile(resultsFile)
	if err != nil {
		return nil, err
	}

	c.Logger.Info("openai match returned from test data", "host", "20.171.206.1")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

// matchList returns a BotMatch if the host is contained in one of the list's prefixes.
func matchList(host netip.Addr, botName string, list openai.List) *BotMatch {
	if host.Is4() {
		for _, record := range list.IPv4Prefixes {
			if record.IPv4Prefix.Contains(host) {
				return &BotMatch{
					Name:         botName,
					Prefix:       record.IPv4Prefix,
					CreationTime: list.CreationTime,
				}
			}
		}

		return nil
	}

	for _, record := range list.IPv6Prefixes {
		if record.IPv6Prefix.Contains(host) {
			return &BotMatch{
				Name:         botName,
				Prefix:       record.IPv6Prefix,
				CreationTime: list.CreationTime,
			}
		}
	}

	return nil
}

// FindHost searches for the host in the openai data
func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	// return cached report if test data is enabled
	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, fmt.Errorf("loading openai host data from cache: %w", err)
	}

	if !c.Host.Is4() && !c.Host.Is6() {
		return nil, fmt.Errorf(constants.MsgInvalidHostFmt, c.Host.String())
	}

	var result HostSearchResult

	// search each bot's list for the host
	for _, list := range []struct {
		name string
		list openai.List
	}{
		{openai.GPTBotName, doc.GPTBot},
		{openai.SearchBotName, doc.SearchBot},
		{openai.ChatGPTUserName, doc.ChatGPTUser},
	} {
		if match := matchList(c.Host, list.name, list.list); match != nil {
			c.Logger.Debug("returning openai host match data", "bot", list.name)

			result.Matches = append(result.Matches, *match)
		}
	}

	if len(result.Matches) == 0 {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	result.Raw = raw

	return result.Raw, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %w", err)
	}

	tw := table.NewWriter()

	var botNames []string
	for _, match := range result.Matches {
		botNames = append(botNames, match.Name)
	}

	// pad column to ensure title row fills the table
	tw.AppendRow(table.Row{providers.PadRight("Bots", providers.Column1MinWidth), providers.DashIfEmpty(strings.Join(botNames, ", "))})

	for _, match := range result.Matches {
		tw.AppendRow(table.Row{fmt.Sprintf("%s Prefix", match.Name), providers.DashIfEmpty(match.Prefix.String())})

		if !match.CreationTime.IsZero() {
			tw.AppendRow(table.Row{fmt.Sprintf("%s Creation Time", match.Name), providers.DashIfEmpty(match.CreationTime.String())})
		}
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("OPENAI | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("OPENAI | Host: %s", "20.171.206.1")
	}

	return &tw, nil
}

func loadResultsFile(path string) (*HostSearchResult, error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	defer jf.Close()

	var res HostSearchResult

	decoder := json.NewDecoder(jf)

	if err = decoder.Decode(&res); err != nil {
		return nil, fmt.Errorf("error decoding file: %w", err)
	}

	return &res, nil
}

// BotMatch records a single OpenAI bot list containing the host.
type BotMatch struct {
	Name         string       `json:"name"`
	Prefix       netip.Prefix `json:"prefix"`
	CreationTime time.Time    `json:"creation_time"`
}

type HostSearchResult struct {
	Raw     []byte
	Matches []BotMatch `json:"matches"`
}
