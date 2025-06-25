package ipurl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/jonhadfield/ipscout/helpers"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	ipu "github.com/jonhadfield/ip-fetcher/providers/url"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "ipurl"
	CacheTTL     = 3 * time.Hour
	// override default set in providers package constant as column 2 is expected to be wide
	column1MinWidth = 13
	column2MinWidth = 10
)

type Config struct {
	_ struct{}
	session.Session
	Host netip.Addr
	URLs []string
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.IPURL.Enabled != nil && *c.Providers.IPURL.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.IPURL.OutputPriority
}

func (c *ProviderClient) GetConfig() *session.Session {
	return &c.Session
}

func (c *ProviderClient) ExtractThreatIndicators(findRes []byte) (*providers.ThreatIndicators, error) {
	return nil, nil
}

func (c *ProviderClient) RateHostData(findRes []byte, ratingConfigJSON []byte) (providers.RateResult, error) {
	var ratingConfig providers.RatingConfig

	if err := json.Unmarshal(ratingConfigJSON, &ratingConfig); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalRatingConfigFmt, err)
	}

	var doc HostSearchResult

	var rateResult providers.RateResult

	if err := json.Unmarshal(findRes, &doc); err != nil {
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	rateResult.Score = 0
	rateResult.Detected = false

	if len(doc) > 0 {
		rateResult.Detected = true
		rateResult.Score = ratingConfig.ProviderRatingsConfigs.IPURL.DefaultMatchScore
		rateResult.Reasons = append(rateResult.Reasons, fmt.Sprintf("matched prefix in %d ip sets", len(doc)))
	}

	return rateResult, nil
}

func loadTestData() ([]byte, error) {
	resultsFile, err := helpers.PrefixProjectRoot("providers/ipurl/testdata/ipurl_5_105_62_60_report.json")
	if err != nil {
		return nil, fmt.Errorf("error getting abuseipdb test data file path: %w", err)
	}

	tdf, err := providers.LoadResultsFile[HostSearchResult](resultsFile)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	if c.UseTestData {
		return loadTestData()
	}

	pwp := make(map[netip.Prefix][]string)

	err := c.loadProviderDataFromCache(pwp)
	if err != nil {
		return nil, err
	}

	var matches map[netip.Prefix][]string

	for prefix, urls := range pwp {
		if prefix.Contains(c.Host) {
			c.Logger.Info("ipurl match found", "host", c.Host.String(), "urls", urls)

			if matches == nil {
				matches = make(map[netip.Prefix][]string)
			}

			matches[prefix] = urls
		}
	}

	if matches == nil {
		return nil, fmt.Errorf("%s match failed: %w", ProviderName, providers.ErrNoMatchFound)
	}

	var raw []byte

	raw, err = json.Marshal(matches)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	return raw, nil
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating ipurl client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

type ProviderClient struct {
	session.Session
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising ipurl client")

	err := c.refreshURLCache()
	if err != nil {
		return err
	}

	return nil
}

// refreshURLCache checks the cache for each of the urls in the session and loads them into cache if not found
func (c *ProviderClient) refreshURLCache() error {
	// refresh list
	var refreshList []string

	for _, u := range c.Providers.IPURL.URLs {
		if c.Config.Global.DisableCache {
			c.Logger.Debug("cache disabled, refreshing all ipurl urls")

			refreshList = append(refreshList, u)

			continue
		}

		if ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName+"_"+generateURLHash(u)); err != nil {
			return fmt.Errorf("error checking cache for ipurl provider data: %w", err)
		} else if !ok {
			// add to refresh list
			refreshList = append(refreshList, u)
		}
	}

	c.Logger.Debug("refreshing ipurl cache",
		"urls", len(c.Providers.IPURL.URLs),
		"fresh", len(c.Providers.IPURL.URLs)-len(refreshList),
		"not in cache", len(refreshList))

	if len(refreshList) == 0 {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseUsedCache[ProviderName] = true
		c.Stats.Mu.Unlock()

		return nil
	}

	if err := c.loadProviderURLsFromSource(refreshList); err != nil {
		return err
	}

	return nil
}

// generateURLHash concatenates the provider name and the url string and returns a hash
func generateURLHash(us string) string {
	h := sha256.New()
	h.Write([]byte(us))
	r := hex.EncodeToString(h.Sum(nil))

	return r[:providers.CacheKeySHALen]
}

type StoredPrefixes struct {
	Hash     string
	Prefixes map[netip.Prefix][]string
}

type StoredURLPrefixes struct {
	URL      string
	Prefixes []netip.Prefix
}

func (c *ProviderClient) loadProviderURLsFromSource(providerUrls []string) error {
	ic := ipu.New()
	ic.HTTPClient = c.HTTPClient

	var wg sync.WaitGroup

	// create a hash from the slice of urls
	// this will identify the data we cache based of this input
	for _, iu := range providerUrls {
		wg.Add(1)

		go func() {
			defer wg.Done()

			err := c.loadProviderURLFromSource(iu)
			if err != nil {
				c.Logger.Error("error loading provider", "url", iu, "error", err)
			}
		}()
	}

	wg.Wait()

	return nil
}

// loadProviderDataFromSource fetches the data from the source and caches it for individual urls
func (c *ProviderClient) loadProviderURLFromSource(sURL string) error {
	ic := ipu.New()
	ic.HTTPClient = c.HTTPClient

	var requests []ipu.Request

	var pURL *url.URL

	var err error

	if pURL, err = url.Parse(sURL); err != nil {
		return fmt.Errorf("error parsing ipurl provider url: %w", err)
	}

	requests = append(requests, ipu.Request{
		URL:    pURL,
		Method: http.MethodGet,
	})

	hfPrefixes, err := ic.FetchPrefixes(requests)
	if err != nil {
		return fmt.Errorf("error fetching ipurl data: %w", err)
	}

	if len(hfPrefixes) == 0 {
		c.Logger.Warn("no prefixes found for url", "url", sURL)

		return nil
	}

	// log the number of prefixes found
	c.Logger.Debug("found prefixes for url", "url", sURL, "prefixes", len(hfPrefixes))
	// get a list of keys from the prefixes map
	var sPrefixes []netip.Prefix

	for prefix := range hfPrefixes {
		sPrefixes = append(sPrefixes, prefix)
	}

	jPrefix, err := json.Marshal(sPrefixes)
	if err != nil {
		return fmt.Errorf("error marshalling ipurl provider prefixes: %w", err)
	}

	// cache the prefixes for this url
	uh := generateURLHash(sURL)

	docCacheTTL := CacheTTL
	if c.Providers.IPURL.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.IPURL.DocumentCacheTTL)
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName + "_" + uh,
		Value:      jPrefix,
		Version:    "-",
		Created:    time.Now(),
	}, docCacheTTL); err != nil {
		return fmt.Errorf("error upserting ipurl provider data: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderURLDataFromCache(pURL string) ([]netip.Prefix, error) {
	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + generateURLHash(pURL)

	var item *cache.Item

	var err error

	if item, err = cache.Read(c.Logger, c.Cache, cacheKey); err != nil {
		return nil, fmt.Errorf("error reading ipurl provider cache: %w", err)
	}

	if item == nil {
		return nil, fmt.Errorf("no cached data found for %s", cacheKey)
	}

	var prefixes []netip.Prefix
	if err = json.Unmarshal(item.Value, &prefixes); err != nil {
		// if we can't unmarshal the data, it may be an old cache item that needs to be removed
		c.Logger.Warn("error unmarshalling cached ipurl provider doc", "cacheKey", cacheKey, "error", err)
	}

	if err != nil {
		defer func() {
			// remove any data that can't be unmarshalled
			_ = cache.Delete(c.Logger, c.Cache, cacheKey)
		}()

		return nil, fmt.Errorf("error unmarshalling cached ipurl provider doc: %w", err)
	}

	return prefixes, nil
}

func (c *ProviderClient) loadProviderDataFromCache(pwp map[netip.Prefix][]string) error {
	for _, u := range c.Providers.IPURL.URLs {
		prefixes, err := c.loadProviderURLDataFromCache(u)
		if err != nil {
			return err
		}

		for _, prefix := range prefixes {
			pwp[prefix] = append(pwp[prefix], u)
		}
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return nil
}

type HostSearchResult map[netip.Prefix][]string

func unmarshalResponse(rBody []byte) (HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling ipurl api response: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) CreateTable(data []byte) (*table.Writer, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.CreateTableDuration, ProviderName)()

	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling stored ipurl data: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()

	rowEmphasisColour := providers.RowEmphasisColor(c.Session)

	first := true
	for prefix, urls := range result {
		if first {
			// pad column to ensure title row fills the table
			tw.AppendRow(table.Row{
				color.HiWhiteString(providers.PadRight("Prefixes", column1MinWidth)),
				rowEmphasisColour(prefix.String()),
			})

			first = false
		} else {
			tw.AppendRow(table.Row{"", rowEmphasisColour(prefix.String())})
		}

		for _, url := range urls {
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s %s", IndentPipeHyphens, url)})
		}
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: true, WidthMax: providers.WideColumnMaxWidth, WidthMin: column2MinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("IP URL | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("IP URL | Host: 5.105.62.60")
	}

	return &tw, nil
}

const IndentPipeHyphens = " |-----"
