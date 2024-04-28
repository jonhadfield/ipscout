package ipurl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcherURL "github.com/jonhadfield/ip-fetcher/providers/url"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers"
)

const (
	ProviderName = "ipurl"
	CacheTTL     = 3 * time.Hour
)

type Config struct {
	_ struct{}
	config.Config
	Host netip.Addr
	URLs []string
}

func (c *ProviderClient) Enabled() bool {
	return c.Config.Providers.IPURL.Enabled
}

func (c *ProviderClient) GetConfig() *config.Config {
	return &c.Config
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.FindHostDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

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
		return nil, fmt.Errorf("ip urls: %w", providers.ErrNoMatchFound)
	}

	var raw []byte
	raw, err = json.Marshal(matches)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	return raw, nil
}

func NewProviderClient(c config.Config) (*ProviderClient, error) {
	c.Logger.Debug("creating ipurl client")

	tc := &ProviderClient{
		Config: c,
	}

	return tc, nil
}

type ProviderClient struct {
	config.Config
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return errors.New("cache not set")
	}

	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising ipurl client")

	err := c.refreshURLCache()
	if err != nil {
		return err
	}

	return nil
}

// refreshURLCache checks the cache for each of the urls in the config and loads them into cache if not found
func (c *ProviderClient) refreshURLCache() error {
	// refresh list
	var refreshList []string

	for _, u := range c.Providers.IPURL.URLs {
		if c.Global.DisableCache {
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
	ic := ipfetcherURL.New(ipfetcherURL.WithHttpClient(c.HttpClient))
	ic.HttpClient = c.HttpClient

	var wg sync.WaitGroup

	// create a hash from the slice of urls
	// this will identify the data we cache based of this input
	for _, iu := range providerUrls {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, err := c.loadProviderURLFromSource(iu)
			if err != nil {
				c.Logger.Error("error loading provider", "url", iu, "error", err)
			}
		}()
	}

	wg.Wait()

	return nil
}

// loadProviderDataFromSource fetches the data from the source and caches it for individual urls
func (c *ProviderClient) loadProviderURLFromSource(pURL string) ([]netip.Prefix, error) {
	hf := ipfetcherURL.HttpFile{
		Client: c.HttpClient,
		Url:    pURL,
	}

	if c.Global.LogLevel == "debug" {
		hf.Debug = true
	}

	hfPrefixes, err := hf.FetchPrefixes()
	if err != nil {
		return nil, fmt.Errorf("error fetching ipurl data: %w", err)
	}

	// cache the prefixes for this url
	var mHfPrefixes []byte

	if mHfPrefixes, err = json.Marshal(hfPrefixes); err != nil {
		return nil, fmt.Errorf("error marshalling ipurl provider doc: %w", err)
	}

	uh := generateURLHash(pURL)

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.Version,
		Key:        providers.CacheProviderPrefix + ProviderName + "_" + uh,
		Value:      mHfPrefixes,
		Version:    "-",
		Created:    time.Now(),
	}, CacheTTL); err != nil {
		return nil, fmt.Errorf("error upserting ipurl provider data: %w", err)
	}

	return hfPrefixes, nil
}

func (c *ProviderClient) loadProviderURLDataFromCache(pURL string) ([]netip.Prefix, error) {
	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + generateURLHash(pURL)
	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		prefixes, uErr := unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached ipurl provider doc: %w", err)
		}

		return prefixes, nil
	} else {
		return nil, fmt.Errorf("error reading ipurl provider cache: %w", err)
	}
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

func unmarshalProviderData(rBody []byte) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix

	if err := json.Unmarshal(rBody, &prefixes); err != nil {
		return nil, fmt.Errorf("error unmarshalling ipurl api response: %w", err)
	}

	return prefixes, nil
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
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.CreateTableDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	result, err := unmarshalResponse(data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling stored ipurl data: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	tw := table.NewWriter()
	tw.AppendRow(table.Row{color.HiWhiteString("Prefixes")})

	for prefix, urls := range result {
		tw.AppendRow(table.Row{"", color.CyanString(prefix.String())})

		for _, url := range urls {
			tw.AppendRow(table.Row{"", fmt.Sprintf("%s %s", IndentPipeHyphens, url)})
		}
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: true, WidthMax: MaxColumnWidth, WidthMin: 10},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("IP URLs | Host: %s", c.Host.String())

	return &tw, nil
}

const MaxColumnWidth = 120

const IndentPipeHyphens = " |-----"
