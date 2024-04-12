package ipurl

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/crosscheck-ip/providers"
	ipfetcherURL "github.com/jonhadfield/ip-fetcher/providers/url"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	ProviderName = "ipurl"
	CacheTTL     = time.Duration(24 * time.Hour)
)

type Config struct {
	_ struct{}
	config.Config
	Host netip.Addr
	URLs []string
}

func (c *ProviderClient) Initialise() error {
	start := time.Now()
	defer func() {
		c.Stats.Mu.Lock()
		c.Stats.InitialiseDuration[ProviderName] = time.Since(start)
		c.Stats.Mu.Unlock()
	}()

	c.Logger.Debug("initialising ipurl client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return err
	}

	if ok {
		c.Logger.Info("ipurl provider data found in cache")

		return nil
	}

	err = c.loadProviderDataFromSource()
	if err != nil {
		return err
	}

	return nil
}

func generateURLsHash(urls []string) string {
	sort.Strings(urls)

	s := strings.Join(urls, "")
	h := sha1.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

type StoredPrefixes struct {
	Hash     string
	Prefixes map[netip.Prefix][]string
}

func (c *ProviderClient) loadProviderDataFromSource() error {
	ic := ipfetcherURL.New(ipfetcherURL.WithHttpClient(c.HttpClient))
	ic.HttpClient = c.HttpClient
	var reqs []ipfetcherURL.Request

	// create a hash from the slice of urls
	// this will identify the data we cache based of this input
	urlsHash := generateURLsHash(c.Providers.IPURL.URLs)

	for _, iu := range c.Providers.IPURL.URLs {
		u, err := url.Parse(iu)
		if err != nil {
			return err
		}

		reqs = append(reqs, ipfetcherURL.Request{
			Method: http.MethodGet,
			Url:    u,
		})
	}

	prefixes, err := ic.FetchPrefixes(reqs)
	if err != nil {
		return err
	}

	// fmt.Println("prefixes", prefixes)
	var mStoredPrefixes []byte
	if mStoredPrefixes, err = json.Marshal(StoredPrefixes{Prefixes: prefixes, Hash: urlsHash}); err != nil {
		return err
	}

	if err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		Key:     providers.CacheProviderPrefix + ProviderName + "_" + urlsHash,
		Value:   mStoredPrefixes,
		Version: urlsHash,
		Created: time.Now(),
	}, CacheTTL); err != nil {
		return err
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*StoredPrefixes, error) {
	cacheKey := providers.CacheProviderPrefix + ProviderName + "_" + generateURLsHash(c.Providers.IPURL.URLs)
	var doc *StoredPrefixes
	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error
		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached ipurl provider doc: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("error reading ipurl provider cache: %w", err)
	}

	return doc, nil
}

func unmarshalProviderData(rBody []byte) (*StoredPrefixes, error) {
	var res *StoredPrefixes

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, err
	}

	return res, nil
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

	var err error
	// load test results data
	// if c.UseTestData {
	// 	var loadErr error
	// 	out, loadErr = loadTestData(c)
	// 	if err != nil {
	// 		return nil, loadErr
	// 	}
	//
	// 	c.Logger.Info("ipurl match returned from test data", "host", c.Host.String())
	//
	// 	return out, nil
	// }

	hash := generateURLsHash(c.Providers.IPURL.URLs)

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	var matches map[netip.Prefix][]string

	for prefix, urls := range doc.Prefixes {
		if prefix.Contains(c.Host) {
			fmt.Printf("prefix: %s - %s\n", prefix, urls)
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

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("%s/backups/ipurl_%s_report.json", config.GetConfigRoot("", config.AppName),
			hash), raw, 0600); err != nil {
			panic(err)
		}
		c.Logger.Info("backed up ipurl response", "host", c.Host.String())
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

type HostSearchResult map[netip.Prefix][]string

func unmarshalResponse(rBody []byte) (HostSearchResult, error) {
	var res HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("error unmarshalling criminalip api response: %w", err)
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
	// if c.UseTestData {
	// 	tw.SetTitle("IP URLs | Host: %s", result.IP)
	// }

	return &tw, nil
}

const MaxColumnWidth = 120

const IndentPipeHyphens = " |-----"
