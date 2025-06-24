package zscaler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jonhadfield/ipscout/helpers"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/jonhadfield/ipscout/constants"

	"github.com/jedib0t/go-pretty/v6/table"
	ipfetcher "github.com/jonhadfield/ip-fetcher/providers/zscaler"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/jonhadfield/ipscout/session"
)

const (
	ProviderName = "zscaler"
	DocTTL       = 24 * time.Hour
)

type Config struct {
	_ struct{}
	session.Session
	Host netip.Addr
}

type ProviderClient struct {
	session.Session
}

func NewProviderClient(c session.Session) (providers.ProviderClient, error) {
	c.Logger.Debug("creating zscaler client")

	tc := &ProviderClient{
		Session: c,
	}

	return tc, nil
}

func (c *ProviderClient) Enabled() bool {
	if c.UseTestData || (c.Providers.Zscaler.Enabled != nil && *c.Providers.Zscaler.Enabled) {
		return true
	}

	return false
}

func (c *ProviderClient) Priority() *int32 {
	return c.Providers.Zscaler.OutputPriority
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

	if doc.Range == "" {
		return nil, errors.New("no range found in zscaler data")
	}

	indicators["HostedInZscaler"] = "true"

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
		return providers.RateResult{}, fmt.Errorf(constants.ErrUnmarshalFindResultFmt, err)
	}

	if doc.Range == "" {
		return rateResult, errors.New("no prefix found in zscaler data")
	}

	rateResult.Score = ratingConfig.ProviderRatingsConfigs.Zscaler.DefaultMatchScore
	rateResult.Detected = true
	rateResult.Reasons = []string{"hosted in Zscaler"}

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

func unmarshalProviderData(data []byte) (*ipfetcher.Doc, error) {
	var res *ipfetcher.Doc

	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("error unmarshalling zscaler data: %w", err)
	}

	return res, nil
}

func (c *ProviderClient) loadProviderData() error {
	zc := ipfetcher.New()
	zc.Client = c.HTTPClient

	if c.Providers.Zscaler.URL != "" {
		zc.DownloadURL = c.Providers.Zscaler.URL
		c.Logger.Debug("overriding zscaler source", "url", zc.DownloadURL)
	}

	doc, err := zc.Fetch()
	if err != nil {
		return fmt.Errorf("error fetching zscaler data: %w", err)
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("error marshalling zscaler provider doc: %w", err)
	}

	docCacheTTL := DocTTL
	if c.Providers.Zscaler.DocumentCacheTTL != 0 {
		docCacheTTL = time.Minute * time.Duration(c.Providers.Zscaler.DocumentCacheTTL)
	}

	err = cache.UpsertWithTTL(c.Logger, c.Cache, cache.Item{
		AppVersion: c.App.SemVer,
		Key:        providers.CacheProviderPrefix + ProviderName,
		Value:      data,
		Created:    time.Now(),
	}, docCacheTTL)
	if err != nil {
		return fmt.Errorf("error upserting zscaler data: %w", err)
	}

	return nil
}

func (c *ProviderClient) Initialise() error {
	if c.Cache == nil {
		return session.ErrCacheNotSet
	}

	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.InitialiseDuration, ProviderName)()

	c.Logger.Debug("initialising zscaler client")

	ok, err := cache.CheckExists(c.Logger, c.Cache, providers.CacheProviderPrefix+ProviderName)
	if err != nil {
		return fmt.Errorf("checking zscaler cache: %w", err)
	}

	if ok {
		c.Logger.Info("zscaler provider data found in cache")

		return nil
	}

	c.Logger.Info("loading zscaler provider data from source")

	err = c.loadProviderData()
	if err != nil {
		return fmt.Errorf("loading zscaler data: %w", err)
	}

	return nil
}

func (c *ProviderClient) loadProviderDataFromCache() (*ipfetcher.Doc, error) {
	c.Logger.Info("loading zscaler provider data from cache")

	cacheKey := providers.CacheProviderPrefix + ProviderName

	var doc *ipfetcher.Doc

	if item, err := cache.Read(c.Logger, c.Cache, cacheKey); err == nil {
		var uErr error

		doc, uErr = unmarshalProviderData(item.Value)
		if uErr != nil {
			defer func() {
				_ = cache.Delete(c.Logger, c.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached zscaler provider doc: %w", uErr)
		}
	} else {
		return nil, fmt.Errorf("error reading zscaler cache: %w", err)
	}

	c.Stats.Mu.Lock()
	c.Stats.FindHostUsedCache[ProviderName] = true
	c.Stats.Mu.Unlock()

	return doc, nil
}

func loadTestData(c *ProviderClient) ([]byte, error) {
	tdf, err := providers.LoadResultsFile[HostSearchResult]("providers/zscaler/testdata/zscaler_report.json")
	if err != nil {
		return nil, err
	}

	c.Logger.Info("zscaler match returned from test data", "host", "198.51.100.0")

	out, err := json.Marshal(tdf)
	if err != nil {
		return nil, fmt.Errorf("error marshalling test data: %w", err)
	}

	return out, nil
}

func (c *ProviderClient) FindHost() ([]byte, error) {
	defer helpers.TrackDuration(&c.Stats.Mu, c.Stats.FindHostDuration, ProviderName)()

	if c.UseTestData {
		return loadTestData(c)
	}

	doc, err := c.loadProviderDataFromCache()
	if err != nil {
		return nil, err
	}

	result := &HostSearchResult{} // nolint:staticcheck

	ip := net.ParseIP(c.Host.String())
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", c.Host.String())
	}

	zs := reflect.ValueOf(doc.ZscalerNet)

	for i := range zs.NumField() {
		continent := zs.Field(i)
		if continent.Kind() != reflect.Struct {
			continue
		}

		continentName := zs.Type().Field(i).Name

		for j := range continent.NumField() {
			city := continent.Field(j)
			if city.Kind() != reflect.Slice {
				continue
			}

			cityName := continent.Type().Field(j).Name

			for k := range city.Len() {
				entry := city.Index(k)

				r := entry.FieldByName("Range")
				if !r.IsValid() || r.Kind() != reflect.String {
					continue
				}

				var cidr *net.IPNet

				_, cidr, err = net.ParseCIDR(r.String())
				if err != nil {
					continue
				}

				if cidr.Contains(ip) {
					result.Continent = continentName
					result.City = cityName
					result.GRE = entry.FieldByName("Gre").String()
					result.VPN = entry.FieldByName("Vpn").String()
					result.Hostname = entry.FieldByName("Hostname").String()
					result.Latitude = entry.FieldByName("Latitude").String()
					result.Longtitude = entry.FieldByName("Longitude").String()
					result.Range = r.String()

					break
				}
			}
		}
	}

	if result.Range == "" {
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

	var rows []table.Row

	tw.AppendRow(table.Row{providers.PadRight("Prefix", providers.Column1MinWidth), providers.DashIfEmpty(result.Range)})
	tw.AppendRow(table.Row{providers.PadRight("GRE", providers.Column1MinWidth), providers.DashIfEmpty(result.GRE)})
	tw.AppendRow(table.Row{providers.PadRight("Continent", providers.Column1MinWidth), providers.DashIfEmpty(result.Continent)})
	tw.AppendRow(table.Row{providers.PadRight("City", providers.Column1MinWidth), providers.DashIfEmpty(result.City)})
	tw.AppendRow(table.Row{providers.PadRight("Hostname", providers.Column1MinWidth), providers.DashIfEmpty(result.Hostname)})
	tw.AppendRow(table.Row{providers.PadRight("Longtitude", providers.Column1MinWidth), providers.DashIfEmpty(result.Longtitude)})
	tw.AppendRow(table.Row{providers.PadRight("Latitude", providers.Column1MinWidth), providers.DashIfEmpty(result.Latitude)})

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: providers.DataColumnNo, AutoMerge: false, WidthMax: providers.WideColumnMaxWidth, WidthMin: providers.WideColumnMinWidth},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("ZSCALER | Host: %s", c.Host.String())

	if c.UseTestData {
		tw.SetTitle("ZSCALER | Host: %s", "198.51.100.0")
	}

	return &tw, nil
}

type HostSearchResult struct {
	Raw        []byte
	Continent  string `json:"continent"`
	City       string `json:"city"`
	VPN        string `json:"vpn"`
	Range      string `json:"range"`
	GRE        string `json:"gre"`
	Hostname   string `json:"hostname"`
	Latitude   string `json:"latitude"`
	Longtitude string `json:"longitude"`
}
