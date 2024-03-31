package digitalocean

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/crosscheck-ip/cache"
	"github.com/jonhadfield/crosscheck-ip/config"
	"github.com/jonhadfield/ip-fetcher/providers/digitalocean"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	ProviderName = "digitalocean"
)

type Config struct {
	_ struct{}
	config.Config
	Host   netip.Addr
	APIKey string
}

func loadAPIResponse(host netip.Addr, client *retryablehttp.Client) (res *HostSearchResult, err error) {
	digitaloceanClient := digitalocean.New()
	digitaloceanClient.Client = client

	doc, err := digitaloceanClient.Fetch()
	if err != nil {
		return nil, fmt.Errorf("error fetching digitalocean data: %w", err)
	}

	for _, record := range doc.Records {
		if record.Network.Contains(host) {
			res = &HostSearchResult{
				Record:       record,
				ETag:         doc.ETag,
				LastModified: doc.LastModified,
			}
		}
	}

	if res == nil {
		// fmt.Printf("no digitalocean match for host: %s\n", host.String())
		return nil, nil
	}

	var raw []byte
	raw, err = json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	res.Raw = raw

	// TODO: remove before release
	if os.Getenv("CCI_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("backups/digitalocean_%s_report.json",
			strings.ReplaceAll(host.String(), ".", "_")), raw, 0644); err != nil {
			panic(err)
		}
	}

	return res, nil
}

func unmarshalResponse(rBody []byte) (*HostSearchResult, error) {
	var res *HostSearchResult

	if err := json.Unmarshal(rBody, &res); err != nil {
		return nil, err
	}

	return res, nil
}

type TableCreatorClient struct {
	config.Config
}

func NewTableClient(config config.Config) (*TableCreatorClient, error) {
	tc := &TableCreatorClient{
		Config: config,
	}

	return tc, nil
}

func fetchData(client config.Config) (*HostSearchResult, error) {
	var result *HostSearchResult

	var err error

	if client.UseTestData {
		result, err = loadResultsFile("providers/digitalocean/testdata/digitalocean_18_164_52_75_report.json")
		if err != nil {
			return nil, err
		}

		return result, nil
	}

	cacheKey := fmt.Sprintf("digitalocean_%s_report.json", strings.ReplaceAll(client.Host.String(), ".", "_"))
	var item *cache.Item
	if item, err = cache.Read(client.Cache, cacheKey); err == nil {
		result, err = unmarshalResponse(item.Value)
		if err != nil {
			defer func() {
				fmt.Printf("removing invalid cache item: %s\n", cacheKey)
				cache.Delete(client.Cache, cacheKey)
			}()

			return nil, fmt.Errorf("error unmarshalling cached response: %w", err)
		}

		return result, nil
	}

	result, err = loadAPIResponse(client.Host, client.HttpClient)
	if err != nil {
		return nil, fmt.Errorf("error loading digitalocean api response: %w", err)
	}

	if result == nil {
		cache.Delete(client.Cache, cacheKey)

		return nil, fmt.Errorf("no result found for host: %s", client.Host.String())
	}

	if err = cache.Upsert(client.Cache, cache.Item{
		Key:     cacheKey,
		Value:   result.Raw,
		Created: time.Now(),
	}); err != nil {
		return nil, err
	}

	return result, nil
}

const (
	MaxColumnWidth = 120
)

func (c *TableCreatorClient) CreateTable() (*table.Writer, error) {
	result, err := fetchData(c.Config)
	if err != nil {
		fmt.Printf("error loading digitalocean api response: %v\n", err)
		return nil, fmt.Errorf("error loading digitalocean api response: %w", err)
	}

	tw := table.NewWriter()
	var rows []table.Row
	tw.AppendRow(table.Row{"Prefix", dashIfEmpty(result.Record.NetworkText)})
	tw.AppendRow(table.Row{"Country Code", dashIfEmpty(result.Record.CountryCode)})
	tw.AppendRow(table.Row{"City Name", dashIfEmpty(result.Record.CityName)})
	tw.AppendRow(table.Row{"City Code", dashIfEmpty(result.Record.CityCode)})
	tw.AppendRow(table.Row{"Zip Code", dashIfEmpty(result.Record.ZipCode)})
	if !result.LastModified.IsZero() {
		tw.AppendRow(table.Row{"Source Update", dashIfEmpty(result.LastModified.String())})
	}

	if result.ETag != "" {
		tw.AppendRow(table.Row{"ETag", dashIfEmpty(result.ETag)})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("DigitalOcean IP | Host: %s", c.Host.String())
	if c.UseTestData {
		tw.SetTitle("DigitalOcean IP | Host: %s", result.Record.NetworkText)
	}

	return &tw, nil
}

func loadResultsFile(path string) (res *HostSearchResult, err error) {
	jf, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer jf.Close()

	decoder := json.NewDecoder(jf)

	err = decoder.Decode(&res)
	if err != nil {
		return res, err
	}

	return res, nil
}

type HostSearchResult struct {
	Raw          []byte
	Record       digitalocean.Record `json:"prefix"`
	ETag         string              `json:"etag"`
	LastModified time.Time           `json:"last_modified"`
}

func dashIfEmpty(value interface{}) string {
	switch v := value.(type) {
	case string:
		if len(v) == 0 {
			return "-"
		}
		return v
	case *string:
		if v == nil || len(*v) == 0 {
			return "-"
		}
		return *v
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return "-"
	}
}
