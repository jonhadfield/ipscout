package aws

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ip-fetcher/providers/aws"
	"github.com/jonhadfield/noodle/cache"
	"github.com/jonhadfield/noodle/config"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	ProviderName = "aws"
)

type Config struct {
	_ struct{}
	config.Config
	Host   netip.Addr
	APIKey string
}

func loadAPIResponse(host netip.Addr, client *retryablehttp.Client) (res *HostSearchResult, err error) {
	awsClient := aws.New()
	awsClient.Client = client

	doc, etag, err := awsClient.Fetch()
	if err != nil {
		return nil, fmt.Errorf("error fetching aws data: %w", err)
	}

	if host.Is4() {
		for _, prefix := range doc.Prefixes {
			if prefix.IPPrefix.Contains(host) {
				res = &HostSearchResult{
					Prefix: aws.Prefix{
						IPPrefix: prefix.IPPrefix,
						Region:   prefix.Region,
						Service:  prefix.Service,
					},
				}
			}
		}
	}

	if host.Is6() {
		for _, prefix := range doc.IPv6Prefixes {
			if prefix.IPv6Prefix.Contains(host) {
				res = &HostSearchResult{
					Prefix: aws.Prefix{
						IPPrefix: prefix.IPv6Prefix,
						Region:   prefix.Region,
						Service:  prefix.Service,
					},
				}
			}
		}
	}

	res.SyncToken = doc.SyncToken
	res.CreateDate, err = time.Parse("2006-01-02-15-04-05", doc.CreateDate)
	if err != nil {
		return nil, fmt.Errorf("error parsing create date: %w", err)
	}

	res.ETag = etag

	var raw []byte
	raw, err = json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response: %w", err)
	}

	res.Raw = raw

	// TODO: remove before release
	if os.Getenv("NOODLE_BACKUP_RESPONSES") == "true" {
		if err = os.WriteFile(fmt.Sprintf("backups/aws_%s_report.json",
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
		result, err = loadResultsFile("providers/aws/testdata/aws_18_164_52_75_report.json")
		if err != nil {
			return nil, err
		}

		return result, nil
	}

	cacheKey := fmt.Sprintf("aws_%s_report.json", strings.ReplaceAll(client.Host.String(), ".", "_"))
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
		return nil, fmt.Errorf("error loading aws api response: %w", err)
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
		return nil, fmt.Errorf("error loading aws api response: %w", err)
	}

	tw := table.NewWriter()
	var rows []table.Row
	tw.AppendRow(table.Row{"Prefix", dashIfEmpty(result.Prefix.IPPrefix.String())})
	tw.AppendRow(table.Row{"Service", dashIfEmpty(result.Prefix.Service)})
	tw.AppendRow(table.Row{"Region", dashIfEmpty(result.Prefix.Region)})
	if !result.CreateDate.IsZero() {
		tw.AppendRow(table.Row{"Source Update", dashIfEmpty(result.CreateDate.String())})
	}

	if result.SyncToken != "" {
		tw.AppendRow(table.Row{"Sync Token", dashIfEmpty(result.SyncToken)})
	}

	if result.ETag != "" {
		tw.AppendRow(table.Row{"ETag", dashIfEmpty(result.ETag)})
	}

	tw.AppendRows(rows)
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 50},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("AWS IP | Host: %s", c.Host.String())
	if c.UseTestData {
		tw.SetTitle("AWS IP | Host: %s", result.Prefix.IPPrefix.String())
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
	Raw            []byte
	aws.Prefix     `json:"prefix"`
	aws.IPv6Prefix `json:"ipv6Prefix"`
	ETag           string    `json:"etag"`
	SyncToken      string    `json:"syncToken"`
	CreateDate     time.Time `json:"createDate"`
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
