package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/dgraph-io/badger/v4"
	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/session"
)

const (
	maxColumnWidth = 60
	indentSpaces   = 2
	minTableWidth  = 20
)

type Client struct {
	Sess *session.Session
}

var timeFormat = "2006-01-02 15:04:05 MST"

func (c *Client) CreateConfigTable() (*table.Writer, error) {
	tw := table.NewWriter()

	tw.AppendHeader(table.Row{"Key", "Value"})
	tw.AppendRow(table.Row{color.HiYellowString("Global")})
	tw.AppendRow(table.Row{color.WhiteString("%sindent_spaces", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.IndentSpaces})
	tw.AppendRow(table.Row{color.WhiteString("%smax_value_chars", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.MaxValueChars})
	tw.AppendRow(table.Row{color.WhiteString("%smax_age", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.MaxAge})
	tw.AppendRow(table.Row{color.WhiteString("%smax_reports", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.MaxReports})
	tw.AppendRow(table.Row{color.HiYellowString("Providers")})
	// abuseipdb
	tw.AppendRow(table.Row{color.HiCyanString("%sAbuseIPDB", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	abuseipdbEnabled := false
	if c.Sess.Providers.AbuseIPDB.Enabled != nil {
		abuseipdbEnabled = *c.Sess.Providers.AbuseIPDB.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), abuseipdbEnabled})

	// annotated

	tw.AppendRow(table.Row{color.HiCyanString("%sAnnotated", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	annotatedEnabled := false
	if c.Sess.Providers.Annotated.Enabled != nil {
		annotatedEnabled = *c.Sess.Providers.Annotated.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), annotatedEnabled})

	for x, path := range c.Sess.Providers.Annotated.Paths {
		var pathsTitle string
		if x == 0 {
			pathsTitle = "paths"
		}

		tw.AppendRow(table.Row{color.WhiteString("%s%s", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces), pathsTitle), path})
	}

	// aws
	tw.AppendRow(table.Row{color.HiCyanString("%sAWS", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	awsEnabled := false
	if c.Sess.Providers.AWS.Enabled != nil {
		awsEnabled = *c.Sess.Providers.AWS.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), awsEnabled})

	// azure
	tw.AppendRow(table.Row{color.HiCyanString("%sAzure", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	azureEnabled := false
	if c.Sess.Providers.Azure.Enabled != nil {
		azureEnabled = *c.Sess.Providers.Azure.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), azureEnabled})

	// criminalip
	tw.AppendRow(table.Row{color.HiCyanString("%sCriminalIP", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	criminalipEnabled := false
	if c.Sess.Providers.CriminalIP.Enabled != nil {
		criminalipEnabled = *c.Sess.Providers.CriminalIP.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), criminalipEnabled})

	// digitalocean
	tw.AppendRow(table.Row{color.HiCyanString("%sDigitalocean", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	digitaloceanEnabled := false
	if c.Sess.Providers.DigitalOcean.Enabled != nil {
		digitaloceanEnabled = *c.Sess.Providers.DigitalOcean.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), digitaloceanEnabled})

	// gcp
	tw.AppendRow(table.Row{color.HiCyanString("%sGCP", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	gcpEnabled := false
	if c.Sess.Providers.GCP.Enabled != nil {
		gcpEnabled = *c.Sess.Providers.GCP.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), gcpEnabled})

	// google
	tw.AppendRow(table.Row{color.HiCyanString("%sGoogle", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	googleEnabled := false
	if c.Sess.Providers.Google.Enabled != nil {
		googleEnabled = *c.Sess.Providers.Google.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), googleEnabled})

	// googlebot
	tw.AppendRow(table.Row{color.HiCyanString("%sGooglebot", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	googlebotEnabled := false
	if c.Sess.Providers.Googlebot.Enabled != nil {
		googlebotEnabled = *c.Sess.Providers.Googlebot.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), googlebotEnabled})

	// iCloud Private Relay
	tw.AppendRow(table.Row{color.HiCyanString("%siCloud Private Relay", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	icloudPREnabled := false
	if c.Sess.Providers.ICloudPR.Enabled != nil {
		icloudPREnabled = *c.Sess.Providers.ICloudPR.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), icloudPREnabled})

	// ipapi
	tw.AppendRow(table.Row{color.HiCyanString("%sIPAPI", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	ipapiEnabled := false
	if c.Sess.Providers.IPAPI.Enabled != nil {
		ipapiEnabled = *c.Sess.Providers.IPAPI.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), ipapiEnabled})

	// IPURL
	tw.AppendRow(table.Row{color.HiCyanString("%sIPURL", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	ipurlEnabled := false
	if c.Sess.Providers.IPURL.Enabled != nil {
		ipurlEnabled = *c.Sess.Providers.IPURL.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), ipurlEnabled})

	for x, url := range c.Sess.Providers.IPURL.URLs {
		var urlsTitle string

		if x == 0 {
			urlsTitle = "urls"
		}

		tw.AppendRow(table.Row{color.WhiteString("%s%s", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces), urlsTitle), url})
	}

	// linode
	tw.AppendRow(table.Row{color.HiCyanString("%sLinode", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	linodeEnabled := false

	if c.Sess.Providers.Linode.Enabled != nil {
		linodeEnabled = *c.Sess.Providers.Linode.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), linodeEnabled})

	// ptr
	tw.AppendRow(table.Row{color.HiCyanString("%sPTR", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	ptrEnabled := false
	if c.Sess.Providers.PTR.Enabled != nil {
		ptrEnabled = *c.Sess.Providers.PTR.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), ptrEnabled})

	// shodan
	tw.AppendRow(table.Row{color.HiCyanString("%sShodan", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	shodanEnabled := false
	if c.Sess.Providers.Shodan.Enabled != nil {
		shodanEnabled = *c.Sess.Providers.Shodan.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), shodanEnabled})

	// virustotal
	tw.AppendRow(table.Row{color.HiCyanString("%sVirusTotal", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces))})

	virustotalEnabled := false
	if c.Sess.Providers.VirusTotal.Enabled != nil {
		virustotalEnabled = *c.Sess.Providers.VirusTotal.Enabled
	}

	tw.AppendRow(table.Row{color.WhiteString("%senabled", strings.Repeat(" ", indentSpaces*c.Sess.Config.Global.IndentSpaces)), virustotalEnabled})

	// end
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMax: maxColumnWidth, WidthMin: minTableWidth},
	})

	tw.SetAutoIndex(false)
	tw.SetTitle("CONFIG")

	return &tw, nil
}

func NewClient(config *session.Session) (Client, error) {
	p := Client{
		Sess: config,
	}

	return p, nil
}

func (c *Client) Show() error {
	tables, err := c.CreateConfigTable()
	if err != nil {
		return err
	}

	present.Tables(c.Sess, []providers.TableWithPriority{{Table: tables}})

	return nil
}

func (c *Client) Delete(keys []string) error {
	db, err := cache.Create(c.Sess.Logger, filepath.Join(c.Sess.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	c.Sess.Cache = db

	defer db.Close()

	if err = cache.DeleteMultiple(c.Sess.Logger, db, keys); err != nil {
		return fmt.Errorf("error deleting cache items: %w", err)
	}

	return nil
}

func (c *Client) Get(key string, raw bool) error {
	db, err := cache.Create(c.Sess.Logger, filepath.Join(c.Sess.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}

	c.Sess.Cache = db

	defer db.Close()

	item, err := cache.Read(c.Sess.Logger, db, key)
	if err != nil {
		return fmt.Errorf("error reading cache: %w", err)
	}

	if raw {
		fmt.Printf("%s\n", item.Value)

		return nil
	}

	type PresentationItem struct {
		AppVersion string
		Key        string
		Value      json.RawMessage
		Version    string
		Created    string
	}

	var pItem PresentationItem
	pItem.Key = item.Key
	pItem.AppVersion = item.AppVersion
	pItem.Version = item.Version
	pItem.Created = item.Created.Format(timeFormat)
	pItem.Value = item.Value

	out, err := json.MarshalIndent(&pItem, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling item: %w", err)
	}

	fmt.Printf("%s\n", out)

	return nil
}

type CacheItemInfo struct {
	AppVersion    string
	Key           string
	Value         []byte
	ExpiresAt     time.Time
	EstimatedSize int64
}

func (c *Client) GetCacheItemsInfo() ([]CacheItemInfo, error) {
	var cacheItemsInfo []CacheItemInfo

	db := c.Sess.Cache

	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(providers.CacheProviderPrefix)
		// prefix := []byte(providers.CacheProviderPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()

			ci, err := cache.Read(c.Sess.Logger, db, string(k))
			if err != nil {
				return fmt.Errorf("error reading cache item: %w", err)
			}

			item.ExpiresAt()
			item.EstimatedSize()

			cacheItemsInfo = append(cacheItemsInfo, CacheItemInfo{
				Key:           string(k),
				EstimatedSize: item.EstimatedSize(),
				ExpiresAt:     time.Unix(int64(item.ExpiresAt()), 0),
				AppVersion:    ci.AppVersion,
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error reading cache: %w", err)
	}

	return cacheItemsInfo, nil
}
