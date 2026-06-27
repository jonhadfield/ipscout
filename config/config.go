package config

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/dgraph-io/badger/v4"
	"github.com/jonhadfield/ipscout/providers"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers/annotated"
	"github.com/jonhadfield/ipscout/providers/ipurl"
	"github.com/jonhadfield/ipscout/registry"
	"github.com/jonhadfield/ipscout/session"
)

type Client struct {
	Sess *session.Session
}

func (c *Client) CreateConfigTable() (*table.Writer, error) {
	tw := table.NewWriter()

	tw.AppendHeader(table.Row{"Key", "Value"})
	tw.AppendRow(table.Row{color.HiYellowString("Global")})
	tw.AppendRow(table.Row{color.WhiteString("%sindent_spaces", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.IndentSpaces})
	tw.AppendRow(table.Row{color.WhiteString("%smax_value_chars", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.MaxValueChars})
	tw.AppendRow(table.Row{color.WhiteString("%smax_age", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.MaxAge})
	tw.AppendRow(table.Row{color.WhiteString("%smax_reports", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Global.MaxReports})
	// rating
	tw.AppendRow(table.Row{color.HiYellowString("Rating")})
	tw.AppendRow(table.Row{color.WhiteString("%sconfig_path", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Rating.ConfigPath})
	tw.AppendRow(table.Row{color.WhiteString("%suse_ai", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), c.Sess.Config.Rating.UseAI})

	openAIAPIKeyDefinedOutput := "<not defined>"
	if c.Sess.Config.Rating.OpenAIAPIKey != "" {
		openAIAPIKeyDefinedOutput = "<defined>"
	}

	tw.AppendRow(table.Row{color.WhiteString("%sopenai_api_key", strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)), openAIAPIKeyDefinedOutput})

	tw.AppendRow(table.Row{color.HiYellowString("Providers")})

	providerIndent := strings.Repeat(" ", c.Sess.Config.Global.IndentSpaces)
	fieldIndent := strings.Repeat(" ", providers.IndentSpaces*c.Sess.Config.Global.IndentSpaces)

	// Render every registered provider from the registry so new providers
	// appear here automatically and can never be silently omitted.
	for _, entry := range registry.All() {
		tw.AppendRow(table.Row{color.HiCyanString("%s%s", providerIndent, entry.DisplayName)})

		enabled := false
		if e := entry.Enabled(*c.Sess); e != nil {
			enabled = *e
		}

		tw.AppendRow(table.Row{color.WhiteString("%senabled", fieldIndent), enabled})

		// A few providers have additional list fields worth displaying.
		switch entry.Name {
		case annotated.ProviderName:
			for x, path := range c.Sess.Providers.Annotated.Paths {
				var title string
				if x == 0 {
					title = "paths"
				}

				tw.AppendRow(table.Row{color.WhiteString("%s%s", fieldIndent, title), path})
			}
		case ipurl.ProviderName:
			for x, url := range c.Sess.Providers.IPURL.URLs {
				var title string
				if x == 0 {
					title = "urls"
				}

				tw.AppendRow(table.Row{color.WhiteString("%s%s", fieldIndent, title), url})
			}
		}
	}

	// end
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMax: providers.MaxColumnWidth, WidthMin: providers.MinTableWidth},
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
		return fmt.Errorf(cache.ErrDeleteCacheItemsFmt, err)
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
		return fmt.Errorf(cache.ErrReadCacheFmt, err)
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
	pItem.Created = item.Created.Format(providers.TimeFormat)
	pItem.Value = item.Value

	out, err := json.MarshalIndent(&pItem, "", "  ")
	if err != nil {
		return fmt.Errorf(cache.ErrMarshalItemFmt, err)
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
				return fmt.Errorf(cache.ErrReadCacheItemFmt, err)
			}

			var expiresAt int64

			if item.ExpiresAt() <= math.MaxInt64 {
				expiresAt = int64(item.ExpiresAt()) //nolint:gosec
			}

			item.EstimatedSize()

			cacheItemsInfo = append(cacheItemsInfo, CacheItemInfo{
				Key:           string(k),
				EstimatedSize: item.EstimatedSize(),
				ExpiresAt:     time.Unix(expiresAt, 0),
				AppVersion:    ci.AppVersion,
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf(cache.ErrIteratingCacheFmt, err)
	}

	return cacheItemsInfo, nil
}
