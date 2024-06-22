package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/jonhadfield/ipscout/providers"

	"github.com/dustin/go-humanize"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/session"
	"github.com/mitchellh/go-homedir"
)

const MaxColumnWidth = 60

type Client struct {
	Config *session.Session
}

var timeFormat = "2006-01-02 15:04:05 MST"

func (c *Client) CreateItemsInfoTable(info []CacheItemInfo) (*table.Writer, error) {
	tw := table.NewWriter()

	if len(info) == 0 {
		tw.AppendRow(table.Row{"no cache items found"})
		tw.SetAutoIndex(false)

		return &tw, nil
	}

	tw.AppendHeader(table.Row{"Key", "Expires", "Size", "App Version"})

	for _, x := range info {
		tw.AppendRow(table.Row{x.Key, x.ExpiresAt.Format(timeFormat), humanize.Bytes(uint64(x.EstimatedSize)), present.DashIfEmpty(x.AppVersion)})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 20},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("CACHE ITEMS")

	return &tw, nil
}

func NewClient(config *session.Session) (Client, error) {
	p := Client{
		Config: config,
	}

	return p, nil
}

func (c *Client) List() error {
	homeDir, err := homedir.Dir()
	if err != nil {
		c.Config.Logger.Error("failed to get home directory", "error", err)

		os.Exit(1)
	}

	db, err := cache.Create(c.Config.Logger, filepath.Join(homeDir, ".config", "ipscout"))
	if err != nil {
		c.Config.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	c.Config.Cache = db

	defer db.Close()

	cacheItemsInfo, err := c.GetCacheItemsInfo()
	if err != nil {
		return err
	}

	tables, err := c.CreateItemsInfoTable(cacheItemsInfo)
	if err != nil {
		return err
	}

	present.Tables(c.Config, []providers.TableWithPriority{
		{
			Table: tables,
			// Priority: 0,
		},
	})

	return nil
}

func (c *Client) Delete(keys []string) error {
	homeDir, err := homedir.Dir()
	if err != nil {
		c.Config.Logger.Error("failed to get home directory", "error", err)

		os.Exit(1)
	}

	db, err := cache.Create(c.Config.Logger, filepath.Join(homeDir, ".config", "ipscout"))
	if err != nil {
		c.Config.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	c.Config.Cache = db

	defer db.Close()

	if err = cache.DeleteMultiple(c.Config.Logger, db, keys); err != nil {
		return fmt.Errorf("error deleting cache items: %w", err)
	}

	return nil
}

func (c *Client) Get(key string, raw bool) error {
	homeDir, err := homedir.Dir()
	if err != nil {
		c.Config.Logger.Error("failed to get home directory", "error", err)

		os.Exit(1)
	}

	db, err := cache.Create(c.Config.Logger, filepath.Join(homeDir, ".config", "ipscout"))
	if err != nil {
		c.Config.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	c.Config.Cache = db

	defer db.Close()

	item, err := cache.Read(c.Config.Logger, db, key)
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

	db := c.Config.Cache

	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(providers.CacheProviderPrefix)
		// prefix := []byte(providers.CacheProviderPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()

			ci, err := cache.Read(c.Config.Logger, db, string(k))
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
