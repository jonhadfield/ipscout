package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dustin/go-humanize"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/mitchellh/go-homedir"
)

const MaxColumnWidth = 60

type Client struct {
	Config *config.Config
}

var timeFormat = "2006-01-02 15:04:05 MST"

func (c *Client) CreateItemsInfoTable(info []CacheItemInfo) (*table.Writer, error) {
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"Key", "Expires", "Size"})
	for _, x := range info {
		tw.AppendRow(table.Row{x.Key, x.ExpiresAt.Format(timeFormat), humanize.Bytes(uint64(x.EstimatedSize))})
	}
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMax: MaxColumnWidth, WidthMin: 20},
	})
	tw.SetAutoIndex(false)
	tw.SetTitle("CACHE ITEMS")

	return &tw, nil
}

func NewClient(config *config.Config) (Client, error) {
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

	present.Tables(c.Config, []*table.Writer{tables})

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
		return err
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
		return err
	}

	//var out []byte
	if raw {
		fmt.Printf("%s\n", item.Value)

		return nil
	}

	out, err := json.MarshalIndent(*item, "", "  ")
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", out)

	return nil
}

type CacheItemInfo struct {
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
			item.ExpiresAt()
			item.EstimatedSize()

			cacheItemsInfo = append(cacheItemsInfo, CacheItemInfo{
				Key:           string(k),
				EstimatedSize: item.EstimatedSize(),
				ExpiresAt:     time.Unix(int64(item.ExpiresAt()), 0),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return cacheItemsInfo, nil
}
