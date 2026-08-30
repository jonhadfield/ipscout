package manager

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/jonhadfield/ipscout/providers"

	"github.com/dustin/go-humanize"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jonhadfield/ipscout/cache"
	"github.com/jonhadfield/ipscout/present"
	"github.com/jonhadfield/ipscout/session"
)

type Client struct {
	Config *session.Session
}

func (c *Client) CreateItemsInfoTable(info []CacheItemInfo) (*table.Writer, error) {
	tw := table.NewWriter()

	if len(info) == 0 {
		tw.AppendRow(table.Row{"no cache items found"})
		tw.SetAutoIndex(false)

		return &tw, nil
	}

	tw.AppendHeader(table.Row{"Key", "Expires", "Size", "App Version"})

	for _, x := range info {
		var estimatedSize uint64

		if x.EstimatedSize > 0 {
			estimatedSize = uint64(x.EstimatedSize) //nolint:gosec
		}

		tw.AppendRow(table.Row{x.Key, x.ExpiresAt.Format(providers.TimeFormat), humanize.Bytes(estimatedSize), providers.DashIfEmpty(x.AppVersion)})
	}

	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: false, WidthMax: providers.MaxColumnWidth, WidthMin: providers.MinColumnWidth},
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
	db, err := cache.Create(c.Config.Logger, filepath.Join(c.Config.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("error creating cache: %w", err)
	}

	c.Config.Cache = db

	defer func() { _ = cache.Close(c.Config.Logger, db) }()

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

// GC reclaims value log space until there is nothing left worth rewriting, and
// reports how much of the cache directory that freed.
//
// Closing the cache does a couple of rounds on every run, which keeps growth in
// check going forward. This is the catch-up for a directory that already grew:
// it is unbounded, so it can take a while on a large cache.
func (c *Client) GC() error {
	cachePath := filepath.Join(c.Config.Config.Global.HomeDir, ".config", "ipscout")

	before := dirSize(filepath.Join(cachePath, "cache"))

	db, err := cache.Create(c.Config.Logger, cachePath)
	if err != nil {
		return fmt.Errorf("error creating cache: %w", err)
	}

	c.Config.Cache = db

	rewritten := cache.RunGC(c.Config.Logger, db, 0)

	// The space is only returned once the rewritten files are dropped on close.
	if err = cache.Close(c.Config.Logger, db); err != nil {
		return fmt.Errorf("error closing cache after gc: %w", err)
	}

	after := dirSize(filepath.Join(cachePath, "cache"))

	fmt.Printf("rewrote %d value log file(s)\n", rewritten)
	fmt.Printf("cache went from %s to %s\n", humanBytes(before), humanBytes(after))

	return nil
}

// dirSize totals the regular files under path, returning 0 if it cannot be read.
func dirSize(path string) int64 {
	var total int64

	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable entry just does not count
		}

		if info, statErr := d.Info(); statErr == nil {
			total += info.Size()
		}

		return nil
	})

	return total
}

func humanBytes(b int64) string {
	const unit = 1024

	if b < unit {
		return fmt.Sprintf("%d B", b)
	}

	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func (c *Client) Delete(keys []string) error {
	db, err := cache.Create(c.Config.Logger, filepath.Join(c.Config.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("error creating cache: %w", err)
	}

	c.Config.Cache = db

	defer func() { _ = cache.Close(c.Config.Logger, db) }()

	if err = cache.DeleteMultiple(c.Config.Logger, db, keys); err != nil {
		return fmt.Errorf(cache.ErrDeleteCacheItemsFmt, err)
	}

	return nil
}

func (c *Client) Get(key string, raw bool) error {
	db, err := cache.Create(c.Config.Logger, filepath.Join(c.Config.Config.Global.HomeDir, ".config", "ipscout"))
	if err != nil {
		return fmt.Errorf("error creating cache: %w", err)
	}

	c.Config.Cache = db

	defer func() { _ = cache.Close(c.Config.Logger, db) }()

	item, err := cache.Read(c.Config.Logger, db, key)
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

	db := c.Config.Cache

	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(providers.CacheProviderPrefix)

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()

			ci, err := cache.Read(c.Config.Logger, db, string(k))
			if err != nil {
				return fmt.Errorf(cache.ErrReadCacheItemFmt, err)
			}

			item.ExpiresAt()
			item.EstimatedSize()

			var expiresAt int64
			if item.ExpiresAt() <= math.MaxInt64 {
				expiresAt = int64(item.ExpiresAt()) //nolint:gosec
			}

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
