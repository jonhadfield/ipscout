package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/jonhadfield/ipscout/config"
	"github.com/jonhadfield/ipscout/providers"
	"github.com/mitchellh/go-homedir"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type Item struct {
	Key     string
	Value   []byte
	Version string
	Created time.Time
}

var (
	ErrUpsertFailed      = errors.New("upsert failed")
	ErrCreateCacheFailed = errors.New("create cache failed")
	ErrKeyNotFound       = badger.ErrKeyNotFound
	ErrCreateKeyFailed   = errors.New("create key failed")
	ErrDeleteKeyFailed   = errors.New("delete key failed")
)

type Client struct {
	Config *config.Config
}

func NewClient(config *config.Config) (Client, error) {
	p := Client{
		Config: config,
	}

	return p, nil
}

func (client *Client) List() error {
	homeDir, err := homedir.Dir()
	if err != nil {
		client.Config.Logger.Error("failed to get home directory", "error", err)

		os.Exit(1)
	}

	db, err := Create(client.Config.Logger, filepath.Join(homeDir, ".config", "ipscout"))
	if err != nil {
		client.Config.Logger.Error("failed to create cache", "error", err)

		os.Exit(1)
	}

	client.Config.Cache = db

	defer db.Close()

	db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(providers.CacheProviderPrefix)
		// prefix := []byte(providers.CacheProviderPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				fmt.Printf("key=%s, value=%s\n", k, v[:200])
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return nil
}

func Create(logger *slog.Logger, path string) (*badger.DB, error) {
	logger.Info("creating cache", "path", filepath.Join(path, "cache"))

	db, err := badger.Open(badger.DefaultOptions(filepath.Join(path, "cache")).WithLogger(nil))
	if err != nil {
		return nil, err
	}

	return db, nil
}

func Upsert(logger *slog.Logger, db *badger.DB, item Item) error {
	mItem, err := json.Marshal(item)

	if err != nil {
		return err
	}

	logger.Info("upserting item", "key", item.Key, "value len", len(mItem))
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(item.Key), mItem)
	})
}

func UpsertWithTTL(logger *slog.Logger, db *badger.DB, item Item, ttl time.Duration) error {
	mItem, err := json.Marshal(item)

	if err != nil {
		return err
	}

	logger.Info("upserting item", "key", item.Key, "value len", len(mItem), "ttl", ttl.String())
	return db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(item.Key), mItem).WithTTL(ttl)
		return txn.SetEntry(e)
	})
}

func Read(logger *slog.Logger, db *badger.DB, key string) (*Item, error) {
	logger.Info("reading cache item", "key", key)

	var item *Item

	err := db.View(func(txn *badger.Txn) error {
		itemFound, tErr := txn.Get([]byte(key))
		if tErr != nil {
			return tErr
		}

		return itemFound.Value(func(val []byte) error {
			logger.Info("read cache item", "key", key, "value len", len(val))

			if uErr := json.Unmarshal(val, &item); uErr != nil {
				return uErr
			}

			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return item, nil
}

func CheckExists(logger *slog.Logger, db *badger.DB, key string) (bool, error) {
	logger.Info("checking cache item exists", "key", key)

	var found bool
	err := db.View(func(txn *badger.Txn) error {
		_, tErr := txn.Get([]byte(key))
		if tErr != nil {
			if errors.Is(tErr, badger.ErrKeyNotFound) {
				return nil
			}

			return tErr
		}

		found = true

		return nil
	})
	if err != nil {
		return false, err
	}

	return found, nil
}

func Delete(logger *slog.Logger, db *badger.DB, key string) error {
	logger.Info("deleting cache item", "key", key)

	return db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}
