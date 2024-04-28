package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
)

type Item struct {
	Key        string
	Value      []byte
	Version    string
	AppVersion string
	Created    time.Time
}

var (
	ErrUpsertFailed      = errors.New("upsert failed")
	ErrCreateCacheFailed = errors.New("create cache failed")
	ErrKeyNotFound       = badger.ErrKeyNotFound
	ErrCreateKeyFailed   = errors.New("create key failed")
	ErrDeleteKeyFailed   = errors.New("delete key failed")
)

func Create(logger *slog.Logger, path string) (*badger.DB, error) {
	logger.Info("creating cache", "path", filepath.Join(path, "cache"))

	db, err := badger.Open(badger.DefaultOptions(filepath.Join(path, "cache")).WithLogger(nil))
	if err != nil {
		return nil, fmt.Errorf("error creating cache: %w", err)
	}

	return db, nil
}

func UpsertWithTTL(logger *slog.Logger, db *badger.DB, item Item, ttl time.Duration) error {
	mItem, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("error marshalling cache item: %w", err)
	}

	logger.Info("upserting item", "key", item.Key, "value len", len(mItem), "ttl", ttl.String())
	return db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(item.Key), mItem).WithTTL(ttl)
		return txn.SetEntry(e)
	})
}

func Read(logger *slog.Logger, db *badger.DB, key string) (*Item, error) {
	logger.Debug("reading cache item", "key", key)

	var item *Item

	err := db.View(func(txn *badger.Txn) error {
		itemFound, tErr := txn.Get([]byte(key))
		if tErr != nil {
			return fmt.Errorf("error getting cache item: %w", tErr)
		}

		return itemFound.Value(func(val []byte) error {
			logger.Debug("read cache item", "key", key, "value len", len(val))

			if uErr := json.Unmarshal(val, &item); uErr != nil {
				return fmt.Errorf("error unmarshalling cache item: %w", uErr)
			}

			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("error reading cache item: %w", err)
	}

	return item, nil
}

func CheckExists(logger *slog.Logger, db *badger.DB, key string) (bool, error) {
	logger.Debug("checking cache item exists", "key", key)

	var found bool

	err := db.View(func(txn *badger.Txn) error {
		_, tErr := txn.Get([]byte(key))
		if tErr != nil {
			if errors.Is(tErr, badger.ErrKeyNotFound) {
				return nil
			}

			return fmt.Errorf("error getting cache item: %w", tErr)
		}

		found = true

		return nil
	})
	if err != nil {
		return false, fmt.Errorf("error checking cache item exists: %w", err)
	}

	return found, nil
}

func Delete(logger *slog.Logger, db *badger.DB, key string) error {
	logger.Info("deleting cache item", "key", key)

	return db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

func DeleteMultiple(logger *slog.Logger, db *badger.DB, keys []string) error {
	logger.Info("deleting cache items", "keys", keys)

	var deleted int

	var notfound int

	for _, key := range keys {
		found, err := CheckExists(logger, db, key)
		if err != nil {
			return err
		}

		if !found {
			notfound++
			continue
		}

		if err = Delete(logger, db, key); err != nil {
			return err
		}

		deleted++
	}

	fmt.Printf("cache items deleted: %d not found: %d\n", deleted, notfound)

	return nil
}
