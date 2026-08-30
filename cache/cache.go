package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

type Item struct {
	Key        string
	Value      []byte
	Version    string
	AppVersion string
	Created    time.Time
}

const (
	numLevelZeroTablesStall = 2
	valueLogFileSize        = 128 << 20 // 128 MB
	// gcDiscardRatio is badger's threshold: a value log file is rewritten only
	// if at least this proportion of it is stale. 0.7 is badger's own
	// recommendation — lower values rewrite more often for less reclaimed.
	gcDiscardRatio = 0.7
	// closeGCRounds bounds the rewrites attempted when closing. Each round
	// rewrites at most one file, so a small budget reclaims steadily across
	// runs instead of stalling a single lookup behind a 128 MB rewrite.
	closeGCRounds = 2
)

var (
	ErrUpsertFailed      = errors.New("upsert failed")
	ErrCreateCacheFailed = errors.New("create cache failed")
	ErrKeyNotFound       = badger.ErrKeyNotFound
	ErrCreateKeyFailed   = errors.New("create key failed")
	ErrDeleteKeyFailed   = errors.New("delete key failed")
)

func Create(logger *slog.Logger, path string) (*badger.DB, error) {
	logger.Debug("creating cache", "path", filepath.Join(path, "cache"))

	if path == "" {
		return nil, errors.New("path is empty")
	}

	opts := badger.DefaultOptions(filepath.Join(path, "cache")).
		WithLogger(nil).
		WithNumVersionsToKeep(1).
		WithNumMemtables(1).
		WithNumLevelZeroTables(1).
		WithNumLevelZeroTablesStall(numLevelZeroTablesStall).
		WithValueLogFileSize(valueLogFileSize).
		WithCompactL0OnClose(false).
		WithCompression(options.None).
		WithBlockCacheSize(0)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("error creating cache: %w", err)
	}

	return db, nil
}

// RunGC rewrites value log files whose stale fraction exceeds gcDiscardRatio,
// stopping after rounds rewrites or as soon as there is nothing left worth
// reclaiming. It returns the number of files rewritten.
//
// Badger frees value log space only here. Expiring a key by TTL removes the
// key, not the value behind it, so without this the cache grows without bound:
// 66 live entries totalling 84 MB had reached 16 GB across 548 value log files
// before this existed. Passing rounds <= 0 runs until there is nothing left.
func RunGC(logger *slog.Logger, db *badger.DB, rounds int) int {
	if db == nil {
		return 0
	}

	rewritten := 0

	for i := 0; rounds <= 0 || i < rounds; i++ {
		// RunValueLogGC returns ErrNoRewrite when no file is stale enough,
		// which is the normal stopping condition rather than a failure.
		if err := db.RunValueLogGC(gcDiscardRatio); err != nil {
			if !errors.Is(err, badger.ErrNoRewrite) {
				logger.Debug("cache value log gc stopped", "error", err)
			}

			break
		}

		rewritten++
	}

	if rewritten > 0 {
		logger.Debug("cache value log gc reclaimed files", "files", rewritten)
	}

	return rewritten
}

// Close reclaims a bounded amount of value log space, then closes the database.
// Prefer it over calling db.Close directly so the cache does not grow forever.
func Close(logger *slog.Logger, db *badger.DB) error {
	if db == nil {
		return nil
	}

	RunGC(logger, db, closeGCRounds)

	if err := db.Close(); err != nil {
		return fmt.Errorf("error closing cache: %w", err)
	}

	return nil
}

func UpsertWithTTL(logger *slog.Logger, db *badger.DB, item Item, ttl time.Duration) error {
	mItem, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("error marshalling cache item: %w", err)
	}

	logger.Debug("upserting item", "key", item.Key, "value len", len(mItem), "ttl", ttl.String())

	if int64(len(mItem)) > db.Opts().ValueLogFileSize {
		return fmt.Errorf("cache value too large for key %s: %d bytes exceeds %d byte limit",
			item.Key, len(mItem), db.Opts().ValueLogFileSize)
	}

	err = db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(item.Key), mItem).WithTTL(ttl)

		return txn.SetEntry(e)
	})
	if err != nil {
		return fmt.Errorf("error upserting cache item: %w", err)
	}

	return nil
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
	logger.Debug("deleting cache item", "key", key)

	if err := db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	}); err != nil {
		return fmt.Errorf("error deleting cache item: %w", err)
	}

	return nil
}

func DeleteMultiple(logger *slog.Logger, db *badger.DB, keys []string) error {
	logger.Debug("deleting cache items", "keys", keys)

	var deletedKeys []string

	var missingKeys []string

	err := db.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			_, gErr := txn.Get([]byte(key))
			if gErr != nil {
				if errors.Is(gErr, badger.ErrKeyNotFound) {
					missingKeys = append(missingKeys, key)

					continue
				}

				return fmt.Errorf("error checking cache key %s: %w", key, gErr)
			}

			if dErr := txn.Delete([]byte(key)); dErr != nil {
				return fmt.Errorf("error deleting cache key %s: %w", key, dErr)
			}

			deletedKeys = append(deletedKeys, key)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("error in batch delete transaction: %w", err)
	}

	if len(deletedKeys) == 0 {
		fmt.Println("no cache items deleted")
	} else {
		fmt.Printf("cache items deleted: %d\n", len(deletedKeys))
	}

	if len(missingKeys) > 0 {
		fmt.Printf("cache keys not found: %s\n", strings.Join(missingKeys, ", "))
	}

	return nil
}
