package cache

import (
	"encoding/json"
	"errors"
	"github.com/dgraph-io/badger/v4"
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

func Create(path string) (*badger.DB, error) {
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(path, "cache")).WithLogger(nil))
	if err != nil {
		return nil, err
	}

	return db, nil
}

func Upsert(db *badger.DB, item Item) error {
	mItem, err := json.Marshal(item)

	if err != nil {
		return err
	}

	return db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(item.Key), mItem)
	})
}

func Read(db *badger.DB, key string) (*Item, error) {
	var item *Item

	err := db.View(func(txn *badger.Txn) error {
		itemFound, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		return itemFound.Value(func(val []byte) error {
			return json.Unmarshal(val, &item)
		})
	})
	if err != nil {
		return nil, err
	}

	return nil, ErrKeyNotFound
}

func CheckExists(db *badger.DB, key string) (bool, error) {
	var found bool
	err := db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil
			}

			return err
		}

		found = true

		return nil
	})

	if err != nil {
		return false, err
	}

	return found, nil
}

func Delete(db *badger.DB, key string) error {
	return db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}
