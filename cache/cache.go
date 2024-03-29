package cache

import (
	"encoding/json"
	"github.com/dgraph-io/badger/v4"
	"time"
)

type Item struct {
	Key     string
	Value   []byte
	Created time.Time
}

func Create() (*badger.DB, error) {
	db, err := badger.Open(badger.DefaultOptions("/tmp/badger").WithLogger(nil))
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
	var item Item

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

	return &item, nil
}

func Delete(db *badger.DB, key string) error {
	return db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}
