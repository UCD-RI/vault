package cache

import (
	"errors"
	"fmt"

	hclog "github.com/hashicorp/go-hclog"
	memdb "github.com/hashicorp/go-memdb"
)

type IndexName uint32

const (
	IndexNameInvalid = iota
	IndexNameCacheKey
	IndexNameLeaseID
	IndexNameRequestPath
	IndexNameTokenID
)

func (indexName IndexName) String() string {
	switch indexName {
	case IndexNameCacheKey:
		return "cache_key"
	case IndexNameLeaseID:
		return "lease_id"
	case IndexNameRequestPath:
		return "request_path"
	case IndexNameTokenID:
		return "token_id"
	}
	return ""
}

func indexName(indexName string) IndexName {
	switch indexName {
	case "cache_key":
		return IndexNameCacheKey
	case "lease_id":
		return IndexNameLeaseID
	case "request_path":
		return IndexNameRequestPath
	case "token_id":
		return IndexNameTokenID
	default:
		return IndexNameInvalid
	}
}

// Cache is the overaching cache object that holds the cached response along
// with a coulple of indexes.
type Cache struct {
	cache  *memdb.MemDB
	logger hclog.Logger
}

// Config is used to provide configuration options to the cache object on creation.
type Config struct {
	Logger hclog.Logger
}

// New creates a new cache object
func New(conf *Config) (Database, error) {
	db, err := newDB()
	if err != nil {
		return nil, err
	}

	return &Cache{
		cache:  db,
		logger: conf.Logger,
	}, nil
}

func newDB() (*memdb.MemDB, error) {
	cacheSchema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			"indexer": &memdb.TableSchema{
				Name: "indexer",
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:   "id",
						Unique: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "CacheKey",
						},
					},
					"key": &memdb.IndexSchema{
						Name:   "key",
						Unique: true,
						Indexer: &memdb.CompoundIndex{
							Indexes: []memdb.Indexer{
								&memdb.StringFieldIndex{
									Field: "KeyType",
								},
								&memdb.StringFieldIndex{
									Field: "Key",
								},
							},
						},
					},
				},
			},
		},
	}

	db, err := memdb.NewMemDB(cacheSchema)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (c *Cache) Get(iName string, values ...string) (*Index, error) {
	in := indexName(iName)
	if in == IndexNameInvalid {
		return nil, fmt.Errorf("invalid index name %q", iName)
	}

	txn := c.cache.Txn(false)
	defer txn.Abort()

	raw, err := txn.First("indexer", "id", values[0])
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	index, ok := raw.(*Index)
	if !ok {
		return nil, errors.New("unable to parse index value from the cache")
	}

	return index, nil
}

func (c *Cache) Set(index *Index) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	if err := txn.Insert("indexer", index); err != nil {
		return fmt.Errorf("unable to insert index into cache: %v", err)
	}

	txn.Commit()

	return nil
}

func (c *Cache) Evict(indexName string, values ...string) error {
	index, err := c.Get(indexName, values...)
	if err != nil {
		return fmt.Errorf("unable to fetch index on cache deletion: %v", err)
	}

	if index == nil {
		return nil
	}

	txn := c.cache.Txn(true)
	defer txn.Abort()

	if err := txn.Delete("indexer", index); err != nil {
		return fmt.Errorf("unable to delete index from cache: %v", err)
	}

	txn.Commit()

	return nil
}

func (c *Cache) Flush() error {
	newDB, err := newDB()
	if err != nil {
		c.logger.Error("error resetting the cache", "error", err)
		return err
	}
	c.cache = newDB
	return nil
}

func (c *Cache) EvictByPrefix(keyType, prefix string) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	lookupPrefix := prefix + "_prefix"
	_, err := txn.DeleteAll("indexer", "key", keyType, lookupPrefix)
	if err != nil {
		return fmt.Errorf("unable to delete cache indexes for prefix %q: %v", prefix, err)
	}

	return nil
}

/*
// GetByType returns the first found cached index of the specified key type.
func (c *Cache) GetByType(key, keyType string) (*Index, error) {
	txn := c.cache.Txn(false)
	defer txn.Abort()

	raw, err := txn.First("indexer", "key", keyType, key)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	index, ok := raw.(*Index)
	if !ok {
		return nil, errors.New("unable to parse index value from the cache")
	}

	return index, nil
}
*/
