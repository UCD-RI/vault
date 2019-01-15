package cache

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	hclog "github.com/hashicorp/go-hclog"
	memdb "github.com/hashicorp/go-memdb"
)

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
func New(conf *Config) (*Cache, error) {
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

// Reset is used to reset the entire cache.
func (c *Cache) Reset() error {
	newDB, err := newDB()
	if err != nil {
		c.logger.Error("error resetting the cache", "error", err)
		return err
	}
	c.cache = newDB
	return nil
}

// Get retrieves the cached object by tokenID and cacheKey.
func (c *Cache) Get(tokenID, cacheKey string) (*Index, error) {
	txn := c.cache.Txn(false)
	defer txn.Abort()

	raw, err := txn.First("indexer", "id", cacheKey)
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

// Insert adds an index object into the cache
func (c *Cache) Insert(index *Index) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	if err := txn.Insert("indexer", index); err != nil {
		return fmt.Errorf("unable to insert index into cache: %v", err)
	}

	txn.Commit()

	return nil
}

// Remove deletes the cached index by tokenID and cacheKey.
func (c *Cache) Remove(tokenID, cacheKey string) error {
	index, err := c.Get(tokenID, cacheKey)
	if err != nil {
		return fmt.Errorf("unable to fetch index on cache deletion: %v", err)
	}

	txn := c.cache.Txn(true)
	defer txn.Abort()

	if err := txn.Delete("indexer", index); err != nil {
		return fmt.Errorf("unable to delete index from cache: %v", err)
	}

	txn.Commit()

	return nil
}

// DeleteByIndex deletes the specified cached index.
func (c *Cache) DeleteByIndex(index *Index) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	if err := txn.Delete("indexer", index); err != nil {
		return fmt.Errorf("unable to delete index from cache: %v", err)
	}

	txn.Commit()

	return nil
}

// DeleteByPrefix deletes all indexes based on the provided on keyType and
// prefix.
func (c *Cache) DeleteByPrefix(keyType, prefix string) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	lookupPrefix := prefix + "_prefix"
	_, err := txn.DeleteAll("indexer", "key", keyType, lookupPrefix)
	if err != nil {
		return fmt.Errorf("unable to delete cache indexes for prefix %q: %v", prefix, err)
	}

	return nil
}

// ComputeCacheKey results in a value that uniquely identifies a request
// received by the agent. It does so by SHA256 hashing the marshalled JSON
// which contains the request path, query parameters and body parameters.
func ComputeCacheKey(req *http.Request) (string, error) {
	var b bytes.Buffer

	// Serialze the request
	if err := req.Write(&b); err != nil {
		return "", fmt.Errorf("unable to serialize request: %v", err)
	}

	sum := sha256.Sum256(b.Bytes())
	return string(sum[:]), nil
}
