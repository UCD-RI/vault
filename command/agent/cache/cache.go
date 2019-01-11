package cache

import (
	"context"
	"errors"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

// Index holds all the data for a particular lease or request path.
type Index struct {
	// CacheKey is a hashed key derived from the request.
	CacheKey string

	// Key can be a lease ID, token ID, or request path.
	Key string

	// KeyType is the type of key that's be tracked. It can be lease_id, token_id,
	// or request_path.
	KeyType string

	// TokenID is the token used for this request.
	TokenID string

	// context is the context gets passed into api.Renewer and retrived during
	// cache invalidation to stop renewals.
	Context context.Context

	// Response is the byte representation of the response that we're caching
	Response []byte
}

// Cache is the overaching cache object that holds the cached response along
// with a coulple of indexes.
type Cache struct {
	cache *memdb.MemDB
}

// New creates a new cache object
func New() (*Cache, error) {
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
									Field: "Key",
								},
								&memdb.StringFieldIndex{
									Field: "KeyType",
								},
							},
						},
					},
				},
			},
		},
	}

	cache, err := memdb.NewMemDB(cacheSchema)
	if err != nil {
		return nil, err
	}

	return &Cache{
		cache: cache,
	}, nil
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

// Insert adds an index object into the cache
func (c *Cache) Insert(cacheKey, tokenID string, response []byte) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	// TODO: Properly set Key and KeyType
	index := &Index{
		CacheKey: cacheKey,
		TokenID:  tokenID,
		Response: response,
		Key:      "foo",
		KeyType:  "lease_id",
	}

	if err := txn.Insert("indexer", index); err != nil {
		return fmt.Errorf("unable to insert index into cache: %v", err)
	}

	txn.Commit()

	return nil
}

// Remove deletes entry from the TokenCache submap. If the TokenCache is empty, it will also delete the
// entry from the Cache object.
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
