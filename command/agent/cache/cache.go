package cache

import (
	"context"
	"errors"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

// Index holds all the data for a particular lease or request path.
type Index struct {
	// RequestKey is a hashed key derived from the request.
	RequestKey string

	// TrackedKey can be a lease ID, token ID, or request path.
	TrackedKey string

	// TrackedKeyType is the type of key that's be tracked. It can be lease_id, token_id,
	// or request_path.
	TrackedKeyType string

	// TokenID is the token used for this request.
	TokenID string

	// context is the context gets passed into api.Renewer and retrived during
	// cache invalidation to stop renewals.
	Context context.Context

	// Data is the byte representation of the response that we're caching
	Data []byte
}

// Cache is the overaching cache object that holds the caehed response data
// grouped by token ID.
type Cache struct {
	cache *memdb.MemDB
}

// New creates a new cache map object.
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
							Field: "RequestKey",
						},
					},
					"tracked_key": &memdb.IndexSchema{
						Name:   "tracked_key",
						Unique: true,
						Indexer: &memdb.CompoundIndex{
							Indexes: []memdb.Indexer{
								&memdb.StringFieldIndex{
									Field: "TrackedKey",
								},
								&memdb.StringFieldIndex{
									Field: "TrackedKeyType",
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

// Get retrieves the cached data by tokenID and requestKey.
func (c *Cache) Get(tokenID, requestKey string) (*Index, error) {
	txn := c.cache.Txn(false)
	defer txn.Abort()

	raw, err := txn.First("indexer", "id", requestKey)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	data, ok := raw.(*Index)
	if !ok {
		return nil, errors.New("unable to parse index value from the cache")
	}

	return data, nil
}

// Insert adds an entry in to the submap. It takes the two indexes, tokenID and
// requetKey, and stores the CachedData in the proper location.
func (c *Cache) Insert(requestKey, tokenID string, data []byte) error {
	txn := c.cache.Txn(true)
	defer txn.Abort()

	// TODO: Properly set TrackedKey and TrackedKeyType
	index := &Index{
		RequestKey:     requestKey,
		TokenID:        tokenID,
		Data:           data,
		TrackedKey:     "foo",
		TrackedKeyType: "lease_id",
	}

	if err := txn.Insert("indexer", index); err != nil {
		return fmt.Errorf("unable to insert data into  cache: %v", err)
	}

	txn.Commit()

	return nil
}

// Remove deletes entry from the TokenCache submap. If the TokenCache is empty, it will also delete the
// entry from the Cache object.
func (c *Cache) Remove(tokenID, requestKey string) error {
	index, err := c.Get(tokenID, requestKey)
	if err != nil {
		return fmt.Errorf("unable to fetch index on cache deletion: %v", err)
	}

	txn := c.cache.Txn(true)
	defer txn.Abort()

	if err := txn.Delete("indexer", index); err != nil {
		return fmt.Errorf("unable to delete data from cache: %v", err)
	}

	txn.Commit()

	return nil
}
