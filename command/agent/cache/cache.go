package cache

import (
	"context"
	"fmt"

	hclog "github.com/hashicorp/go-hclog"
)

type CacheType string

const CacheTypeMemDB CacheType = "memdb"

// Cache is the interface required to serve as an in-memory database for the
// agent cache.
type Cache interface {
	// Set stores the given index in the cache
	Set(index *Index) error

	// Get returns the index based on the index type and the index values
	Get(indexName string, values ...string) (*Index, error)

	// Evict removes an index based on the index type and the index values
	Evict(indexName string, values ...string) error

	// EvictByPrefix removes one or more indexes from the cache based on the
	// index name and the prefix of the index value.
	EvictByPrefix(indexName string, prefix string) error

	// Flush clears out all the entries from the cache
	Flush() error
}

// Index holds the response to be cached along with multiple other values that
// serve as pointers to refer back to this index.
type Index struct {
	// Response is the serialized response object that the agent is caching
	Response []byte

	// CacheKey is a value that uniquely represents the request held by this
	// index. This is computed by serializing and hashing the response object.
	CacheKey string

	// Key is a pointer that is used to refer back to this index. There can
	// be two types of keys: request_path or lease_id.
	Key string

	// KeyType represents the type of the value held by the Key field. This
	// can be `request_path` or `lease_id`.
	KeyType string

	// TokenID is the token used to fetch the response from Vault
	TokenID string

	// Context is the context object for a goroutine that manages the renewal
	// of the secret that belongs to the response in this index. This context
	// is used to stop the renewal process during cache invalidations.
	Context context.Context
}

// Config represents configuration options for cache object creation
type Config struct {
	Logger    hclog.Logger
	CacheType CacheType
}

func New(config *Config) (Cache, error) {
	switch config.CacheType {
	case CacheTypeMemDB:
		return NewCacheMemDB(&CacheMemDBConfig{
			Logger: config.Logger,
		})

	default:
		return nil, fmt.Errorf("unsupported cache type: %q", config.CacheType)
	}
}
