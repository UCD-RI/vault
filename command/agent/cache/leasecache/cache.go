package leasecache

import (
	"fmt"
)

type CacheType string

const (
	CacheTypeMemDB CacheType = "memdb"
)

// Cache is the interface required to serve as an in-memory database for the
// agent cache.
type Cache interface {
	// Set stores the given index in the cache
	Set(index *Index) error

	// Get returns the index based on the index type and the index value
	Get(indexName string, indexValue string) (*Index, error)

	// Evict removes an index based on the index type and the index value
	Evict(indexName string, indexValue string) error

	// EvictAll removes an one or more indexex based on the index type and index value
	EvictAll(indexName string, indexValue string) error

	// EvictByPrefix removes one or more indexes from the cache based on the
	// index name and the prefix of the index value.
	EvictByPrefix(indexName string, prefix string) error

	// Flush clears out all the entries from the cache
	Flush() error
}

// Config represents configuration options for creating the cache
type Config struct {
	CacheType CacheType
}

// New creates a cache object based on the cache type present in the supplied
// configuration
func New(config *Config) (Cache, error) {
	switch config.CacheType {
	case CacheTypeMemDB:
		return NewCacheMemDB()
	default:
		return nil, fmt.Errorf("unsupported cache type: %q", config.CacheType)
	}
}
