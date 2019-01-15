package cache

import "context"

// Cache is the interface required to serve as an in-memory database for the
// agent cache.
type Cache interface {
	// Set stores the given index in the cache
	Set(index *Index) error

	// Get returns the index based on the index type and the index values
	Get(indexName string, values ...string) (*Index, error)

	// Evict removes an index based on the index type and the index values
	Evict(indexName string, values ...string) error

	// Evict removes one or more indexes from the cache based on the index name
	// and the prefix of the index value.
	EvictByPrefix(indexName string, prefix string) error

	// Flush clears out all the entries from the cache
	Flush() error
}

// Index holds the response that needs to be cached along with multiple other
// values that serve as pointers to refet to this index.
type Index struct {
	// CacheKey is a value that uniquely represents a request. It is derived
	// from the http request received by the agent.
	CacheKey string

	// Key can be a lease ID, token ID, or request path
	Key string

	// KeyType is the type of key that's be tracked. It can be lease_id, token_id,
	// or request_path
	KeyType string

	// TokenID is the token used for this request
	TokenID string

	// Context is the context object for a goroutine that is managing the
	// renewal of the secret that belongs to the response. This context is used
	// to stop the renewal process during cache invalidations.
	Context context.Context

	// Response is the serialized response object that the agent is caching
	Response []byte
}
