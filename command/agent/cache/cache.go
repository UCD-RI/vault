package cache

import "context"

// Database is the interface required to serve as an in-memory
type Database interface {
	Put(index *Index) error
	Get(keyType string, factors ...string) *Index
	Delete(keyType string, factors ...string) error
}

// Index holds all the data for a particular lease or request path
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
