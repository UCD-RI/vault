package cachememdb

import "context"

// Index holds the response to be cached along with multiple other values that
// serve as pointers to refer back to this index.
type Index struct {
	// Response is the serialized response object that the agent is caching
	Response []byte

	// CacheKey is a value that uniquely represents the request held by this
	// index. This is computed by serializing and hashing the response object.
	CacheKey string

	// LeaseID is the identifier of the lease in Vault, that belongs to the
	// response held by this index
	LeaseID string

	// RequestPath is the path of the request that resulted in the response
	// held by this index
	RequestPath string

	// TokenID is the token fetched the response held by this index
	TokenID string

	// RenewCtx is the context object for a goroutine that manages the renewal
	// of the secret that belongs to the response in this index. This context
	// is used to stop the renewal process during cache invalidations.
	RenewCtx context.Context

	// ID is the identifier for the index
	ID string
}

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

func indexNameFromString(indexName string) IndexName {
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
