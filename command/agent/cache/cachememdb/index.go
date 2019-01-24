package cachememdb

import "context"

type RenewCtxInfo struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
}

// Index holds the response to be cached along with multiple other values that
// serve as pointers to refer back to this index.
type Index struct {
	// ID is a value that uniquely represents the request held by this
	// index. This is computed by serializing and hashing the response object.
	// Required: true, Unique: true
	ID string

	// TokenID is the token fetched the response held by this index
	// Required: true, Unique: false
	TokenID string

	// RequestPath is the path of the request that resulted in the response
	// held by this index.
	// Required: true, Unique: false
	RequestPath string

	// LeaseID is the identifier of the lease in Vault, that belongs to the
	// response held by this index.
	// Required: false, Unique: true
	LeaseID string

	// Response is the serialized response object that the agent is caching.
	Response []byte

	// RenewCtxInfo holds the context and the corresponding cancel func for the
	// goroutine that manages the renewal of the secret belonging to the
	// response in this index.
	RenewCtxInfo *RenewCtxInfo
}

type IndexName uint32

const (
	IndexNameInvalid IndexName = iota
	IndexNameID
	IndexNameLeaseID
	IndexNameRequestPath
	IndexNameTokenID
)

func (indexName IndexName) String() string {
	switch indexName {
	case IndexNameID:
		return "id"
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
	case "id":
		return IndexNameID
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
