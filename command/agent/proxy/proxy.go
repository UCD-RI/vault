package proxy

import (
	"net/http"

	"github.com/hashicorp/vault/logical"
)

type Request struct {
	CacheKey string
	TokenID  string
	Request  *http.Request
}

type Response struct {
	Response *logical.Response
}

// Proxier is the interface implemented by the proxy layers (e.g. caches, API
// client wrapped) that is used to proxy agent requests.
type Proxier interface {
	Send(*Request) (*Response, error)
}
