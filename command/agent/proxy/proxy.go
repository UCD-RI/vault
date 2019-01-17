package proxy

import (
	"net/http"

	"github.com/hashicorp/vault/api"
)

type Request struct {
	CacheKey string
	Token    string
	Request  *http.Request
}

type Response struct {
	Response *api.Response
}

type UpdateRequest struct {
	Request *http.Request
	Renewal *api.RenewOutput
}

type UpdateResponse struct{}

// Proxier is the interface implemented by different components that are
// responsible for performing specific tasks. All these tasks combined together
// would serve the request received by the agent. The components that implement
// this interface are RenewProxy, Cache and APIProxy.
type Proxier interface {
	Send(*Request) (*Response, error)
	Update(*UpdateRequest) (*UpdateResponse, error)
}
