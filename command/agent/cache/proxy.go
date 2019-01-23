package cache

import (
	"context"
	"net/http"

	"github.com/hashicorp/vault/api"
)

type SendRequest struct {
	Token   string
	Request *http.Request
}

type SendResponse struct {
	Response *api.Response
}

// Proxier is the interface implemented by different components that are
// responsible for performing specific tasks. All these tasks combined together
// would serve the request received by the agent. The components that implement
// this interface are RenewProxy, Cache and APIProxy.
type Proxier interface {
	Send(ctx context.Context, req *SendRequest) (*SendResponse, error)
}
