package cache

import (
	"context"
	"io/ioutil"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
)

// APIProxy is an implementation of the proxier interface that is used to
// forward the request to Vault and get the response.
type APIProxy struct {
	logger hclog.Logger
}

type APIProxyConfig struct {
	Logger hclog.Logger
}

func NewAPIProxy(config *APIProxyConfig) Proxier {
	return &APIProxy{
		logger: config.Logger,
	}
}

func (ap *APIProxy) Send(req *SendRequest) (*SendResponse, error) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	client.SetToken(req.Token)

	fwReq := client.NewRequest(req.Request.Method, req.Request.URL.Path)
	fwReq.BodyBytes, err = ioutil.ReadAll(req.Request.Body)
	if err != nil {
		return nil, err
	}

	// Make the request to Vault and get the response
	ap.logger.Info("forwarding request", "path", req.Request.RequestURI)
	resp, err := client.RawRequestWithContext(context.Background(), fwReq)
	if err != nil {
		return nil, err
	}

	return &SendResponse{
		Response: resp,
	}, nil
}
