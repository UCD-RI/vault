package apiproxy

import (
	"context"
	"io/ioutil"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/cache"
)

// APIProxy is an implementation of the proxier interface that is used to
// forward the request to Vault and get the response.
type APIProxy struct {
	logger hclog.Logger
}

type Config struct {
	Logger hclog.Logger
}

func New(config *Config) cache.Proxier {
	return &APIProxy{
		logger: config.Logger,
	}
}

func (ap *APIProxy) Send(req *cache.SendRequest) (*cache.SendResponse, error) {
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

	return &cache.SendResponse{
		Response: resp,
	}, nil
}
