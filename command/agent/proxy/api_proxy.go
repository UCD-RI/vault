package proxy

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
)

// APIProxy is an implementation of the proxier interface that is used to
// forward the request to Vault and get the response.
type APIProxy struct{}

func NewAPIProxy() Proxier {
	return &APIProxy{}
}

func (ap *APIProxy) Send(req *Request) (*Response, error) {
	fmt.Printf("===== APIProxy.Send() req: %#v\n", req)

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
	resp, err := client.RawRequestWithContext(context.Background(), fwReq)
	if err != nil {
		return nil, err
	}

	return &Response{
		Response: resp,
	}, nil
}

func (ap *APIProxy) Update(req *UpdateRequest) (*UpdateResponse, error) {
	return nil, nil
}
