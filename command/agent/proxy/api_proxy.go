package proxy

import (
	"context"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/consts"
)

// APIProxy is an implementation of the proxier interface that is used to
// forward the request to Vault and get the response.
type APIProxy struct {
}

func NewAPIProxy() Proxier {
	return &APIProxy{}
}

func (ap *APIProxy) Send(req *Request) (*Response, error) {
	fmt.Printf("===== ForwardProxier.Send() received req: %#v\n", req)

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}

	reqToken := req.Request.Header.Get(consts.AuthHeaderName)
	client.SetToken(reqToken)

	//fmt.Printf("reqToken: %q\n", reqToken)

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
