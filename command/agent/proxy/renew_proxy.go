package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
)

// RenewProxy is an implementation of the proxier interface that is used to
// handle renewals of secrets.
type RenewProxy struct {
	contexts map[string]context.Context
	proxier  Proxier
}

type RenewProxyConfig struct {
	Proxier Proxier
}

func NewRenewProxy(config *RenewProxyConfig) Proxier {
	return &RenewProxy{
		proxier: config.Proxier,
	}
}

func (rp *RenewProxy) Send(req *Request) (*Response, error) {
	fmt.Printf("===== RenewProxy.Send() req: %#v\n", req)
	resp, err := rp.proxier.Send(req)
	if err != nil {
		return nil, err
	}

	fmt.Printf("response in renew proxy: %#v\n", resp.Response)

	body, err := ioutil.ReadAll(resp.Response.Body)
	if err != nil {
		return nil, err
	}
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	secret, err := api.ParseSecret(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	fmt.Printf("===== RenewProxy: secret: %#v\n", secret)

	// TODO: Lot of things still needs to be addressed in this function
	rp.handleSecret(req, secret)

	return resp, nil
}

func (rp *RenewProxy) handleSecret(req *Request, secret *api.Secret) {
	fmt.Printf("===== handleSecret: secret.Auth: %#v\n", secret.Auth)
	renewSecret := func(ctx context.Context, secret *api.Secret) {
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			fmt.Printf("failed to create API client: %v\n", err)
			return
		}
		client.SetToken(req.Token)

		renewer, err := client.NewRenewer(&api.RenewerInput{
			Secret: secret,
		})
		if err != nil {
			fmt.Printf("failed to create renewer: %v", err)
			return
		}
		fmt.Printf("===== invoking renewer\n")
		go renewer.Renew()

		for {
			select {
			case <-ctx.Done():
				fmt.Printf("shutdown triggered, stopping renewer\n")
				renewer.Stop()
				return
			case err := <-renewer.DoneCh():
				if err != nil {
					fmt.Printf("failed to renew secret: %v", err)
					return
				}
				return
			case renewal := <-renewer.RenewCh():
				fmt.Printf("===== successful renewal: %#v\n", renewal.Secret.Auth)
				// Inform cache proxy about the renewal
				_, err = rp.proxier.Update(&UpdateRequest{
					Request: req.Request,
					Renewal: renewal,
				})
				if err != nil {
					fmt.Printf("failed to update renewal data in the cache proxy: %v\n", err)
					return
				}
			}
		}
	}
	go renewSecret(context.Background(), secret)
}

func (rp *RenewProxy) Update(req *UpdateRequest) (*UpdateResponse, error) {
	return nil, nil
}
