package proxy

import "fmt"

// RenewProxy is an implementation of the proxier interface that is used to
// handle renewals of secrets.
type RenewProxy struct {
	proxier Proxier
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
	return rp.proxier.Send(req)
}
