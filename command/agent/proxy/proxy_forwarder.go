package proxy

import "fmt"

// ForwardProxier is an implementation of the proxier interface that is used to
// forward the request to Vault and get the response.
type ForwardProxier struct {
}

func NewForwardProxier() Proxier {
	return &ForwardProxier{}
}

func (f *ForwardProxier) Send(req *Request) (*Response, error) {
	fmt.Printf("===== ForwardProxier.Send() received req: %#v\n", req)
	return nil, nil
}
