package proxy

import (
	"net/http"

	"github.com/hashicorp/vault/api"
)

type MockAPIProxy struct{}

func NewMockAPIProxy() *MockAPIProxy {
	return &MockAPIProxy{}
}

func (m *MockAPIProxy) Send(req *Request) (*Response, error) {
	return &Response{
		Response: &api.Response{
			Response: &http.Response{},
		},
	}, nil
}
