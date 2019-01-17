package apiproxy

import (
	"net/http"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/cache"
)

type MockAPIProxy struct{}

func NewMockAPIProxy() *MockAPIProxy {
	return &MockAPIProxy{}
}

func (m *MockAPIProxy) Send(req *cache.SendRequest) (*cache.SendResponse, error) {
	return &cache.SendResponse{
		Response: &api.Response{
			Response: &http.Response{},
		},
	}, nil
}
