package cache

import (
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/command/agent/proxy"
)

type MockCache struct {
	underlying proxy.Proxier
}

type MockCacheConfig struct {
	Proxier proxy.Proxier
	Logger  hclog.Logger
}

func NewMockCache(conf *MockCacheConfig) (*MockCache, error) {
	return &MockCache{
		underlying: conf.Proxier,
	}, nil
}

func (c *MockCache) Send(req *proxy.Request) (*proxy.Response, error) {
	return c.underlying.Send(req)
}
