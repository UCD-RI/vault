package leasecache

import (
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/command/agent/cache"
)

type MockCache struct {
	underlying cache.Proxier
}

type MockCacheConfig struct {
	Proxier cache.Proxier
	Logger  hclog.Logger
}

func NewMockCache(conf *MockCacheConfig) (*MockCache, error) {
	return &MockCache{
		underlying: conf.Proxier,
	}, nil
}

func (c *MockCache) Send(req *cache.SendRequest) (*cache.SendResponse, error) {
	return c.underlying.Send(req)
}
