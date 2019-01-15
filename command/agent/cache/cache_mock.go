package cache

import (
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/command/agent/proxy"
)

type CacheMock struct {
	proxier proxy.Proxier
}

type CacheMockConfig struct {
	Proxier proxy.Proxier
	Logger  hclog.Logger
}

func (c *CacheMock) Send(req *proxy.Request) (*proxy.Response, error) {
	return c.proxier.Send(req)
}

func NewCacheMock(config *CacheMockConfig) (Cache, error) {
	return &CacheMock{
		proxier: config.Proxier,
	}, nil
}

func (c *CacheMock) Set(index *Index) error {
	return nil
}

func (c *CacheMock) Get(indexName string, indexValue string) (*Index, error) {
	return nil, nil
}

func (c *CacheMock) Evict(indexName string, indexValue string) error {
	return nil
}

func (c *CacheMock) EvictByPrefix(indexName string, prefix string) error {
	return nil
}

func (c *CacheMock) Flush() error {
	return nil
}
