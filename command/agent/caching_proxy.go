package agent

import "github.com/hashicorp/vault/api"

type Cache struct {
	data map[string]interface{}
}

type CachingProxy struct {
	client *api.Client
	cache  *Cache
}

type CachingProxyConfig struct {
	Client *api.Client
}

func NewCache() *Cache {
	return &Cache{}
}

func NewCachingProxy(config *CachingProxyConfig) *CachingProxy {
	return &CachingProxy{
		client: config.Client,
		cache:  NewCache(),
	}
}
