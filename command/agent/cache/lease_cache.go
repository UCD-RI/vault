package cache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/proxy"
)

// LeaseCache is an implementation of Proxier that handles
// the caching of responses. It passes the incoming request
// to an underlying Proxier implementation.
type LeaseCache struct {
	underlying proxy.Proxier
	logger     hclog.Logger
	db         Cache
}

// LeaseCacheConfig is the configuration for initializing a new
// LeaseCache.
type LeaseCacheConfig struct {
	Proxier proxy.Proxier
	Logger  hclog.Logger
}

// NewLeaseCache creates a new instance of a LeaseCache.
func NewLeaseCache(conf *LeaseCacheConfig) (*LeaseCache, error) {
	dbConf := &Config{
		CacheType: CacheTypeMemDB,
	}
	db, err := New(dbConf)
	if err != nil {
		return nil, err
	}

	lc := &LeaseCache{
		underlying: conf.Proxier,
		logger:     conf.Logger,
		db:         db,
	}

	return lc, nil
}

// Send performs a cache lookup on the incoming request. If it's a cache hit, it
// will return the cached response, otherwise it will delegate to the underlygin
// Proxier and cache the received response.
func (c *LeaseCache) Send(req *proxy.Request) (*proxy.Response, error) {
	// Compute the CacheKey
	cacheKey, err := computeCacheKey(req.Request)
	if err != nil {
		c.logger.Error("unable to compute cache key", "error", err)
		return nil, err
	}
	req.CacheKey = cacheKey

	// Check if the response for this request is already in the cache
	index, err := c.db.Get("cache_key", req.CacheKey)
	if err != nil {
		return nil, err

	}

	// Cached request is found, deserialize the response and return early
	if index != nil {
		c.logger.Info("cached index found, returning cached response")

		reader := bufio.NewReader(bytes.NewReader(index.Response))
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			c.logger.Error("unable to deserialize response", "error", err)
			return nil, err
		}

		return &proxy.Response{
			Response: &api.Response{
				Response: resp,
			},
		}, nil
	}

	// Pass the request down
	resp, err := c.underlying.Send(req)
	if err != nil {
		return nil, err
	}

	// Temporarily hold the response body since serializing the response
	// via http.Response.Write() will close the body. We reset the body
	// after this initial read also after the write call.
	respBody, err := ioutil.ReadAll(resp.Response.Body)
	if err != nil {
		c.logger.Error("unable to read the response body", "err", err)
		return nil, err
	}
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	// Serialize the response to store into the cache
	var respBytes bytes.Buffer
	if err := resp.Response.Write(&respBytes); err != nil {
		c.logger.Error("unable to serialize response", "error", err)
		return nil, err
	}

	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	c.logger.Info("response not found in the cache, caching response")

	// Build the index to cache based on the response received
	index = &Index{
		CacheKey:    req.CacheKey,
		TokenID:     req.Token,
		RequestPath: req.Request.URL.Path,
		Response:    respBytes.Bytes(),
	}

	// TODO: Not sure what to put in as value. The goal is only to derive a
	// renewal specific context and nothing else. The value probably won't
	// be used at all.
	reqCtx := req.Request.Context()
	renewCtx := context.WithValue(reqCtx, "key", req.CacheKey)
	index.Context = renewCtx

	// Cache the receive response
	if err := c.db.Set(index); err != nil {
		c.logger.Error("unable to cache the proxied response", "error", err)
		return nil, err
	}

	return resp, nil
}

// computeCacheKey results in a value that uniquely identifies a request
// received by the agent. It does so by SHA256 hashing the marshalled JSON
// which contains the request path, query parameters and body parameters.
func computeCacheKey(req *http.Request) (string, error) {
	var b bytes.Buffer

	// We need to hold on to the request body to plop it back in since
	// http.Request.Write will close the reader.
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read request body: %v", err)
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	// Serialze the request
	if err := req.Write(&b); err != nil {
		return "", fmt.Errorf("unable to serialize request: %v", err)
	}

	// Reset the request body
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	sum := sha256.Sum256(b.Bytes())
	return string(sum[:]), nil
}
