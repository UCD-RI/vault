package cache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/cache/leasecache"
	"github.com/hashicorp/vault/helper/jsonutil"
)

// LeaseCache is an implementation of Proxier that handles
// the caching of responses. It passes the incoming request
// to an underlying Proxier implementation.
type LeaseCache struct {
	underlying Proxier
	logger     hclog.Logger
	db         *leasecache.CacheMemDB
}

// LeaseCacheConfig is the configuration for initializing a new
// Lease
type LeaseCacheConfig struct {
	Proxier Proxier
	Logger  hclog.Logger
}

// NewLeaseCache creates a new instance of a LeaseCache.
func NewLeaseCache(conf *LeaseCacheConfig) (*LeaseCache, error) {
	db, err := leasecache.NewCacheMemDB()
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
func (c *LeaseCache) Send(req *SendRequest) (*SendResponse, error) {
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

		return &SendResponse{
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
		c.logger.Error("unable to read the response body", "error", err)
		return nil, err
	}
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	// Check whether we should cache
	cacheable, err := shouldCache(respBody)
	if err != nil {
		c.logger.Error("unable to parse response body to determine cacheable response", "error", err)
		return nil, err
	}

	if !cacheable {
		return resp, nil
	}

	// Serialize the response to store into the cache
	var respBytes bytes.Buffer
	if err := resp.Response.Write(&respBytes); err != nil {
		c.logger.Error("unable to serialize response", "error", err)
		return nil, err
	}

	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	c.logger.Info("response not found in the cache, caching response")

	// Build the index to cache based on the response received
	index = &leasecache.Index{
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

// HandleClear is returns a handlerFunc that can perform cache clearing operations
func (c *LeaseCache) HandleClear() http.Handler {
	type request struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.logger.Trace("processing cache-clear request")

		req := new(request)

		err := jsonutil.DecodeJSONFromReader(r.Body, req)
		if err != nil && err != io.EOF {
			w.WriteHeader(400)
			return
		}

		switch req.Type {
		case "request_path":
			err = c.db.EvictByPrefix(req.Type, req.Value)
			if err != nil {
				respondError(w, http.StatusInternalServerError, errwrap.Wrapf("unable to evict indexes from cache: {{err}}", err))
				return
			}
		case "token_id":
			err = c.db.EvictAll(req.Type, req.Value)
			if err != nil {
				respondError(w, http.StatusInternalServerError, errwrap.Wrapf("unable to evict index from cache: {{err}}", err))
				return
			}
		case "lease_id":
			err = c.db.Evict(req.Type, req.Value)
			if err != nil {
				respondError(w, http.StatusInternalServerError, errwrap.Wrapf("unable to evict index from cache: {{err}}", err))
				return
			}
		case "all":
			if err := c.db.Flush(); err != nil {
				respondError(w, http.StatusInternalServerError, errwrap.Wrapf("unabled to reset the cache: {{err}}", err))
				return
			}
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid type provided: %v", req.Type))
			return
		}
		// We've successfully cleared the cache
		return
	})
}

// shouldCache determines whether a response should be cached.
// It will return true under any of the following conditions:
// 1. The lease_id value exists and is not an empty string
// 2. The auth block esists and is not nil
func shouldCache(body []byte) (bool, error) {
	rawBody := map[string]interface{}{}
	err := json.Unmarshal(body, &rawBody)
	if err != nil {
		return false, err
	}

	if rawVal, ok := rawBody["lease_id"]; ok {
		if leaseID, ok := rawVal.(string); ok && leaseID != "" {
			return true, nil
		}
	}

	if auth, ok := rawBody["auth"]; ok && auth != nil {
		return true, nil
	}

	return false, nil
}
