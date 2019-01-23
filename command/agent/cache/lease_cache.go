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
	"math/rand"
	"net/http"
	"time"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	cachememdb "github.com/hashicorp/vault/command/agent/cache/cachememdb"
	"github.com/hashicorp/vault/helper/contextutil"
	"github.com/hashicorp/vault/helper/jsonutil"
)

// LeaseCache is an implementation of Proxier that handles
// the caching of responses. It passes the incoming request
// to an underlying Proxier implementation.
type LeaseCache struct {
	proxier Proxier
	logger  hclog.Logger
	db      *cachememdb.CacheMemDB
	rand    *rand.Rand
}

// LeaseCacheConfig is the configuration for initializing a new
// Lease
type LeaseCacheConfig struct {
	Proxier Proxier
	Logger  hclog.Logger
}

// NewLeaseCache creates a new instance of a LeaseCache.
func NewLeaseCache(conf *LeaseCacheConfig) (*LeaseCache, error) {
	db, err := cachememdb.NewCacheMemDB()
	if err != nil {
		return nil, err
	}

	lc := &LeaseCache{
		proxier: conf.Proxier,
		logger:  conf.Logger,
		db:      db,
		rand:    rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
	}

	return lc, nil
}

// Send performs a cache lookup on the incoming request. If it's a cache hit, it
// will return the cached response, otherwise it will delegate to the
// underlying Proxier and cache the received response.
func (c *LeaseCache) Send(ctx context.Context, req *SendRequest) (*SendResponse, error) {
	// Compute the CacheKey
	cacheKey, err := computeCacheKey(req.Request)
	if err != nil {
		c.logger.Error("unable to compute cache key", "error", err)
		return nil, err
	}

	// Check if the response for this request is already in the cache
	index, err := c.db.Get("cache_key", cacheKey)
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
	resp, err := c.proxier.Send(ctx, req)
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
	err = resp.Response.Write(&respBytes)
	if err != nil {
		c.logger.Error("unable to serialize response", "error", err)
		return nil, err
	}

	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	c.logger.Info("response not found in the cache, caching response")

	// Build the index to cache based on the response received
	index = &cachememdb.Index{
		CacheKey:    cacheKey,
		TokenID:     req.Token,
		RequestPath: req.Request.URL.Path,
		Response:    respBytes.Bytes(),
		RenewCtx:    context.WithValue(ctx, struct{}{}, cacheKey),
	}

	// Start renewing the secret in the response
	go c.startRenewing(index.RenewCtx, req, respBody)

	// Cache the receive response
	err = c.db.Set(index)
	if err != nil {
		c.logger.Error("unable to cache the proxied response", "error", err)
		return nil, err
	}

	return resp, nil
}

func (c *LeaseCache) startRenewing(ctx context.Context, req *SendRequest, respBody []byte) {
	secret, err := api.ParseSecret(bytes.NewBuffer(respBody))
	if err != nil {
		c.logger.Error("failed to parse secret from response body", "error", err)
		return
	}

	// Start renewals when around half the lease duration is exhausted
	leaseDuration := secret.LeaseDuration
	if secret.Auth != nil {
		leaseDuration = secret.Auth.LeaseDuration
	}
	// Add jitter and backoff until +-10% of half the lease duration
	contextutil.BackoffOrQuit(ctx, time.Second*time.Duration(leaseDuration*(c.rand.Intn(20)+40)/100))

	// Fast path for shutdown
	select {
	case <-ctx.Done():
		c.logger.Info("shutdown triggered, not starting the renewer")
		return
	default:
	}

	renewFunc := func(ctx context.Context, secret *api.Secret) {
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			c.logger.Error("failed to create API client", "error", err)
			return
		}
		client.SetToken(req.Token)

		renewer, err := client.NewRenewer(&api.RenewerInput{
			Secret: secret,
		})
		if err != nil {
			c.logger.Error("failed to create secret renewer", "error", err)
			return
		}
		go renewer.Renew()
		defer renewer.Stop()

		for {
			select {
			case <-ctx.Done():
				c.logger.Info("shutdown triggered, stopping renewer")
				return
			case err := <-renewer.DoneCh():
				if err != nil {
					c.logger.Error("failed to renew secret", "error", err)
					return
				}
				c.logger.Info("renewal completed; evicting from cache")
				// TODO: Renewal process is complete. But this doesn't mean
				// that the cache should evict the response right away. It
				// should stay until its last bits of lease duration is
				// exhausted.
				err = c.db.Evict("cache_key", ctx.Value(struct{}{}).(string))
				if err != nil {
					c.logger.Error("failed to evict index", "error", err)
				}
				return
			case renewal := <-renewer.RenewCh():
				c.logger.Info("renewal received; updating cache")
				err = c.updateResponse(ctx, renewal)
				if err != nil {
					c.logger.Error("failed to handle renewal", "error", err)
					return
				}
			}
		}
	}
	go renewFunc(ctx, secret)
}

func (c *LeaseCache) updateResponse(ctx context.Context, renewal *api.RenewOutput) error {
	// Get the cache key from the renewal context
	cacheKey := ctx.Value(struct{}{}).(string)

	// Get the cached index
	index, err := c.db.Get("cache_key", cacheKey)
	if err != nil {
		return err
	}
	if index == nil {
		return fmt.Errorf("missing cache entry for key: %q", cacheKey)
	}

	// Read the response from the index
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(index.Response)), nil)
	if err != nil {
		c.logger.Error("unable to deserialize response", "error", err)
		return err
	}

	// Update the body in the reponse by the renewed secret
	bodyBytes, err := json.Marshal(renewal.Secret)
	if err != nil {
		return err
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	// Serialize the response
	var respBytes bytes.Buffer
	err = resp.Write(&respBytes)
	if err != nil {
		c.logger.Error("unable to serialize updated response", "error", err)
		return err
	}

	// Update the response in the index and set it in the cache
	index.Response = respBytes.Bytes()
	err = c.db.Set(index)
	if err != nil {
		c.logger.Error("unable to cache the proxied response", "error", err)
		return err
	}

	return nil
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
