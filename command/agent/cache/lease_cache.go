package cache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type contextIndex struct{}

var (
	contextIndexID = contextIndex{}
)

type responseType int32

const (
	responseTypeNonCacheable responseType = iota
	responseTypeLease
	responseTypeToken
)

type ContextInfo struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
}

type cacheClearRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// LeaseCache is an implementation of Proxier that handles
// the caching of responses. It passes the incoming request
// to an underlying Proxier implementation.
type LeaseCache struct {
	proxier       Proxier
	logger        hclog.Logger
	db            *cachememdb.CacheMemDB
	rand          *rand.Rand
	tokenContexts map[string]*ContextInfo
	baseCtxInfo   *ContextInfo
}

// LeaseCacheConfig is the configuration for initializing a new
// Lease
type LeaseCacheConfig struct {
	BaseCtxInfo *ContextInfo
	BaseContext context.Context
	Proxier     Proxier
	Logger      hclog.Logger
}

// NewLeaseCache creates a new instance of a LeaseCache.
func NewLeaseCache(conf *LeaseCacheConfig) (*LeaseCache, error) {
	if conf == nil {
		return nil, errors.New("nil configuration provided")
	}

	if conf.Proxier == nil || conf.Logger == nil {
		return nil, fmt.Errorf("missing configuration required params: %v", conf)
	}

	db, err := cachememdb.NewCacheMemDB()
	if err != nil {
		return nil, err
	}

	return &LeaseCache{
		proxier:       conf.Proxier,
		logger:        conf.Logger,
		db:            db,
		rand:          rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
		tokenContexts: make(map[string]*ContextInfo),
		baseCtxInfo:   conf.BaseCtxInfo,
	}, nil
}

// Send performs a cache lookup on the incoming request. If it's a cache hit,
// it will return the cached response, otherwise it will delegate to the
// underlying Proxier and cache the received response.
func (c *LeaseCache) Send(ctx context.Context, req *SendRequest) (*SendResponse, error) {
	// Compute the index ID
	// TODO: Determine whether it's better to pass in a cloned object instead of modifying the incoming one.
	id, err := computeIndexID(req)
	if err != nil {
		c.logger.Error("failed to compute cache key", "error", err)
		return nil, err
	}

	// Check if the response for this request is already in the cache
	index, err := c.db.Get(cachememdb.IndexNameID.String(), id)
	if err != nil {
		return nil, err
	}

	// Cached request is found, deserialize the response and return early
	if index != nil {
		c.logger.Debug("cached index found, returning cached response", "path", req.Request.RequestURI)

		reader := bufio.NewReader(bytes.NewReader(index.Response))
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			c.logger.Error("failed to deserialize response", "error", err)
			return nil, err
		}

		return &SendResponse{
			Response: &api.Response{
				Response: resp,
			},
		}, nil
	}

	// Pass the request down and get a response
	resp, err := c.proxier.Send(ctx, req)
	if err != nil {
		return nil, err
	}

	// Temporarily hold the response body since serializing the response via
	// http.Response.Write() will close the body. Reset the response body
	// afterwards.
	respBody, err := ioutil.ReadAll(resp.Response.Body)
	if err != nil {
		c.logger.Error("failed to read the response body", "error", err)
		return nil, err
	}

	// Reset the response body for http.Response.Write to work
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	// Determine the type of the response
	rType, rValue, err := respType(respBody)
	if err != nil {
		c.logger.Error("failed to determine the response response type", "error", err)
		return nil, err
	}

	// Fast-path for non-cacheable response
	if rType == responseTypeNonCacheable {
		return resp, nil
	}

	// Serialize the response to store into the cache
	var respBytes bytes.Buffer
	err = resp.Response.Write(&respBytes)
	if err != nil {
		c.logger.Error("failed to serialize response", "error", err)
		return nil, err
	}

	// Reset the response body again for upper layers to read
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(respBody))

	c.logger.Debug("response not found in the cache, caching response", "path", req.Request.RequestURI)

	// Build the index to cache based on the response received
	index = &cachememdb.Index{
		ID:          id,
		Token:       req.Token,
		RequestPath: req.Request.RequestURI,
		Response:    respBytes.Bytes(),
	}

	// Get the context for the token
	renewCtxInfo := c.ctxInfo(req.Token)

	// If the secret is of type lease, derive a context for its renewal
	if rType == responseTypeLease {
		newCtxInfo := new(ContextInfo)
		newCtxInfo.Ctx, newCtxInfo.CancelFunc = context.WithCancel(renewCtxInfo.Ctx)
		renewCtxInfo = newCtxInfo
		// Populate the lease value in the index
		index.Lease = rValue
	}

	// Store the cache index ID in the context for the renewer to operate on
	// the cached index
	renewCtx := context.WithValue(renewCtxInfo.Ctx, contextIndexID, index.ID)

	// Store the renewer context information in the index
	index.RenewCtxInfo = &cachememdb.ContextInfo{
		Ctx:        renewCtx,
		CancelFunc: renewCtxInfo.CancelFunc,
	}

	// Start renewing the secret in the response
	go c.startRenewing(renewCtx, index, req, respBody)

	// Store the index in the cache
	err = c.db.Set(index)
	if err != nil {
		c.logger.Error("failed to cache the proxied response", "error", err)
		return nil, err
	}

	return resp, nil
}

func (c *LeaseCache) ctxInfo(token string) *ContextInfo {
	ctxInfo, ok := c.tokenContexts[token]
	if !ok {
		ctxInfo = new(ContextInfo)
		ctxInfo.Ctx, ctxInfo.CancelFunc = context.WithCancel(c.baseCtxInfo.Ctx)
		c.tokenContexts[token] = ctxInfo
	}
	return ctxInfo
}

func (c *LeaseCache) startRenewing(ctx context.Context, index *cachememdb.Index, req *SendRequest, respBody []byte) {
	secret, err := api.ParseSecret(bytes.NewBuffer(respBody))
	if err != nil {
		c.logger.Error("failed to parse secret from response body", "error", err)
		return
	}

	defer func() {
		// When the renewer is done managing the secret, ensure that the cache
		// doesn't hold the secret anymore
		id := ctx.Value(contextIndexID).(string)
		c.logger.Debug("cleaning up cache entry", "id", id)
		err = c.db.Evict(cachememdb.IndexNameID.String(), id)
		if err != nil {
			c.logger.Error("failed to cleanup index", "id", id, "error", err)
			return
		}
	}()

	// Begin renewing when around half the lease duration is exhausted
	leaseDuration := secret.LeaseDuration
	if secret.Auth != nil {
		leaseDuration = secret.Auth.LeaseDuration
	}
	// Add a jitter of +-10% to half time
	backoffDuration := time.Second * time.Duration(leaseDuration*(c.rand.Intn(20)+40)/100)

	c.logger.Debug("initiating backoff", "path", req.Request.RequestURI, "duration", backoffDuration.String())
	contextutil.BackoffOrQuit(ctx, backoffDuration)

	// Fast path for shutdown
	select {
	case <-ctx.Done():
		c.logger.Debug("shutdown triggered, not starting the renewer", "path", req.Request.RequestURI)
		return
	default:
	}

	go func(ctx context.Context, secret *api.Secret) {
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			c.logger.Error("failed to create API client in the renewer", "error", err)
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

		c.logger.Debug("initiating renewal", "path", req.Request.RequestURI)
		go renewer.Renew()
		defer renewer.Stop()

		for {
			select {
			case <-ctx.Done():
				c.logger.Debug("shutdown triggered, stopping renewer", "path", req.Request.RequestURI)
				return
			case err := <-renewer.DoneCh():
				if err != nil {
					c.logger.Error("failed to renew secret", "error", err)
					return
				}
				c.logger.Debug("renewal completed; evicting from cache", "path", req.Request.RequestURI)
				// TODO: Renewal process is complete. But this doesn't mean
				// that the cache should evict the response right away. It
				// should stay until the last bits of lease duration is
				// exhausted.
				err = c.db.Evict(cachememdb.IndexNameID.String(), ctx.Value(contextIndexID).(string))
				if err != nil {
					c.logger.Error("failed to evict index", "error", err)
					return
				}
				return
			case renewal := <-renewer.RenewCh():
				c.logger.Debug("renewal received; updating cache", "path", req.Request.RequestURI)
				err = c.updateResponse(ctx, renewal)
				if err != nil {
					c.logger.Error("failed to handle renewal", "error", err)
					return
				}
			}
		}
	}(ctx, secret)
}

func (c *LeaseCache) updateResponse(ctx context.Context, renewal *api.RenewOutput) error {
	id := ctx.Value(contextIndexID).(string)

	// Get the cached index using the id in the context
	index, err := c.db.Get(cachememdb.IndexNameID.String(), id)
	if err != nil {
		return err
	}
	if index == nil {
		return fmt.Errorf("missing cache entry for id: %q", id)
	}

	// Read the response from the index
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(index.Response)), nil)
	if err != nil {
		c.logger.Error("failed to deserialize response", "error", err)
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
		c.logger.Error("failed to serialize updated response", "error", err)
		return err
	}

	// Update the response in the index and set it in the cache
	index.Response = respBytes.Bytes()
	err = c.db.Set(index)
	if err != nil {
		c.logger.Error("failed to cache the proxied response", "error", err)
		return err
	}

	return nil
}

// computeIndexID results in a value that uniquely identifies a request
// received by the agent. It does so by SHA256 hashing the serialized request
// object containing the request path, query parameters and body parameters.
func computeIndexID(req *SendRequest) (string, error) {
	var b bytes.Buffer

	// We need to hold on to the request body to plop it back in since
	// http.Request.Write will close the reader.
	body, err := ioutil.ReadAll(req.Request.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read request body: %v", err)
	}
	req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	// Serialze the request
	if err := req.Request.Write(&b); err != nil {
		return "", fmt.Errorf("failed to serialize request: %v", err)
	}

	// Reset the request body
	req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	// Append req.Token into the byte slice. This is needed since auto-auth'ed
	// requests sets the token directly into SendRequest.Token
	b.Write([]byte(req.Token))

	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// HandleCacheClear is returns a handlerFunc that can perform cache clearing operations
func (c *LeaseCache) HandleCacheClear(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := new(cacheClearRequest)

		err := jsonutil.DecodeJSONFromReader(r.Body, req)
		if err != nil && err != io.EOF {
			respondError(w, http.StatusBadRequest, err)
			return
		}

		err = c.handleCacheClear(ctx, req)
		if err != nil {
			respondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to clear cache: {{err}}", err))
			return
		}

		return
	})
}

func (c *LeaseCache) handleCacheClear(ctx context.Context, req *cacheClearRequest) error {
	c.logger.Debug("received cache-clear request", "type", req.Type)
	switch req.Type {
	case "request_path":
		// Find all the cached entries which has the given request path and
		// cancel the contexts of all the respective renewers
		indexes, err := c.db.GetByPrefix(req.Type, req.Value)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}
	case "token":
		if req.Value == "" {
			return nil
		}
		// Get the context for the given token and cancel its context
		tokenCtxInfo := c.ctxInfo(req.Value)
		tokenCtxInfo.CancelFunc()

		// Remove the cancelled context from the map
		delete(c.tokenContexts, req.Value)
	case "lease":
		// Get the cached index for the given lease
		index, err := c.db.Get(req.Type, req.Value)
		if err != nil {
			return err
		}
		if index == nil {
			return nil
		}
		// Cancel its renewer context
		index.RenewCtxInfo.CancelFunc()
	case "all":
		// Cancel the base context which triggers all the goroutines to
		// stop and evict entries from cache.
		c.baseCtxInfo.CancelFunc()

		// Reset the base context
		baseCtx, baseCancel := context.WithCancel(ctx)
		c.baseCtxInfo = &ContextInfo{
			Ctx:        baseCtx,
			CancelFunc: baseCancel,
		}

		// Reset the memdb instance
		if err := c.db.Flush(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid type %q", req.Type)
	}
	return nil
}

// respType determines the if the response is of type lease, token or
// non-cacheable.
func respType(body []byte) (responseType, string, error) {
	rawBody := map[string]interface{}{}
	err := json.Unmarshal(body, &rawBody)
	if err != nil {
		return responseTypeNonCacheable, "", err
	}

	if rawVal, ok := rawBody["lease_id"]; ok {
		if leaseID, ok := rawVal.(string); ok && leaseID != "" {
			return responseTypeLease, leaseID, nil
		}
	}

	if auth, ok := rawBody["auth"]; ok && auth != nil {
		token := auth.(map[string]interface{})["client_token"].(string)
		return responseTypeToken, token, nil
	}

	return responseTypeNonCacheable, "", nil
}
