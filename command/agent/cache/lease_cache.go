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
	"strings"
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
	errInvalidType = errors.New("invalid type provided")
)

const (
	vaultPathTokenRevoke         = "/v1/auth/token/revoke"
	vaultPathTokenRevokeSelf     = "/v1/auth/token/revoke-self"
	vaultPathTokenRevokeAccessor = "/v1/auth/token/revoke-accessor"
	vaultPathTokenRevokeOrphan   = "/v1/auth/token/revoke-orphan"
	vaultPathTokenLookupSelf     = "/v1/auth/token/lookup-self"
	vaultPathLeaseRevoke         = "/v1/sys/leases/revoke"
	vaultPathLeaseRevokeForce    = "/v1/sys/leases/revoke-force"
	vaultPathLeaseRevokePrefix   = "/v1/sys/leases/revoke-prefix"
)

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
// Lease.
type LeaseCacheConfig struct {
	BaseContext context.Context
	Proxier     Proxier
	Logger      hclog.Logger
}

// ContextInfo holds a derived context and cancelFunc pair.
type ContextInfo struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
}

// NewLeaseCache creates a new instance of a LeaseCache.
func NewLeaseCache(conf *LeaseCacheConfig) (*LeaseCache, error) {
	if conf == nil {
		return nil, errors.New("nil configuration provided")
	}

	if conf.Proxier == nil || conf.Logger == nil {
		return nil, fmt.Errorf("missing configuration required params: %v", conf)
	}

	db, err := cachememdb.New()
	if err != nil {
		return nil, err
	}

	// Create a base context for the lease cache layer
	baseCtx, baseCancelFunc := context.WithCancel(conf.BaseContext)
	baseCtxInfo := &ContextInfo{
		Ctx:        baseCtx,
		CancelFunc: baseCancelFunc,
	}

	return &LeaseCache{
		proxier:       conf.Proxier,
		logger:        conf.Logger,
		db:            db,
		rand:          rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
		tokenContexts: make(map[string]*ContextInfo),
		baseCtxInfo:   baseCtxInfo,
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
		c.logger.Debug("returning cached response", "path", req.Request.RequestURI)

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

	c.logger.Debug("forwarding the request and caching the response", "path", req.Request.RequestURI)

	// Pass the request down and get a response
	resp, err := c.proxier.Send(ctx, req)
	if err != nil {
		return nil, err
	}

	// Determine if this is a revocation request, and if so we clear the proper
	// cache index(es) as well
	if err := c.handleRevocation(ctx, req, resp.Response.StatusCode); err != nil {
		c.logger.Error("failed to handle eviction triggered by revocation", "error", err)
		return nil, err
	}

	// Build the index to cache based on the response received
	index = &cachememdb.Index{
		ID:          id,
		RequestPath: req.Request.RequestURI,
	}

	secret, err := api.ParseSecret(bytes.NewBuffer(resp.ResponseBody))
	if err != nil {
		c.logger.Error("failed to parse response as secret", "error", err)
		return nil, err
	}

	renewCtxInfo := c.ctxInfo(req.Token)
	switch {
	case secret == nil:
		// Fast path for non-cacheable responses
		return resp, nil
	case secret.LeaseID != "":
		newCtxInfo := new(ContextInfo)
		newCtxInfo.Ctx, newCtxInfo.CancelFunc = context.WithCancel(renewCtxInfo.Ctx)
		renewCtxInfo = newCtxInfo

		index.Lease = secret.LeaseID
		index.Token = req.Token
	case secret.Auth != nil:
		index.Token = secret.Auth.ClientToken
		index.TokenAccessor = secret.Auth.Accessor
		renewCtxInfo = c.ctxInfo(index.Token)
	default:
		// We shouldn't be hitting this, but will err on the side of caution and
		// simply proxy.
		return resp, nil
	}

	// Serialize the response to store it in the cached index
	var respBytes bytes.Buffer
	err = resp.Response.Write(&respBytes)
	if err != nil {
		c.logger.Error("failed to serialize response", "error", err)
		return nil, err
	}

	// Reset the response body for upper layers to read
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(resp.ResponseBody))

	// Set the index's Response
	index.Response = respBytes.Bytes()

	// Store the index ID in the renewer context
	renewCtx := context.WithValue(renewCtxInfo.Ctx, contextIndexID, index.ID)

	// Store the renewer context in the index
	index.RenewCtxInfo = &cachememdb.ContextInfo{
		Ctx:        renewCtx,
		CancelFunc: renewCtxInfo.CancelFunc,
	}

	// Start renewing the secret in the response
	go c.startRenewing(renewCtx, index, req, resp.ResponseBody)

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

	// Short-circuit if the secret is not renewable
	if !secret.Renewable {
		return
	}

	// Begin renewing when around half the lease duration is exhausted
	leaseDuration := secret.LeaseDuration
	if secret.Auth != nil {
		leaseDuration = secret.Auth.LeaseDuration
	}
	// Add a jitter of +-10% to half time
	backoffDuration := time.Second * time.Duration(leaseDuration*(c.rand.Intn(20)+40)/100)

	c.logger.Debug("initiating backoff", "path", req.Request.RequestURI, "duration", backoffDuration.String())
	contextutil.BackoffOrQuit(ctx, backoffDuration)

	cleanupFunc := func() {
		id := ctx.Value(contextIndexID).(string)
		c.logger.Debug("evicting index from cache", "id", id)
		err = c.db.Evict(cachememdb.IndexNameID.String(), id)
		if err != nil {
			c.logger.Error("failed to evict index", "id", id, "error", err)
			return
		}
	}

	// Fast path for shutdown
	select {
	case <-ctx.Done():
		c.logger.Debug("shutdown triggered, not starting the renewer", "path", req.Request.RequestURI)
		cleanupFunc()
		return
	default:
	}

	go func(ctx context.Context, secret *api.Secret) {
		defer cleanupFunc()

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

		var lastLeaseDuration int
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

				// Backoff from returning until the last bits of the lease
				// duration is consumed
				contextutil.BackoffOrQuit(ctx, time.Second*time.Duration(lastLeaseDuration))
				return
			case renewal := <-renewer.RenewCh():
				c.logger.Debug("renewal received; updating cache", "path", req.Request.RequestURI)
				err = c.updateResponse(ctx, renewal)
				if err != nil {
					c.logger.Error("failed to handle renewal", "error", err)
					return
				}
				lastLeaseDuration = renewal.Secret.LeaseDuration
				if renewal.Secret.Auth != nil {
					lastLeaseDuration = renewal.Secret.Auth.LeaseDuration
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

	// Serialze the request
	if err := req.Request.Write(&b); err != nil {
		return "", fmt.Errorf("failed to serialize request: %v", err)
	}

	// Reset the request body after it has been closed by Write
	req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(req.RequestBody))

	// Append req.Token into the byte slice. This is needed since auto-auth'ed
	// requests sets the token directly into SendRequest.Token
	b.Write([]byte(req.Token))

	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// HandleCacheClear returns a handlerFunc that can perform cache clearing operations.
func (c *LeaseCache) HandleCacheClear(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := new(cacheClearRequest)
		if err := jsonutil.DecodeJSONFromReader(r.Body, req); err != nil {
			if err == io.EOF {
				err = errors.New("empty JSON provided")
			}
			respondError(w, http.StatusBadRequest, errwrap.Wrapf("failed to parse JSON input: {{err}}", err))
			return
		}

		c.logger.Debug("received cache-clear request", "type", req.Type)

		if err := c.handleCacheClear(ctx, req.Type, req.Value); err != nil {
			// Default to 500 on error, unless the user provided an invalid type,
			// which would then be a 400.
			httpStatus := http.StatusInternalServerError
			if err == errInvalidType {
				httpStatus = http.StatusBadRequest
			}
			respondError(w, httpStatus, errwrap.Wrapf("failed to clear cache: {{err}}", err))
			return
		}

		return
	})
}

func (c *LeaseCache) handleCacheClear(ctx context.Context, clearType, clearValue string) error {
	switch clearType {
	case "request_path":
		// Find all the cached entries which has the given request path and
		// cancel the contexts of all the respective renewers
		indexes, err := c.db.GetByPrefix(clearType, clearValue)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}

	case "token":
		if clearValue == "" {
			return nil
		}
		// Get the context for the given token and cancel its context
		tokenCtxInfo := c.ctxInfo(clearValue)
		tokenCtxInfo.CancelFunc()

		// Remove the cancelled context from the map
		delete(c.tokenContexts, clearValue)

	case "token_accessor", "lease":
		// Get the cached index and cancel the corresponding renewer context
		index, err := c.db.Get(clearType, clearValue)
		if err != nil {
			return err
		}
		if index == nil {
			return nil
		}
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
		return errInvalidType
	}

	return nil
}

// handleRevocation checks whether an originating request is an revocation request, and if so
// performs the proper cache cleanup.
func (c *LeaseCache) handleRevocation(ctx context.Context, req *SendRequest, respStatus int) error {
	// Lease and token revocations return 204's on success. Fast-path if that's
	// not the case.
	if respStatus != http.StatusNoContent {
		return nil
	}

	c.logger.Debug("triggered caching eviction from revocation request")

	path := req.Request.RequestURI
	// TODO: Handle namespaces
	switch {
	case path == vaultPathTokenRevoke:
		// Get the token from the request body
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return err
		}
		token, ok := jsonBody["token"]
		if !ok {
			return fmt.Errorf("failed to get token from request body")
		}

		// Clear the cache entry associated with the token and all the other
		// entries belonging to the leases derived from this token.
		if err := c.handleCacheClear(ctx, "token", token.(string)); err != nil {
			return err
		}

	case path == vaultPathTokenRevokeSelf:
		// Clear the cache entry associated with the token and all the other
		// entries belonging to the leases derived from this token.
		if err := c.handleCacheClear(ctx, "token", req.Token); err != nil {
			return err
		}

	case path == vaultPathTokenRevokeAccessor:
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return err
		}
		accessor, ok := jsonBody["accessor"]
		if !ok {
			return fmt.Errorf("failed to get token from request body")
		}

		if err := c.handleCacheClear(ctx, "token_accessor", accessor.(string)); err != nil {
			return err
		}

	case path == vaultPathTokenRevokeOrphan:
		// TODO: Figure out how to do revoke-orphan without canceling derived contexts

	case path == vaultPathLeaseRevoke:
		// TODO: Should lease present in the URL itself be considered here?
		// Get the lease from the request body
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return err
		}
		leaseID, ok := jsonBody["lease_id"]
		if !ok {
			return fmt.Errorf("failed to get lease_id from request body")
		}
		if err := c.handleCacheClear(ctx, "lease", leaseID.(string)); err != nil {
			return err
		}

	case strings.HasPrefix(path, vaultPathLeaseRevokeForce):
		// Trim the URL path to get the request path prefix
		prefix := strings.TrimPrefix(path, vaultPathLeaseRevokeForce)
		// Get all the cache indexes that use the request path containing the
		// prefix and cancel the renewer context of each.
		indexes, err := c.db.GetByPrefix("request_path", "/v1"+prefix)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}

	case strings.HasPrefix(path, vaultPathLeaseRevokePrefix):
		// Trim the URL path to get the request path prefix
		prefix := strings.TrimPrefix(path, vaultPathLeaseRevokePrefix)
		// Get all the cache indexes that use the request path containing the
		// prefix and cancel the renewer context of each.
		indexes, err := c.db.GetByPrefix("request_path", "/v1"+prefix)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}
	}

	return nil
}
