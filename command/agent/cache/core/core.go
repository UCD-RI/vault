package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/vault/command/agent/cache"
	"github.com/hashicorp/vault/command/agent/cache/apiproxy"
	"github.com/hashicorp/vault/command/agent/cache/leasecache"
	vaulthttp "github.com/hashicorp/vault/http"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/logical"
)

type Core struct {
	logger    hclog.Logger
	client    *api.Client
	proxier   cache.Proxier
	listeners []net.Listener
}

type Config struct {
	Logger    hclog.Logger
	Client    *api.Client
	Listeners []net.Listener
}

func New(config *Config) (*Core, error) {
	proxier, err := leasecache.NewLeaseCache(&leasecache.LeaseCacheConfig{
		Proxier: apiproxy.NewAPIProxy(),
		Logger:  config.Logger.Named("agent.core"),
	})
	if err != nil {
		return nil, err
	}

	return &Core{
		logger:    config.Logger,
		client:    config.Client,
		proxier:   proxier,
		listeners: config.Listeners,
	}, nil
}

func (c *Core) Listen(ctx context.Context) {
	for _, ln := range c.listeners {
		server := &http.Server{
			Handler:           c.handler(ctx),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          c.logger.StandardLogger(nil),
		}
		go server.Serve(ln)
	}
}

func (c *Core) handler(ctx context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", handleRequest(ctx, c))
	return mux
}

func handleRequest(ctx context.Context, core *Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("===== Agent.handleRequest: %q\n", r.RequestURI)

		resp, err := core.proxier.Send(&cache.SendRequest{
			Request: r,
			Token:   core.client.Token(),
		})
		if err != nil {
			respondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to get the response: {{err}}", err))
			return
		}

		respBody, err := ioutil.ReadAll(resp.Response.Body)
		if err != nil {
			respondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to read response body: {{err}}", err))
			return
		}

		copyHeader(w.Header(), resp.Response.Header)
		w.WriteHeader(resp.Response.StatusCode)
		w.Write(respBody)
		return
	})
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func respondError(w http.ResponseWriter, status int, err error) {
	logical.AdjustErrorStatusCode(&status, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := &vaulthttp.ErrorResponse{Errors: make([]string, 0, 1)}
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
	}

	enc := json.NewEncoder(w)
	enc.Encode(resp)
}
