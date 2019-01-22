package cache

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/command/agent/cache/httputil"
	"github.com/hashicorp/vault/helper/consts"
)

type Config struct {
	Token            string
	Proxier          Proxier
	UseAutoAuthToken bool
	Listeners        []net.Listener
	Handler          *http.ServeMux
	Logger           hclog.Logger
}

func Run(ctx context.Context, config *Config) {
	config.Handler.Handle("/", handler(ctx, config))
	for _, ln := range config.Listeners {
		server := &http.Server{
			Handler:           config.Handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          config.Logger.StandardLogger(nil),
		}
		go server.Serve(ln)
	}
}

func handler(ctx context.Context, config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config.Logger.Info("received request", "path", r.RequestURI)

		token := r.Header.Get(consts.AuthHeaderName)
		if token == "" && config.UseAutoAuthToken {
			token = config.Token
		}

		resp, err := config.Proxier.Send(&SendRequest{
			Token:   token,
			Request: r,
		})
		if err != nil {
			httputil.RespondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to get the response: {{err}}", err))
			return
		}

		respBody, err := ioutil.ReadAll(resp.Response.Body)
		if err != nil {
			httputil.RespondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to read response body: {{err}}", err))
			return
		}

		httputil.CopyHeader(w.Header(), resp.Response.Header)
		w.WriteHeader(resp.Response.StatusCode)
		w.Write(respBody)
		return
	})
}
