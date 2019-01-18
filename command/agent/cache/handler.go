package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
)

func HandleRequest(ctx context.Context, client *api.Client, proxy Proxier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("===== Agent.handleRequest: %q\n", r.RequestURI)

		resp, err := proxy.Send(&SendRequest{
			Request: r,
			Token:   client.Token(),
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
