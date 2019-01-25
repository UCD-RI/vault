package cache

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-test/deep"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
)

func testNewLeaseCache(t *testing.T, responses []*SendResponse) *LeaseCache {
	t.Helper()

	lc, err := NewLeaseCache(&LeaseCacheConfig{
		Proxier: newMockProxier(responses),
		Logger:  hclog.NewNullLogger(),
	})

	if err != nil {
		t.Fatal(err)
	}
	return lc
}

func TestLeaseCache_Send(t *testing.T) {
	// Create the cache, the two responses should be cached.
	responses := []*SendResponse{
		&SendResponse{
			Response: &api.Response{
				Response: &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`{"value": "output", "lease_id": "foo"}`)),
				},
			},
		},
		&SendResponse{
			Response: &api.Response{
				Response: &http.Response{
					StatusCode: http.StatusCreated,
					Body:       ioutil.NopCloser(strings.NewReader(`{"value": "invalid", "auth": {"client_token": "test"}}`)),
				},
			},
		},
	}
	lc := testNewLeaseCache(t, responses)

	// Send a request, trigger the cache, which returns a response containing lease_id.
	sendReq := &SendRequest{
		Token:   "foo",
		Request: httptest.NewRequest("GET", "http://example.com", strings.NewReader(`{"value": "input"}`)),
	}
	resp, err := lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[0].Response.StatusCode); diff != nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}

	// Verify response is cached by sending the same request.
	sendReq = &SendRequest{
		Token:   "foo",
		Request: httptest.NewRequest("GET", "http://example.com", strings.NewReader(`{"value": "input"}`)),
	}
	resp, err = lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[0].Response.StatusCode); diff != nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}

	// Send a request, trigger the cache, which returns a response containing the auth block.
	sendReq = &SendRequest{
		Token:   "bar",
		Request: httptest.NewRequest("GET", "http://example.com", strings.NewReader(`{"value": "input"}`)),
	}
	resp, err = lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[1].Response.StatusCode); diff != nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}

	// Verify response is cached by sending the same request.
	sendReq = &SendRequest{
		Token:   "bar",
		Request: httptest.NewRequest("GET", "http://example.com", strings.NewReader(`{"value": "input"}`)),
	}
	resp, err = lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[1].Response.StatusCode); diff != nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}
}

func TestLeaseCache_Send_nonCacheable(t *testing.T) {
	// Create the cache
	responses := []*SendResponse{
		&SendResponse{
			Response: &api.Response{
				Response: &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`{"value": "output"}`)),
				},
			},
		},
		&SendResponse{
			Response: &api.Response{
				Response: &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       ioutil.NopCloser(strings.NewReader(`{"value": "invalid"}`)),
				},
			},
		},
	}
	lc := testNewLeaseCache(t, responses)

	sendReq := &SendRequest{
		Token:   "foo",
		Request: httptest.NewRequest("GET", "http://example.com", strings.NewReader(`{"value": "input"}`)),
	}

	// Insert into the empty cache.
	resp, err := lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[0].Response.StatusCode); diff != nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}

	// Check that the response is non-cacheable (e.g. missing lease_id or auth
	// block). Should return status from the second expected response.
	sendReq = &SendRequest{
		Token:   "foo",
		Request: httptest.NewRequest("GET", "http://example.com", strings.NewReader(`{"value": "input"}`)),
	}

	resp, err = lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[1].Response.StatusCode); diff != nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}
}
