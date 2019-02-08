package cache

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-test/deep"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/consts"
	"github.com/hashicorp/vault/helper/logging"
)

func testNewLeaseCache(t *testing.T, responses []*SendResponse) *LeaseCache {
	t.Helper()

	lc, err := NewLeaseCache(&LeaseCacheConfig{
		BaseContext: context.Background(),
		Proxier:     newMockProxier(responses),
		Logger:      logging.NewVaultLogger(hclog.Trace).Named("cache.leasecache"),
	})

	if err != nil {
		t.Fatal(err)
	}
	return lc
}

func TestLeaseCache_Send_NonCacheable(t *testing.T) {
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

func TestLeaseCache_Send_NonCacheable_NonTokenLease(t *testing.T) {
	// Create the cache, the two responses should be cached.
	responses := []*SendResponse{
		&SendResponse{
			Response: &api.Response{
				Response: &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`{"value": "output", "lease_id": "foo"}`)),
				},
			},
			ResponseBody: []byte(`{"value": "output", "lease_id": "foo"}`),
		},
		&SendResponse{
			Response: &api.Response{
				Response: &http.Response{
					StatusCode: http.StatusCreated,
					Body:       ioutil.NopCloser(strings.NewReader(`{"value": "invalid", "auth": {"client_token": "test"}}`)),
				},
			},
			ResponseBody: []byte(`{"value": "invalid", "auth": {"client_token": "test"}}`),
		},
	}
	lc := testNewLeaseCache(t, responses)

	// Send a request, trigger the cache, which returns a response containing lease_id.
	url := "http://example.com/v1/sample/api"
	sendReq := &SendRequest{
		Token:   "foo",
		Request: httptest.NewRequest("GET", url, strings.NewReader(`{"value": "input"}`)),
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
		Request: httptest.NewRequest("GET", url, strings.NewReader(`{"value": "input"}`)),
	}
	resp, err = lc.Send(context.Background(), sendReq)
	if err != nil {
		t.Fatal(err)
	}
	if diff := deep.Equal(resp.Response.StatusCode, responses[0].Response.StatusCode); diff == nil {
		t.Fatalf("expected getting proxied response: got %v", diff)
	}
}

func TestLeaseCache_HandleCacheClear(t *testing.T) {
	lc := testNewLeaseCache(t, nil)

	handler := lc.HandleCacheClear(context.Background())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Test missing body, should return 400
	resp, err := http.Post(ts.URL, "application/json", nil)
	if err != nil {
		t.Fatal()
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status code mismatch: expected = %v, got = %v", http.StatusBadRequest, resp.StatusCode)
	}

	testCases := []struct {
		name               string
		reqType            string
		reqValue           string
		expectedStatusCode int
	}{
		{
			"invalid_type",
			"foo",
			"",
			http.StatusBadRequest,
		},
		{
			"invalid_value",
			"",
			"bar",
			http.StatusBadRequest,
		},
		{
			"all",
			"all",
			"",
			http.StatusOK,
		},
		{
			"by_request_path",
			"request_path",
			"foo",
			http.StatusOK,
		},
		{
			"by_token",
			"token",
			"foo",
			http.StatusOK,
		},
		{
			"by_lease",
			"lease",
			"foo",
			http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := fmt.Sprintf("{\"type\": \"%s\", \"value\": \"%s\"}", tc.reqType, tc.reqValue)
			resp, err := http.Post(ts.URL, "application/json", strings.NewReader(reqBody))
			if err != nil {
				t.Fatal()
			}
			if tc.expectedStatusCode != resp.StatusCode {
				t.Fatalf("status code mismatch: expected = %v, got = %v", tc.expectedStatusCode, resp.StatusCode)
			}
		})
	}
}

func Test_deriveNamespaceAndRevocationPath(t *testing.T) {
	tests := []struct {
		name             string
		req              *SendRequest
		wantNamespace    string
		wantRelativePath string
	}{
		{
			"non_revocation_full_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/ns1/sys/mounts",
					},
				},
			},
			"root/",
			"/v1/ns1/sys/mounts",
		},
		{
			"non_revocation_relative_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/sys/mounts",
					},
					Header: http.Header{
						consts.NamespaceHeaderName: []string{"ns1/"},
					},
				},
			},
			"ns1/",
			"/v1/sys/mounts",
		},
		{
			"non_revocation_relative_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/ns2/sys/mounts",
					},
					Header: http.Header{
						consts.NamespaceHeaderName: []string{"ns1/"},
					},
				},
			},
			"ns1/",
			"/v1/ns2/sys/mounts",
		},
		{
			"revocation_full_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/ns1/sys/leases/revoke",
					},
				},
			},
			"ns1/",
			"/v1/sys/leases/revoke",
		},
		{
			"revocation_relative_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/sys/leases/revoke",
					},
					Header: http.Header{
						consts.NamespaceHeaderName: []string{"ns1/"},
					},
				},
			},
			"ns1/",
			"/v1/sys/leases/revoke",
		},
		{
			"revocation_relative_partial_ns",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/ns2/sys/leases/revoke",
					},
					Header: http.Header{
						consts.NamespaceHeaderName: []string{"ns1/"},
					},
				},
			},
			"ns1/ns2/",
			"/v1/sys/leases/revoke",
		},
		{
			"revocation_prefix_full_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/ns1/sys/leases/revoke-prefix/foo",
					},
				},
			},
			"ns1/",
			"/v1/sys/leases/revoke-prefix/foo",
		},
		{
			"revocation_prefix_relative_path",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/sys/leases/revoke-prefix/foo",
					},
					Header: http.Header{
						consts.NamespaceHeaderName: []string{"ns1/"},
					},
				},
			},
			"ns1/",
			"/v1/sys/leases/revoke-prefix/foo",
		},
		{
			"revocation_prefix_partial_ns",
			&SendRequest{
				Request: &http.Request{
					URL: &url.URL{
						Path: "/v1/ns2/sys/leases/revoke-prefix/foo",
					},
					Header: http.Header{
						consts.NamespaceHeaderName: []string{"ns1/"},
					},
				},
			},
			"ns1/ns2/",
			"/v1/sys/leases/revoke-prefix/foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNamespace, gotRelativePath := deriveNamespaceAndRevocationPath(tt.req)
			if gotNamespace != tt.wantNamespace {
				t.Errorf("deriveNamespaceAndRevocationPath() gotNamespace = %v, want %v", gotNamespace, tt.wantNamespace)
			}
			if gotRelativePath != tt.wantRelativePath {
				t.Errorf("deriveNamespaceAndRevocationPath() gotRelativePath = %v, want %v", gotRelativePath, tt.wantRelativePath)
			}
		})
	}
}
