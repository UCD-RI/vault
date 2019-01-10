package cache

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// RequestKey holds the request path and parameters from an incoming request.
type RequestKey struct {
	Path        string
	QueryParams url.Values
	BodyParams  map[string]interface{}
}

// ComputeCacheKey results in a value that uniquely identifies a request
// received by the agent. It does so by SHA256 hashing the marshalled JSON
// which contains the request path, query parameters and body parameters.
func ComputeCacheKey(req *http.Request) (string, error) {
	reqPath := req.URL.EscapedPath()
	rawQuery := req.URL.Query()

	var body map[string]interface{}
	if req.Body != nil {
		decoder := json.NewDecoder(req.Body)
		err := decoder.Decode(&body)
		switch {
		case err == io.EOF:
			// empty body
		case err != nil:
			return "", err
		}
	}

	requestKey := &RequestKey{
		Path:        reqPath,
		QueryParams: rawQuery,
		BodyParams:  body,
	}

	raw, err := json.Marshal(requestKey)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(raw)
	return string(sum[:]), nil
}
