package proxy

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

// ParseRequestKey takes in the request path and the body
func ParseRequestKey(req *http.Request) ([]byte, error) {
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
			return nil, err
		}
	}

	requestKey := &RequestKey{
		Path:        reqPath,
		QueryParams: rawQuery,
		BodyParams:  body,
	}

	raw, err := json.Marshal(requestKey)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(raw)
	return sum[:], nil
}
