package cache

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
)

// ComputeCacheKey results in a value that uniquely identifies a request
// received by the agent. It does so by SHA256 hashing the marshalled JSON
// which contains the request path, query parameters and body parameters.
func ComputeCacheKey(req *http.Request) (string, error) {
	var b bytes.Buffer

	// Serialze the request
	if err := req.Write(&b); err != nil {
		return "", fmt.Errorf("unable to serialize request: %v", err)
	}

	sum := sha256.Sum256(b.Bytes())
	return string(sum[:]), nil
}
