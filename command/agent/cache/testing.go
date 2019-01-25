package cache

import (
	"context"
	"fmt"
)

// mockProxier is a mock implementation of the Proxier interface, used for testing purposes.
// The mock will return the provided
type mockProxier struct {
	proxiedResponses []*SendResponse
	responseIndex    int
}

func newMockProxier(responses []*SendResponse) *mockProxier {
	return &mockProxier{
		proxiedResponses: responses,
	}
}

func (p *mockProxier) Send(ctx context.Context, req *SendRequest) (*SendResponse, error) {
	if p.responseIndex >= len(p.proxiedResponses) {
		return nil, fmt.Errorf("index out of bounds: responseIndex = %d, responses = %d", p.responseIndex, len(p.proxiedResponses))
	}
	resp := p.proxiedResponses[p.responseIndex]

	p.responseIndex++

	return resp, nil
}

func (p *mockProxier) ResponseIndex() int {
	return p.responseIndex
}
