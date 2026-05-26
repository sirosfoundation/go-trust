package rpcert

import (
	"context"
	"fmt"
)

// StubRegisterClient is a placeholder implementation of NationalRegisterClient.
// It returns StatusNotFound for all lookups. Replace with a real implementation
// when the TS5/TS6 API specification is finalized.
type StubRegisterClient struct {
	baseURL string
}

// NewStubRegisterClient creates a stub register client.
func NewStubRegisterClient(baseURL string) *StubRegisterClient {
	return &StubRegisterClient{baseURL: baseURL}
}

// LookupRP returns StatusNotFound for all lookups (stub implementation).
func (c *StubRegisterClient) LookupRP(_ context.Context, rpIdentifier string) (*RPEntitlements, error) {
	return nil, fmt.Errorf("national register lookup not implemented (base_url=%s, rp=%s)", c.baseURL, rpIdentifier)
}

// Healthy returns false (stub implementation).
func (c *StubRegisterClient) Healthy() bool {
	return c.baseURL != ""
}
