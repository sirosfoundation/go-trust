package authzenclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("creates client with defaults", func(t *testing.T) {
		c := New("https://pdp.example.com")
		assert.Equal(t, "https://pdp.example.com", c.BaseURL)
		assert.NotNil(t, c.HTTPClient)
		assert.Equal(t, DefaultTimeout, c.HTTPClient.Timeout)
	})

	t.Run("normalizes trailing slash", func(t *testing.T) {
		c := New("https://pdp.example.com/")
		assert.Equal(t, "https://pdp.example.com", c.BaseURL)
	})

	t.Run("applies options", func(t *testing.T) {
		customClient := &http.Client{Timeout: 10 * time.Second}
		c := New("https://pdp.example.com",
			WithHTTPClient(customClient),
			WithEvaluationEndpoint("https://pdp.example.com/custom/eval"),
		)
		assert.Equal(t, customClient, c.HTTPClient)
		assert.Equal(t, "https://pdp.example.com/custom/eval", c.EvaluationEndpoint)
	})

	t.Run("WithTimeout creates client if nil", func(t *testing.T) {
		c := &Client{}
		WithTimeout(5 * time.Second)(c)
		assert.NotNil(t, c.HTTPClient)
		assert.Equal(t, 5*time.Second, c.HTTPClient.Timeout)
	})
}

func TestClient_evaluationURL(t *testing.T) {
	t.Run("uses custom endpoint if set", func(t *testing.T) {
		c := New("https://pdp.example.com",
			WithEvaluationEndpoint("https://other.example.com/eval"))
		assert.Equal(t, "https://other.example.com/eval", c.evaluationURL())
	})

	t.Run("uses default path if no custom endpoint", func(t *testing.T) {
		c := New("https://pdp.example.com")
		assert.Equal(t, "https://pdp.example.com/evaluation", c.evaluationURL())
	})
}

func TestClient_Evaluate(t *testing.T) {
	t.Run("successful evaluation returns decision", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/evaluation", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var req authzen.EvaluationRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "key", req.Subject.Type)
			assert.Equal(t, "did:web:example.com", req.Subject.ID)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.EvaluationResponse{
				Decision: true,
				Context: &authzen.EvaluationResponseContext{
					ID: "decision-123",
				},
			})
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "did:web:example.com"},
			Resource: authzen.Resource{
				Type: "jwk",
				ID:   "did:web:example.com",
				Key:  []interface{}{map[string]interface{}{"kty": "EC"}},
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Decision)
		assert.Equal(t, "decision-123", resp.Context.ID)
	})

	t.Run("validates request before sending", func(t *testing.T) {
		c := New("https://pdp.example.com")
		_, err := c.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "invalid", ID: "test"},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid request")
	})

	t.Run("handles error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid request"}`))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "test"},
		})

		require.Error(t, err)
		evalErr, ok := IsEvaluationError(err)
		require.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, evalErr.StatusCode)
		assert.Contains(t, evalErr.Body, "invalid request")
	})

	t.Run("handles network error", func(t *testing.T) {
		c := New("http://localhost:1") // Invalid port
		c.HTTPClient.Timeout = 100 * time.Millisecond
		_, err := c.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "test"},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP request failed")
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(1 * time.Second)
		}))
		defer server.Close()

		c := New(server.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := c.EvaluateRaw(ctx, &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "test"},
		})
		assert.Error(t, err)
	})
}

func TestClient_Resolve(t *testing.T) {
	t.Run("sends resolution-only request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req authzen.EvaluationRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			// Verify resolution-only structure
			assert.Equal(t, "key", req.Subject.Type)
			assert.Equal(t, "did:web:example.com", req.Subject.ID)
			assert.Equal(t, "did:web:example.com", req.Resource.ID)
			assert.Empty(t, req.Resource.Type) // No type for resolution-only
			assert.Empty(t, req.Resource.Key)  // No key for resolution-only

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.EvaluationResponse{
				Decision: true,
				Context: &authzen.EvaluationResponseContext{
					TrustMetadata: map[string]interface{}{
						"@context": []string{"https://www.w3.org/ns/did/v1"},
						"id":       "did:web:example.com",
					},
				},
			})
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.Resolve(context.Background(), "did:web:example.com")

		require.NoError(t, err)
		assert.True(t, resp.Decision)
		assert.NotNil(t, resp.Context)
		assert.NotNil(t, resp.Context.TrustMetadata)
	})

	t.Run("ResolveWithAction includes action", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req authzen.EvaluationRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			assert.NotNil(t, req.Action)
			assert.Equal(t, "issuer", req.Action.Name)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true})
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.ResolveWithAction(context.Background(), "did:web:example.com", "issuer")
		require.NoError(t, err)
	})
}

func TestClient_EvaluateX5C(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzen.EvaluationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "x5c", req.Resource.Type)
		assert.Len(t, req.Resource.Key, 2)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true})
	}))
	defer server.Close()

	c := New(server.URL)
	resp, err := c.EvaluateX5C(context.Background(), "CN=test",
		[]string{"base64cert1", "base64cert2"},
		&authzen.Action{Name: "tls-server"})

	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestClient_EvaluateJWK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzen.EvaluationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "jwk", req.Resource.Type)
		assert.Len(t, req.Resource.Key, 1)
		jwk, ok := req.Resource.Key[0].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "EC", jwk["kty"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true})
	}))
	defer server.Close()

	c := New(server.URL)
	resp, err := c.EvaluateJWK(context.Background(), "did:key:z123",
		map[string]interface{}{"kty": "EC", "crv": "P-256"},
		nil)

	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestDiscover(t *testing.T) {
	t.Run("successful discovery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == WellKnownPath {
				assert.Equal(t, http.MethodGet, r.Method)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(authzen.PDPMetadata{
					PolicyDecisionPoint:      "https://pdp.example.com",
					AccessEvaluationEndpoint: "https://pdp.example.com/v2/evaluation",
					Capabilities:             []string{"urn:authzen:trust"},
				})
				return
			}
			// Handle evaluation requests
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.EvaluationResponse{Decision: true})
		}))
		defer server.Close()

		c, err := Discover(context.Background(), server.URL)
		require.NoError(t, err)
		assert.NotNil(t, c.Metadata)
		assert.Equal(t, "https://pdp.example.com", c.Metadata.PolicyDecisionPoint)
		assert.Equal(t, "https://pdp.example.com/v2/evaluation", c.EvaluationEndpoint)
		assert.Contains(t, c.Metadata.Capabilities, "urn:authzen:trust")
	})

	t.Run("discovery not found falls back to default", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == WellKnownPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}))
		defer server.Close()

		_, err := Discover(context.Background(), server.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 404")
	})

	t.Run("normalizes trailing slash", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, WellKnownPath, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.PDPMetadata{
				PolicyDecisionPoint:      "https://pdp.example.com",
				AccessEvaluationEndpoint: "https://pdp.example.com/evaluation",
			})
		}))
		defer server.Close()

		c, err := Discover(context.Background(), server.URL+"/")
		require.NoError(t, err)
		assert.Equal(t, server.URL, c.BaseURL)
	})

	t.Run("applies options", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authzen.PDPMetadata{
				PolicyDecisionPoint:      "https://pdp.example.com",
				AccessEvaluationEndpoint: "https://pdp.example.com/evaluation",
			})
		}))
		defer server.Close()

		c, err := Discover(context.Background(), server.URL, WithTimeout(5*time.Second))
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, c.HTTPClient.Timeout)
	})
}

func TestEvaluationError(t *testing.T) {
	err := &EvaluationError{
		StatusCode: 400,
		Body:       `{"error": "bad request"}`,
	}

	assert.Equal(t, `evaluation failed with status 400: {"error": "bad request"}`, err.Error())

	evalErr, ok := IsEvaluationError(err)
	assert.True(t, ok)
	assert.Equal(t, 400, evalErr.StatusCode)
}

func TestParseBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid https URL",
			input: "https://pdp.example.com/path?query=1",
			want:  "https://pdp.example.com",
		},
		{
			name:  "valid http URL",
			input: "http://localhost:8080/eval",
			want:  "http://localhost:8080",
		},
		{
			name:    "invalid scheme",
			input:   "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "missing host",
			input:   "https:///path",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			input:   "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBaseURL(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNewAction(t *testing.T) {
	action := NewAction("credential-issuer")
	assert.Equal(t, "credential-issuer", action.Name)
	assert.Nil(t, action.Parameters)
}

func TestNewActionWithCredentialTypes(t *testing.T) {
	t.Run("single credential type", func(t *testing.T) {
		action := NewActionWithCredentialTypes("credential-issuer", "eu.europa.ec.eudi.pid.1")
		assert.Equal(t, "credential-issuer", action.Name)
		assert.NotNil(t, action.Parameters)
		credTypes, ok := action.Parameters["credential_types"].([]string)
		assert.True(t, ok)
		assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1"}, credTypes)
	})

	t.Run("multiple credential types", func(t *testing.T) {
		action := NewActionWithCredentialTypes("credential-issuer",
			"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1")
		assert.Equal(t, "credential-issuer", action.Name)
		credTypes, ok := action.Parameters["credential_types"].([]string)
		assert.True(t, ok)
		assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}, credTypes)
	})

	t.Run("no credential types", func(t *testing.T) {
		action := NewActionWithCredentialTypes("credential-issuer")
		assert.Equal(t, "credential-issuer", action.Name)
		credTypes, ok := action.Parameters["credential_types"].([]string)
		assert.True(t, ok)
		assert.Empty(t, credTypes)
	})
}

func TestNewActionWithParameters(t *testing.T) {
	params := map[string]interface{}{
		"credential_types": []string{"eu.europa.ec.eudi.pid.1"},
		"query":            map[string]string{"type": "dcql"},
	}
	action := NewActionWithParameters("authenticate", params)
	assert.Equal(t, "authenticate", action.Name)
	assert.Equal(t, params, action.Parameters)
}
