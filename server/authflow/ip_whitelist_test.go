package authflow

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/reqctx"
	"github.com/dexidp/dex/storage"
)

func TestConnectorIPAllowed(t *testing.T) {
	for _, tc := range []struct {
		name, remote, resolved string
		whitelist              []string
		want                   bool
	}{
		{"unrestricted", "192.0.2.1:1234", "", nil, true},
		{"allowed peer", "192.0.2.1:1234", "", []string{"192.0.2.1"}, true},
		{"denied peer", "192.0.2.2:1234", "", []string{"192.0.2.1"}, false},
		{"trusted proxy resolution", "10.0.0.1:1234", "192.0.2.1", []string{"192.0.2.1"}, true},
		{"IPv6", "[2001:db8::1]:1234", "", []string{"2001:db8:0:0::1"}, true},
		{"invalid peer", "invalid", "", []string{"192.0.2.1"}, false},
		{"invalid entry", "192.0.2.1:1234", "", []string{"invalid"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth", nil)
			r.RemoteAddr = tc.remote
			// Raw headers must never override the peer or the router's resolution.
			r.Header.Set("X-Real-IP", "192.0.2.1")
			r.Header.Set("X-Forwarded-For", "192.0.2.1")
			if tc.resolved != "" {
				r = r.WithContext(reqctx.WithRemoteIP(r.Context(), tc.resolved))
			}
			require.Equal(t, tc.want, connectorIPAllowed(r, tc.whitelist))
		})
	}
}

func TestAuthorizationIPWhitelist(t *testing.T) {
	_, h := newTestHandler(t, nil)
	ctx := t.Context()
	require.NoError(t, h.Storage.CreateClient(ctx, storage.Client{ID: "test"}))
	require.NoError(t, h.Storage.UpdateConnector(ctx, "mock", func(c storage.Connector) (storage.Connector, error) {
		c.IPWhitelist = []string{"192.0.2.1"}
		return c, nil
	}))

	for _, tc := range []struct {
		name, remote, connectorID string
		wantCode                  int
	}{
		{"allowed connector shown", "192.0.2.1:1234", "", http.StatusOK},
		{"denied connector filtered", "192.0.2.2:1234", "", http.StatusFound},
		{"explicit connector allowed", "192.0.2.1:1234", "mock", http.StatusFound},
		{"explicit connector denied", "192.0.2.2:1234", "mock", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/auth?client_id=test&response_type=code&connector_id="+tc.connectorID, nil)
			r.RemoteAddr = tc.remote
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			require.Equal(t, tc.wantCode, w.Code)
			if tc.name == "denied connector filtered" {
				require.Contains(t, w.Header().Get("Location"), "/auth/mock2?")
			}
		})
	}
}
