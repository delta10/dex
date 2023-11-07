package authflow

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

func TestResponseState(t *testing.T) {
	_, h := newTestHandler(t, nil)
	for _, responseTypes := range [][]string{{"code"}, {"token"}, {"code", "id_token", "token"}} {
		for _, state := range []string{"", "client state & value"} {
			t.Run(responseTypes[0]+"/"+state, func(t *testing.T) {
				authReq := storage.AuthRequest{
					ID: storage.NewID(), ClientID: "test", RedirectURI: "https://client.example/callback",
					State: state, ResponseTypes: responseTypes, Expiry: h.Now().Add(time.Hour),
				}
				require.NoError(t, h.Storage.CreateAuthRequest(t.Context(), authReq))
				w := httptest.NewRecorder()
				h.writeResponse(w, httptest.NewRequest(http.MethodGet, "/auth", nil), authReq)
				require.Equal(t, http.StatusSeeOther, w.Code)
				location, err := url.Parse(w.Header().Get("Location"))
				require.NoError(t, err)
				values := location.Query()
				if len(responseTypes) > 1 || responseTypes[0] == "token" {
					values, err = url.ParseQuery(location.Fragment)
					require.NoError(t, err)
				}
				require.Equal(t, state != "", values.Has("state"))
				require.Equal(t, state, values.Get("state"))
			})
		}
	}
}
