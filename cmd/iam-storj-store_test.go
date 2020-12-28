package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/storj/minio/pkg/auth"
	"github.com/stretchr/testify/require"
)

func TestLoadUserBadURL(t *testing.T) {
	for _, badURL := range []string{"", "test.url.invalid", "http://test.url.invalid"} {
		store := GetTestAuthStore(badURL, "token", 2*time.Second)
		blankCredentialMap := make(map[string]auth.Credentials)
		require.Error(t, store.loadUser(context.Background(), "fakeUser", regularUser, blankCredentialMap))
	}
}

func TestLoadUserTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	store := GetTestAuthStore(ts.URL, "token", 100*time.Millisecond)

	authErr := make(chan error, 1)
	go func() {
		blankCredentialMap := make(map[string]auth.Credentials)
		authErr <- store.loadUser(context.Background(), "fakeUser", regularUser, blankCredentialMap)
	}()

	select {
	case res := <-authErr:
		require.Error(t, res)
		require.True(t, strings.Contains(res.Error(), "timeout"))
	case <-time.After(1 * time.Second):
		require.Fail(t, "Bad LoadUser request should have timed out already")
	}
}

func GetTestAuthStore(authURL, authToken string, timeout time.Duration) *IAMStorjAuthStore {
	return &IAMStorjAuthStore{
		transport: newGatewayHTTPTransport(timeout),
		authURL:   authURL,
		authToken: authToken,
	}
}
