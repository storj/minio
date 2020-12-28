package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/auth"
	iampolicy "github.com/storj/minio/pkg/iam/policy"
)

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

// IAMStorjAuthStore implements IAMStorageAPI
type IAMStorjAuthStore struct {
	mu        sync.RWMutex
	transport *http.Transport
	authURL   string
	authToken string
}

func newIAMStorjAuthStore(objAPI ObjectLayer) *IAMStorjAuthStore {
	return &IAMStorjAuthStore{
		transport: NewGatewayHTTPTransport(),
		// TODO: is there a better way to configure this?
		authURL:   getenv("MINIO_STORJ_AUTH_URL", "http://127.0.0.1:8000"),
		authToken: getenv("MINIO_STORJ_AUTH_TOKEN", ""),
	}
}

func (iamOS *IAMStorjAuthStore) lock()    { iamOS.mu.Lock() }
func (iamOS *IAMStorjAuthStore) unlock()  { iamOS.mu.Unlock() }
func (iamOS *IAMStorjAuthStore) rlock()   { iamOS.mu.RLock() }
func (iamOS *IAMStorjAuthStore) runlock() { iamOS.mu.RUnlock() }

// Migrate users directory in a single scan.
func (iamOS *IAMStorjAuthStore) migrateUsersConfigToV1(ctx context.Context, isSTS bool) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) migrateToV1(ctx context.Context) error {
	return nil
}

// Should be called under config migration lock
func (iamOS *IAMStorjAuthStore) migrateBackendFormat(ctx context.Context) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) saveIAMConfig(ctx context.Context, item interface{}, path string, opts ...options) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadIAMConfig(ctx context.Context, item interface{}, path string) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) deleteIAMConfig(ctx context.Context, path string) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadPolicyDoc(ctx context.Context, policy string, m map[string]iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadPolicyDocs(ctx context.Context, m map[string]iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]auth.Credentials) error {
	if _, ok := m[user]; ok {
		return nil
	}

	reqURL, err := url.Parse(iamOS.authURL)
	if err != nil {
		return err
	}

	reqURL.Path = path.Join(reqURL.Path, "/v1/access", user)
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+iamOS.authToken)

	httpClient := &http.Client{Transport: iamOS.transport}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// TODO: should we cache negative acknowledgement of not found?
	if resp.StatusCode != http.StatusOK {
		return errors.New("invalid status code")
	}

	var response struct {
		AccessGrant string `json:"access_grant"`
		SecretKey   string `json:"secret_key"`
		Public      bool   `json:"public"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	// TODO: i forget if we're supposed to reject requests that have Public set to true

	// TODO: we need to eventually remove values from this map, but when? how do we have
	//       access to it? do we need to hold locks to mutate it? if so, which ones?
	m[user] = auth.Credentials{
		AccessKey:   user,
		AccessGrant: response.AccessGrant,
		SecretKey:   response.SecretKey,
		Status:      "on",
	}

	return nil
}

func (iamOS *IAMStorjAuthStore) loadUsers(ctx context.Context, userType IAMUserType, m map[string]auth.Credentials) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadGroup(ctx context.Context, group string, m map[string]GroupInfo) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadGroups(ctx context.Context, m map[string]GroupInfo) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	return nil
}

// Refresh IAMSys. If an object layer is passed in use that, otherwise load from global.
func (iamOS *IAMStorjAuthStore) loadAll(ctx context.Context, sys *IAMSys) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) savePolicyDoc(ctx context.Context, policyName string, p iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp MappedPolicy, opts ...options) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u UserIdentity, opts ...options) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) saveGroupInfo(ctx context.Context, name string, gi GroupInfo) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) deletePolicyDoc(ctx context.Context, name string) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) deleteGroupInfo(ctx context.Context, name string) error {
	return nil
}

func (iamOS *IAMStorjAuthStore) watch(ctx context.Context, sys *IAMSys) {
	// Refresh IAMSys.
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.NewTimer(globalRefreshIAMInterval).C:
			logger.LogIf(ctx, iamOS.loadAll(ctx, sys))
		}
	}
}
