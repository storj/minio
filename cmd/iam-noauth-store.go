package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/auth"
	iampolicy "github.com/minio/minio/pkg/iam/policy"
)

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

// IAMNoAuthStore implements IAMStorageAPI
type IAMNoAuthStore struct {
	mu sync.RWMutex
}

func newIAMNoAuthStore(ctx context.Context, objAPI ObjectLayer) *IAMNoAuthStore {
	return &IAMNoAuthStore{}
}

func (iamOS *IAMNoAuthStore) lock()    { iamOS.mu.Lock() }
func (iamOS *IAMNoAuthStore) unlock()  { iamOS.mu.Unlock() }
func (iamOS *IAMNoAuthStore) rlock()   { iamOS.mu.RLock() }
func (iamOS *IAMNoAuthStore) runlock() { iamOS.mu.RUnlock() }

// Migrate users directory in a single scan.
func (iamOS *IAMNoAuthStore) migrateUsersConfigToV1(ctx context.Context, isSTS bool) error {
	return nil
}

func (iamOS *IAMNoAuthStore) migrateToV1(ctx context.Context) error {
	return nil
}

// Should be called under config migration lock
func (iamOS *IAMNoAuthStore) migrateBackendFormat(ctx context.Context) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveIAMConfig(item interface{}, path string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadIAMConfig(item interface{}, path string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteIAMConfig(path string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadPolicyDoc(policy string, m map[string]iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadPolicyDocs(ctx context.Context, m map[string]iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadUser(user string, userType IAMUserType, m map[string]auth.Credentials) error {
	if _, ok := m[user]; ok {
		return nil
	}

	// TODO: is there a better way to configure this?
	host := getenv("MINIO_NOAUTH_SERVER_ADDR", "localhost:8000")
	token := getenv("MINIO_NOAUTH_AUTH_TOKEN", "")

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/v1/access/%s", host, user), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// TODO: should iamOS have it's own http client instead of the DefaultClient?
	resp, err := http.DefaultClient.Do(req)
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
		AccessKey: response.AccessGrant,
		SecretKey: response.SecretKey,
		Status:    "on",
	}

	return nil
}

func (iamOS *IAMNoAuthStore) loadUsers(ctx context.Context, userType IAMUserType, m map[string]auth.Credentials) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadGroup(group string, m map[string]GroupInfo) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadGroups(ctx context.Context, m map[string]GroupInfo) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadMappedPolicy(name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	return nil
}

// Refresh IAMSys. If an object layer is passed in use that, otherwise load from global.
func (iamOS *IAMNoAuthStore) loadAll(ctx context.Context, sys *IAMSys) error {
	return nil
}

func (iamOS *IAMNoAuthStore) savePolicyDoc(policyName string, p iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveMappedPolicy(name string, userType IAMUserType, isGroup bool, mp MappedPolicy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveUserIdentity(name string, userType IAMUserType, u UserIdentity) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveGroupInfo(name string, gi GroupInfo) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deletePolicyDoc(name string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteMappedPolicy(name string, userType IAMUserType, isGroup bool) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteUserIdentity(name string, userType IAMUserType) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteGroupInfo(name string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) watch(ctx context.Context, sys *IAMSys) {
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
