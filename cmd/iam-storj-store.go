package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/auth"
	iampolicy "github.com/storj/minio/pkg/iam/policy"
)

// IAMStorjAuthStore implements IAMStorageAPI
type IAMStorjAuthStore struct {
	mu        sync.RWMutex
	transport *http.Transport
	authURL   string
	authToken string
}

// NewIAMStorjAuthStore creates a Storj-specific Minio IAM store.
func NewIAMStorjAuthStore(objAPI ObjectLayer, authURL, authToken string) *IAMStorjAuthStore {
	return &IAMStorjAuthStore{
		transport: NewGatewayHTTPTransport(),
		authURL:   authURL,
		authToken: authToken,
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

func (iamOS *IAMStorjAuthStore) loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]auth.Credentials) (err error) {
	if _, ok := m[user]; ok {
		return nil
	}

	defer func() {
		logger.LogIf(ctx, err)
	}()

	reqURL, err := url.Parse(iamOS.authURL)
	if err != nil {
		return err
	}

	reqURL.Path = path.Join(reqURL.Path, "/v1/access", user)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+iamOS.authToken)
	req.Header.Set("Forwarded", "for="+logger.GetReqInfo(ctx).RemoteHost)

	httpClient := &http.Client{Transport: iamOS.transport}
	delay := ExponentialBackoff{Min: 100 * time.Millisecond, Max: 5 * time.Second}

	var response struct {
		AccessGrant string `json:"access_grant"`
		SecretKey   string `json:"secret_key"`
		Public      bool   `json:"public"`
	}

	for {
		resp, err := httpClient.Do(req)
		if err != nil {
			if !delay.Maxed() {
				if err := delay.Wait(ctx); err != nil {
					return ctx.Err()
				}
				continue
			}
			return err
		}

		// Use an anonymous function for deferring the response close before the
		// next retry and not pilling it up when the method returns.
		retry, err := func() (retry bool, _ error) {
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusInternalServerError {
				return true, nil // auth only returns this for unexpected issues
			}

			if resp.StatusCode != http.StatusOK {
				return false, fmt.Errorf("invalid status code: %d", resp.StatusCode)
			}

			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				if !delay.Maxed() {
					return true, nil
				}
				return false, err
			}
			return false, nil
		}()

		if retry {
			if err := delay.Wait(ctx); err != nil {
				return ctx.Err()
			}
			continue
		}
		if err == nil {
			// TODO: We need to eventually remove values from this map.
			// Using IAMStorjAuthStore.watch()?  Using Credentials.Expiration?
			m[user] = auth.Credentials{
				AccessKey:   user,
				AccessGrant: response.AccessGrant,
				SecretKey:   response.SecretKey,
				Status:      "on",
			}
		}
		return err
	}
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

// ExponentialBackoff keeps track of how long we should sleep between
// failing attempts.  It is duplicated from
// https://github.com/storj/linksharing/blob/main/sharing/utils.go
type ExponentialBackoff struct {
	delay time.Duration
	Max   time.Duration
	Min   time.Duration
}

func (e *ExponentialBackoff) init() {
	if e.Max == 0 {
		// maximum delay - pulled from net/http.Server.Serve
		e.Max = time.Second
	}
	if e.Min == 0 {
		// minimum delay - pulled from net/http.Server.Serve
		e.Min = 5 * time.Millisecond
	}
}

// Wait should be called when there is a failure. Each time it is called
// it will sleep an exponentially longer time, up to a max.
func (e *ExponentialBackoff) Wait(ctx context.Context) error {
	e.init()
	if e.delay == 0 {
		e.delay = e.Min
	} else {
		e.delay *= 2
	}
	if e.delay > e.Max {
		e.delay = e.Max
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	t := time.NewTimer(e.delay)
	defer t.Stop()

	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Maxed returns true if the wait time has maxed out.
func (e *ExponentialBackoff) Maxed() bool {
	e.init()
	return e.delay == e.Max
}
