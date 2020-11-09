package cmd

import (
	"context"
	"time"

	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/auth"
	iampolicy "github.com/minio/minio/pkg/iam/policy"
)

// IAMNoAuthStore implements IAMStorageAPI
type IAMNoAuthStore struct {
}

func newIAMNoAuthStore(objAPI ObjectLayer) *IAMNoAuthStore {
	return &IAMNoAuthStore{}
}

func (iamOS *IAMNoAuthStore) lock()   {}
func (iamOS *IAMNoAuthStore) unlock() {}

func (iamOS *IAMNoAuthStore) rlock()   {}
func (iamOS *IAMNoAuthStore) runlock() {}

// Should be called under config migration lock
func (iamOS *IAMNoAuthStore) migrateBackendFormat(ctx context.Context) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveIAMConfig(ctx context.Context, item interface{}, path string, opts ...options) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadIAMConfig(ctx context.Context, item interface{}, path string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteIAMConfig(ctx context.Context, path string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadPolicyDoc(ctx context.Context, policy string, m map[string]iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadPolicyDocs(ctx context.Context, m map[string]iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]auth.Credentials) error {
	databaseOfUsers := map[string]auth.Credentials{
		"aaa": {
			AccessKey: "1gioUdqrCiaf7XNZsQGZ9a6qNVACsdgeTrWuMdYkBDKx8LQYu7V2We8Qis3iE6iAd7TH9gcYiM875WCr7LdVYHBdkzgcTGNGSP1RXLuLaqzagGNRQZ4GgxJFqqZsfKVikeVWdjosh6joiKEQsbxwhvnSk3kJmJ5HSkXWqX7T9AEFEpXMFVR955CFBzKiekFafFq8EYY7tautiUPTKsLuhPht1KshyZBTGRLkJQN31g8ZE4mN5yet5BVgsgju3JSmPhTpWnGPhMDANTNeA4KtQuZpgLNfTZrirBsw6VpGtUukdFBKPTmmudMk6cfBkLyRtFkwECvpNhb5WwuFP54exapVZstnq8o7Uk2a8jomS3MPejYXCAote9e7Uuoa1nynfsNvN1TjDGGL2uReCbH6yzWurq",
			SecretKey: "11111111",
			Status:    "on",
		},
		"bbb": {
			AccessKey: "1gioUdqrCiaf7XNZsQGZ9a6qNVACsdgeTrWuMdYkBDKx8LQYu7V2We8Qis3iE6iAd7TH9gcYiM875WCr7LdVYHBdkzgcTGNGSP1RXLuLaqzagGNRQZ4GgxJFqqZsfKVikeVWdjosh6joiKEQsbxwhvnSk3kJmJ5HSkXWqX7T9AEFEpXMFVR955CFBzKiekFafFq8F9K9facGmqyMi2fnUy7aHwQGgf5dwCSpexJo4LpjhJWjYzLRE4q4DUPHBN2x6QhShuF2nEyyK58ki2BJb41V7AxacbFeJSaD33U4zEFj7ScDuwJs1Z4wiFktNZxKzjsBNxb8BKCe1C4Pn1PMMPJ36Gg22HoDo82W52PmkMv81DrzpEJT7xYcNgwCaTQYuwpW9MFuZJ8TJh7eQdzv54VV4q",
			SecretKey: "22222222",
			Status:    "on",
		},
		"ccc": {
			AccessKey: "1gioUdqrCiaf7XNZsQGZ9a6qNVACsdgeTrWuMdYkBDKx8LQYu7V2We8Qis3iE6iAd7TH9gcYiM875WCr7LdVYHBdkzgcTGNGSP1RXLuLaqzagGNRQZ4GgxJFqqZsfKVikeVWdjosh6joiKEQsbxwhvnSk3kJmJ5HSkXWqX7T9AEFEpXMFVR955CFBzKiekFafFq8F3tp5wu1gxJ7TzCfo5rycBs2DJNRGtusmQV2PLhUZkAbStdJPDDWKADoSDecg9pFnt6hpVCzNiryuYFTjJqx9qVx5GeXBLD5yhmY1bXpu5KRXow7PW8n9kidmeKP3htorQdHsYQtB3SyDYWVqEyiMcZKsH4aExfjfghKUeYYU2TPdpjsLHfVKECuqaMEcdqM6nrXZkPMjMJbMG27Hy77jT",
			SecretKey: "33333333",
			Status:    "on",
		},
	}

	m[user] = databaseOfUsers[user]
	return nil
}

func (iamOS *IAMNoAuthStore) loadUsers(ctx context.Context, userType IAMUserType, m map[string]auth.Credentials) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadGroup(ctx context.Context, group string, m map[string]GroupInfo) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadGroups(ctx context.Context, m map[string]GroupInfo) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	return nil
}

// Refresh IAMSys. If an object layer is passed in use that, otherwise load from global.
func (iamOS *IAMNoAuthStore) loadAll(ctx context.Context, sys *IAMSys) error {
	return nil
}

func (iamOS *IAMNoAuthStore) savePolicyDoc(ctx context.Context, policyName string, p iampolicy.Policy) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp MappedPolicy, opts ...options) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u UserIdentity, opts ...options) error {
	return nil
}

func (iamOS *IAMNoAuthStore) saveGroupInfo(ctx context.Context, name string, gi GroupInfo) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deletePolicyDoc(ctx context.Context, name string) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error {
	return nil
}

func (iamOS *IAMNoAuthStore) deleteGroupInfo(ctx context.Context, name string) error {
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
