package cmd

import (
	"context"

	"github.com/minio/minio/pkg/auth"
	iampolicy "github.com/minio/minio/pkg/iam/policy"
)

// IAMNoAuthStore implements IAMStorageAPI
type IAMNoAuthStore struct {
}

func newIAMNoAuthStore(ctx context.Context, objAPI ObjectLayer) *IAMNoAuthStore {
	return &IAMNoAuthStore{}
}

func (iamOS *IAMNoAuthStore) lock() {
}

func (iamOS *IAMNoAuthStore) unlock() {
}

func (iamOS *IAMNoAuthStore) rlock() {
}

func (iamOS *IAMNoAuthStore) runlock() {
}

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
	m[user] = auth.Credentials{
		AccessKey: user,
		SecretKey: user,
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
}
