/*
 * MinIO Cloud Storage, (C) 2018-2019 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/storj/minio/cmd/config"
	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/auth"
	iampolicy "github.com/storj/minio/pkg/iam/policy"
	"github.com/storj/minio/pkg/madmin"
)

// UsersSysType - defines the type of users and groups system that is
// active on the server.
type UsersSysType string

// Types of users configured in the server.
const (
	// This mode uses the internal users system in MinIO.
	MinIOUsersSysType UsersSysType = "MinIOUsersSys"

	// This mode uses users and groups from a configured LDAP
	// server.
	LDAPUsersSysType UsersSysType = "LDAPUsersSys"

	// This mode does uses Storj's Auth Svc to restrict users and groups.
	StorjAuthSysType UsersSysType = "StorjAuthSys"
)

const (
	// IAM configuration directory.
	iamConfigPrefix = minioConfigPrefix + "/iam"

	// IAM users directory.
	iamConfigUsersPrefix = iamConfigPrefix + "/users/"

	// IAM service accounts directory.
	iamConfigServiceAccountsPrefix = iamConfigPrefix + "/service-accounts/"

	// IAM groups directory.
	iamConfigGroupsPrefix = iamConfigPrefix + "/groups/"

	// IAM policies directory.
	iamConfigPoliciesPrefix = iamConfigPrefix + "/policies/"

	// IAM sts directory.
	iamConfigSTSPrefix = iamConfigPrefix + "/sts/"

	// IAM Policy DB prefixes.
	iamConfigPolicyDBPrefix                = iamConfigPrefix + "/policydb/"
	iamConfigPolicyDBUsersPrefix           = iamConfigPolicyDBPrefix + "users/"
	iamConfigPolicyDBSTSUsersPrefix        = iamConfigPolicyDBPrefix + "sts-users/"
	iamConfigPolicyDBServiceAccountsPrefix = iamConfigPolicyDBPrefix + "service-accounts/"
	iamConfigPolicyDBGroupsPrefix          = iamConfigPolicyDBPrefix + "groups/"

	// IAM identity file which captures identity credentials.
	iamIdentityFile = "identity.json"

	// IAM policy file which provides policies for each users.
	iamPolicyFile = "policy.json"

	// IAM group members file
	iamGroupMembersFile = "members.json"

	// IAM format file
	iamFormatFile = "format.json"

	iamFormatVersion1 = 1
)

const (
	statusEnabled  = "enabled"
	statusDisabled = "disabled"
)

type iamFormat struct {
	Version int `json:"version"`
}

func newIAMFormatVersion1() iamFormat {
	return iamFormat{Version: iamFormatVersion1}
}

func getIAMFormatFilePath() string {
	return iamConfigPrefix + SlashSeparator + iamFormatFile
}

func getUserIdentityPath(user string, userType IAMUserType) string {
	var basePath string
	switch userType {
	case srvAccUser:
		basePath = iamConfigServiceAccountsPrefix
	case stsUser:
		basePath = iamConfigSTSPrefix
	default:
		basePath = iamConfigUsersPrefix
	}
	return pathJoin(basePath, user, iamIdentityFile)
}

func getGroupInfoPath(group string) string {
	return pathJoin(iamConfigGroupsPrefix, group, iamGroupMembersFile)
}

func getPolicyDocPath(name string) string {
	return pathJoin(iamConfigPoliciesPrefix, name, iamPolicyFile)
}

func getMappedPolicyPath(name string, userType IAMUserType, isGroup bool) string {
	if isGroup {
		return pathJoin(iamConfigPolicyDBGroupsPrefix, name+".json")
	}
	switch userType {
	case srvAccUser:
		return pathJoin(iamConfigPolicyDBServiceAccountsPrefix, name+".json")
	case stsUser:
		return pathJoin(iamConfigPolicyDBSTSUsersPrefix, name+".json")
	default:
		return pathJoin(iamConfigPolicyDBUsersPrefix, name+".json")
	}
}

// UserIdentity represents a user's secret key and their status
type UserIdentity struct {
	Version     int              `json:"version"`
	Credentials auth.Credentials `json:"credentials"`
}

func newUserIdentity(cred auth.Credentials) UserIdentity {
	return UserIdentity{Version: 1, Credentials: cred}
}

// GroupInfo contains info about a group
type GroupInfo struct {
	Version int      `json:"version"`
	Status  string   `json:"status"`
	Members []string `json:"members"`
}

func newGroupInfo(members []string) GroupInfo {
	return GroupInfo{Version: 1, Status: statusEnabled, Members: members}
}

// MappedPolicy represents a policy name mapped to a user or group
type MappedPolicy struct {
	Version  int    `json:"version"`
	Policies string `json:"policy"`
}

// converts a mapped policy into a slice of distinct policies
func (mp MappedPolicy) toSlice() []string {
	var policies []string
	for _, policy := range strings.Split(mp.Policies, ",") {
		policy = strings.TrimSpace(policy)
		if policy == "" {
			continue
		}
		policies = append(policies, policy)
	}
	return policies
}

func (mp MappedPolicy) policySet() set.StringSet {
	var policies []string
	for _, policy := range strings.Split(mp.Policies, ",") {
		policy = strings.TrimSpace(policy)
		if policy == "" {
			continue
		}
		policies = append(policies, policy)
	}
	return set.CreateStringSet(policies...)
}

func newMappedPolicy(policy string) MappedPolicy {
	return MappedPolicy{Version: 1, Policies: policy}
}

// IAMSys - config system.
type IAMSys struct {
	sync.Mutex

	usersSysType UsersSysType

	// map of policy names to policy definitions
	iamPolicyDocsMap map[string]iampolicy.Policy
	// map of usernames to credentials
	iamUsersMap map[string]auth.Credentials
	// map of group names to group info
	iamGroupsMap map[string]GroupInfo
	// map of user names to groups they are a member of
	iamUserGroupMemberships map[string]set.StringSet
	// map of usernames/temporary access keys to policy names
	iamUserPolicyMap map[string]MappedPolicy
	// map of group names to policy names
	iamGroupPolicyMap map[string]MappedPolicy

	// Persistence layer for IAM subsystem
	store         IAMStorageAPI
	storeFallback bool
}

// IAMUserType represents a user type inside MinIO server
type IAMUserType int

const (
	regularUser IAMUserType = iota
	stsUser
	srvAccUser
)

// key options
type options struct {
	ttl int64 //expiry in seconds
}

// IAMStorageAPI defines an interface for the IAM persistence layer
type IAMStorageAPI interface {
	lock()
	unlock()

	rlock()
	runlock()

	migrateBackendFormat(context.Context) error

	loadPolicyDoc(ctx context.Context, policy string, m map[string]iampolicy.Policy) error
	loadPolicyDocs(ctx context.Context, m map[string]iampolicy.Policy) error

	loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]auth.Credentials) error
	loadUsers(ctx context.Context, userType IAMUserType, m map[string]auth.Credentials) error

	loadGroup(ctx context.Context, group string, m map[string]GroupInfo) error
	loadGroups(ctx context.Context, m map[string]GroupInfo) error

	loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error
	loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error

	loadAll(context.Context, *IAMSys) error

	saveIAMConfig(ctx context.Context, item interface{}, path string, opts ...options) error
	loadIAMConfig(ctx context.Context, item interface{}, path string) error
	deleteIAMConfig(ctx context.Context, path string) error

	savePolicyDoc(ctx context.Context, policyName string, p iampolicy.Policy) error
	saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp MappedPolicy, opts ...options) error
	saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u UserIdentity, opts ...options) error
	saveGroupInfo(ctx context.Context, group string, gi GroupInfo) error

	deletePolicyDoc(ctx context.Context, policyName string) error
	deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error
	deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error
	deleteGroupInfo(ctx context.Context, name string) error

	watch(context.Context, *IAMSys)
}

// LoadGroup - loads a specific group from storage, and updates the
// memberships cache. If the specified group does not exist in
// storage, it is removed from in-memory maps as well - this
// simplifies the implementation for group removal. This is called
// only via IAM notifications.
func (sys *IAMSys) LoadGroup(objAPI ObjectLayer, group string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	err := sys.store.loadGroup(context.Background(), group, sys.iamGroupsMap)
	if err != nil && err != errNoSuchGroup {
		return err
	}

	if err == errNoSuchGroup {
		// group does not exist - so remove from memory.
		sys.removeGroupFromMembershipsMap(group)
		delete(sys.iamGroupsMap, group)
		delete(sys.iamGroupPolicyMap, group)
		return nil
	}

	gi := sys.iamGroupsMap[group]

	// Updating the group memberships cache happens in two steps:
	//
	// 1. Remove the group from each user's list of memberships.
	// 2. Add the group to each member's list of memberships.
	//
	// This ensures that regardless of members being added or
	// removed, the cache stays current.
	sys.removeGroupFromMembershipsMap(group)
	sys.updateGroupMembershipsMap(group, &gi)
	return nil
}

// LoadPolicy - reloads a specific canned policy from backend disks or etcd.
func (sys *IAMSys) LoadPolicy(objAPI ObjectLayer, policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	return sys.store.loadPolicyDoc(context.Background(), policyName, sys.iamPolicyDocsMap)
}

// LoadPolicyMapping - loads the mapped policy for a user or group
// from storage into server memory.
func (sys *IAMSys) LoadPolicyMapping(objAPI ObjectLayer, userOrGroup string, isGroup bool) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	var err error
	if isGroup {
		err = sys.store.loadMappedPolicy(context.Background(), userOrGroup, regularUser, isGroup, sys.iamGroupPolicyMap)
	} else {
		err = sys.store.loadMappedPolicy(context.Background(), userOrGroup, regularUser, isGroup, sys.iamUserPolicyMap)
	}

	// Ignore policy not mapped error
	if err != nil && err != errNoSuchPolicy {
		return err
	}

	return nil
}

// LoadUser - reloads a specific user from backend disks or etcd.
func (sys *IAMSys) LoadUser(objAPI ObjectLayer, accessKey string, userType IAMUserType) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	err := sys.store.loadUser(context.Background(), accessKey, userType, sys.iamUsersMap)
	if err != nil {
		return err
	}
	err = sys.store.loadMappedPolicy(context.Background(), accessKey, userType, false, sys.iamUserPolicyMap)
	// Ignore policy not mapped error
	if err != nil && err != errNoSuchPolicy {
		return err
	}

	return nil
}

// LoadServiceAccount - reloads a specific service account from backend disks or etcd.
func (sys *IAMSys) LoadServiceAccount(accessKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	err := sys.store.loadUser(context.Background(), accessKey, srvAccUser, sys.iamUsersMap)
	if err != nil {
		return err
	}

	return nil
}

// Perform IAM configuration migration.
func (sys *IAMSys) doIAMConfigMigration(ctx context.Context) error {
	return sys.store.migrateBackendFormat(ctx)
}

// InitCustomStore initializes an IAM store, shortcutting much of minio's startup.
func InitCustomStore(store IAMStorageAPI, sysType UsersSysType) {
	iamSys := NewIAMSys()
	iamSys.store = store
	iamSys.usersSysType = sysType
	globalIAMSys = iamSys
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

// InitStore initializes IAM stores
func (sys *IAMSys) InitStore(objAPI ObjectLayer) {
	sys.Lock()
	defer sys.Unlock()

	authURL := getenv("MINIO_STORJ_AUTH_URL", "http://127.0.0.1:8000")
	authToken := getenv("MINIO_STORJ_AUTH_TOKEN", "")
	sys.store = NewIAMStorjAuthStore(objAPI, authURL, authToken)
	sys.usersSysType = StorjAuthSysType
}

// Initialized check if IAM is initialized
func (sys *IAMSys) Initialized() bool {
	if sys == nil {
		return false
	}
	sys.Lock()
	defer sys.Unlock()
	return sys.store != nil
}

// DeletePolicy - deletes a canned policy from backend or etcd.
func (sys *IAMSys) DeletePolicy(policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if policyName == "" {
		return errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	err := sys.store.deletePolicyDoc(context.Background(), policyName)
	if err == errNoSuchPolicy {
		// Ignore error if policy is already deleted.
		err = nil
	}

	delete(sys.iamPolicyDocsMap, policyName)

	// Delete user-policy mappings that will no longer apply
	for u, mp := range sys.iamUserPolicyMap {
		pset := mp.policySet()
		if pset.Contains(policyName) {
			cr, ok := sys.iamUsersMap[u]
			if !ok {
				// This case cannot happen
				return errNoSuchUser
			}
			pset.Remove(policyName)
			// User is from STS if the cred are temporary
			if cr.IsTemp() {
				sys.policyDBSet(u, strings.Join(pset.ToSlice(), ","), stsUser, false)
			} else {
				sys.policyDBSet(u, strings.Join(pset.ToSlice(), ","), regularUser, false)
			}
		}
	}

	// Delete group-policy mappings that will no longer apply
	for g, mp := range sys.iamGroupPolicyMap {
		pset := mp.policySet()
		if pset.Contains(policyName) {
			pset.Remove(policyName)
			sys.policyDBSet(g, strings.Join(pset.ToSlice(), ","), regularUser, true)
		}
	}

	return err
}

// InfoPolicy - expands the canned policy into its JSON structure.
func (sys *IAMSys) InfoPolicy(policyName string) (iampolicy.Policy, error) {
	if !sys.Initialized() {
		return iampolicy.Policy{}, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	v, ok := sys.iamPolicyDocsMap[policyName]
	if !ok {
		return iampolicy.Policy{}, errNoSuchPolicy
	}

	return v, nil
}

// ListPolicies - lists all canned policies.
func (sys *IAMSys) ListPolicies() (map[string]iampolicy.Policy, error) {
	if !sys.Initialized() {
		return nil, errServerNotInitialized
	}

	sys.store.rlock()
	fallback := sys.storeFallback
	sys.store.runlock()

	if fallback {
		if err := sys.store.loadAll(context.Background(), sys); err != nil {
			return nil, err
		}
	}

	sys.store.rlock()
	defer sys.store.runlock()

	policyDocsMap := make(map[string]iampolicy.Policy, len(sys.iamPolicyDocsMap))
	for k, v := range sys.iamPolicyDocsMap {
		policyDocsMap[k] = v
	}

	return policyDocsMap, nil
}

// SetPolicy - sets a new name policy.
func (sys *IAMSys) SetPolicy(policyName string, p iampolicy.Policy) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if p.IsEmpty() || policyName == "" {
		return errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	if err := sys.store.savePolicyDoc(context.Background(), policyName, p); err != nil {
		return err
	}

	sys.iamPolicyDocsMap[policyName] = p
	return nil
}

// DeleteUser - delete user (only for long-term users not STS users).
func (sys *IAMSys) DeleteUser(accessKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	// First we remove the user from their groups.
	userInfo, getErr := sys.GetUserInfo(accessKey)
	if getErr != nil {
		return getErr
	}

	for _, group := range userInfo.MemberOf {
		removeErr := sys.RemoveUsersFromGroup(group, []string{accessKey})
		if removeErr != nil {
			return removeErr
		}
	}

	// Next we can remove the user from memory and IAM store
	sys.store.lock()
	defer sys.store.unlock()

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	// Delete any service accounts if any first.
	for _, u := range sys.iamUsersMap {
		if u.IsServiceAccount() {
			if u.ParentUser == accessKey {
				_ = sys.store.deleteUserIdentity(context.Background(), u.AccessKey, srvAccUser)
				delete(sys.iamUsersMap, u.AccessKey)
			}
		}
	}

	// It is ok to ignore deletion error on the mapped policy
	sys.store.deleteMappedPolicy(context.Background(), accessKey, regularUser, false)
	err := sys.store.deleteUserIdentity(context.Background(), accessKey, regularUser)
	if err == errNoSuchUser {
		// ignore if user is already deleted.
		err = nil
	}

	delete(sys.iamUsersMap, accessKey)
	delete(sys.iamUserPolicyMap, accessKey)

	return err
}

// CurrentPolicies - returns comma separated policy string, from
// an input policy after validating if there are any current
// policies which exist on MinIO corresponding to the input.
func (sys *IAMSys) CurrentPolicies(policyName string) string {
	if !sys.Initialized() {
		return ""
	}

	sys.store.rlock()
	defer sys.store.runlock()

	var policies []string
	mp := newMappedPolicy(policyName)
	for _, policy := range mp.toSlice() {
		_, found := sys.iamPolicyDocsMap[policy]
		if found {
			policies = append(policies, policy)
		}
	}
	return strings.Join(policies, ",")
}

// SetTempUser - set temporary user credentials, these credentials have an expiry.
func (sys *IAMSys) SetTempUser(accessKey string, cred auth.Credentials, policyName string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	return NotImplemented{}
}

// ListUsers - list all users.
func (sys *IAMSys) ListUsers() (map[string]madmin.UserInfo, error) {
	if !sys.Initialized() {
		return nil, errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return nil, errIAMActionNotAllowed
	}

	sys.store.rlock()
	fallback := sys.storeFallback
	sys.store.runlock()

	if fallback {
		if err := sys.store.loadAll(context.Background(), sys); err != nil {
			return nil, err
		}
	}

	sys.store.rlock()
	defer sys.store.runlock()

	var users = make(map[string]madmin.UserInfo)

	for k, v := range sys.iamUsersMap {
		if !v.IsTemp() && !v.IsServiceAccount() {
			users[k] = madmin.UserInfo{
				PolicyName: sys.iamUserPolicyMap[k].Policies,
				Status: func() madmin.AccountStatus {
					if v.IsValid() {
						return madmin.AccountEnabled
					}
					return madmin.AccountDisabled
				}(),
			}
		}
	}

	return users, nil
}

// IsTempUser - returns if given key is a temporary user.
func (sys *IAMSys) IsTempUser(name string) (bool, error) {
	if !sys.Initialized() {
		return false, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	cred, found := sys.iamUsersMap[name]
	if !found {
		return false, errNoSuchUser
	}

	return cred.IsTemp(), nil
}

// IsServiceAccount - returns if given key is a service account
func (sys *IAMSys) IsServiceAccount(name string) (bool, string, error) {
	if !sys.Initialized() {
		return false, "", errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	cred, found := sys.iamUsersMap[name]
	if !found {
		return false, "", errNoSuchUser
	}

	if cred.IsServiceAccount() {
		return true, cred.ParentUser, nil
	}

	return false, "", nil
}

// GetUserInfo - get info on a user.
func (sys *IAMSys) GetUserInfo(name string) (u madmin.UserInfo, err error) {
	if !sys.Initialized() {
		return u, errServerNotInitialized
	}

	sys.store.rlock()
	defer sys.store.runlock()

	if sys.usersSysType != MinIOUsersSysType {
		// If the user has a mapped policy or is a member of a group, we
		// return that info. Otherwise we return error.
		mappedPolicy, ok1 := sys.iamUserPolicyMap[name]
		memberships, ok2 := sys.iamUserGroupMemberships[name]
		if !ok1 && !ok2 {
			return u, errNoSuchUser
		}
		return madmin.UserInfo{
			PolicyName: mappedPolicy.Policies,
			MemberOf:   memberships.ToSlice(),
		}, nil
	}

	cred, found := sys.iamUsersMap[name]
	if !found {
		return u, errNoSuchUser
	}

	if cred.IsTemp() || cred.IsServiceAccount() {
		return u, errIAMActionNotAllowed
	}

	u = madmin.UserInfo{
		PolicyName: sys.iamUserPolicyMap[name].Policies,
		Status: func() madmin.AccountStatus {
			if cred.IsValid() {
				return madmin.AccountEnabled
			}
			return madmin.AccountDisabled
		}(),
		MemberOf: sys.iamUserGroupMemberships[name].ToSlice(),
	}
	return u, nil
}

// SetUserStatus - sets current user status, supports disabled or enabled.
func (sys *IAMSys) SetUserStatus(accessKey string, status madmin.AccountStatus) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if status != madmin.AccountEnabled && status != madmin.AccountDisabled {
		return errInvalidArgument
	}

	sys.store.lock()
	defer sys.store.unlock()

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	cred, ok := sys.iamUsersMap[accessKey]
	if !ok {
		return errNoSuchUser
	}

	if cred.IsTemp() || cred.IsServiceAccount() {
		return errIAMActionNotAllowed
	}

	uinfo := newUserIdentity(auth.Credentials{
		AccessKey: accessKey,
		SecretKey: cred.SecretKey,
		Status: func() string {
			if status == madmin.AccountEnabled {
				return config.EnableOn
			}
			return config.EnableOff
		}(),
	})

	if err := sys.store.saveUserIdentity(context.Background(), accessKey, regularUser, uinfo); err != nil {
		return err
	}

	sys.iamUsersMap[accessKey] = uinfo.Credentials
	return nil
}

// SetUser - set user credentials and policy.
func (sys *IAMSys) SetUser(accessKey string, uinfo madmin.UserInfo) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	u := newUserIdentity(auth.Credentials{
		AccessKey: accessKey,
		SecretKey: uinfo.SecretKey,
		Status:    string(uinfo.Status),
	})

	sys.store.lock()
	defer sys.store.unlock()

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	cr, ok := sys.iamUsersMap[accessKey]
	if cr.IsTemp() && ok {
		return errIAMActionNotAllowed
	}

	if err := sys.store.saveUserIdentity(context.Background(), accessKey, regularUser, u); err != nil {
		return err
	}

	sys.iamUsersMap[accessKey] = u.Credentials

	// Set policy if specified.
	if uinfo.PolicyName != "" {
		return sys.policyDBSet(accessKey, uinfo.PolicyName, regularUser, false)
	}
	return nil
}

// SetUserSecretKey - sets user secret key
func (sys *IAMSys) SetUserSecretKey(accessKey string, secretKey string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	sys.store.lock()
	defer sys.store.unlock()

	cred, ok := sys.iamUsersMap[accessKey]
	if !ok {
		return errNoSuchUser
	}

	cred.SecretKey = secretKey
	u := newUserIdentity(cred)
	if err := sys.store.saveUserIdentity(context.Background(), accessKey, regularUser, u); err != nil {
		return err
	}

	sys.iamUsersMap[accessKey] = cred
	return nil
}

// GetUser - get user credentials
func (sys *IAMSys) GetUser(accessKey string) (cred auth.Credentials, ok bool) {
	if !sys.Initialized() {
		return cred, false
	}

	sys.store.rlock()
	fallback := sys.storeFallback
	sys.store.runlock()
	if fallback {
		sys.store.lock()
		// If user is already found proceed.
		if _, found := sys.iamUsersMap[accessKey]; !found {
			sys.store.loadUser(context.Background(), accessKey, regularUser, sys.iamUsersMap)
			if _, found = sys.iamUsersMap[accessKey]; found {
				// found user, load its mapped policies
				sys.store.loadMappedPolicy(context.Background(), accessKey, regularUser, false, sys.iamUserPolicyMap)
			} else {
				sys.store.loadUser(context.Background(), accessKey, srvAccUser, sys.iamUsersMap)
				if svc, found := sys.iamUsersMap[accessKey]; found {
					// Found service account, load its parent user and its mapped policies.
					if sys.usersSysType == MinIOUsersSysType {
						sys.store.loadUser(context.Background(), svc.ParentUser, regularUser, sys.iamUsersMap)
					}
					sys.store.loadMappedPolicy(context.Background(), svc.ParentUser, regularUser, false, sys.iamUserPolicyMap)
				} else {
					// None found fall back to STS users.
					sys.store.loadUser(context.Background(), accessKey, stsUser, sys.iamUsersMap)
					if _, found = sys.iamUsersMap[accessKey]; found {
						// STS user found, load its mapped policy.
						sys.store.loadMappedPolicy(context.Background(), accessKey, stsUser, false, sys.iamUserPolicyMap)
					}
				}
			}
		}

		// Load associated policies if any.
		for _, policy := range sys.iamUserPolicyMap[accessKey].toSlice() {
			if _, found := sys.iamPolicyDocsMap[policy]; !found {
				sys.store.loadPolicyDoc(context.Background(), policy, sys.iamPolicyDocsMap)
			}
		}

		sys.buildUserGroupMemberships()
		sys.store.unlock()
	}

	sys.store.rlock()
	defer sys.store.runlock()

	cred, ok = sys.iamUsersMap[accessKey]
	if ok && cred.IsValid() {
		if cred.ParentUser != "" && sys.usersSysType == MinIOUsersSysType {
			_, ok = sys.iamUsersMap[cred.ParentUser]
		}
		// for LDAP service accounts with ParentUser set
		// we have no way to validate, either because user
		// doesn't need an explicit policy as it can come
		// automatically from a group. We are safe to ignore
		// this and continue as policies would fail eventually
		// the policies are missing or not configured.
	}
	return cred, ok && cred.IsValid()
}

// AddUsersToGroup - adds users to a group, creating the group if
// needed. No error if user(s) already are in the group.
func (sys *IAMSys) AddUsersToGroup(group string, members []string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if group == "" {
		return errInvalidArgument
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	sys.store.lock()
	defer sys.store.unlock()

	// Validate that all members exist.
	for _, member := range members {
		cr, ok := sys.iamUsersMap[member]
		if !ok {
			return errNoSuchUser
		}
		if cr.IsTemp() {
			return errIAMActionNotAllowed
		}
	}

	gi, ok := sys.iamGroupsMap[group]
	if !ok {
		// Set group as enabled by default when it doesn't
		// exist.
		gi = newGroupInfo(members)
	} else {
		mergedMembers := append(gi.Members, members...)
		uniqMembers := set.CreateStringSet(mergedMembers...).ToSlice()
		gi.Members = uniqMembers
	}

	if err := sys.store.saveGroupInfo(context.Background(), group, gi); err != nil {
		return err
	}

	sys.iamGroupsMap[group] = gi

	// update user-group membership map
	for _, member := range members {
		gset := sys.iamUserGroupMemberships[member]
		if gset == nil {
			gset = set.CreateStringSet(group)
		} else {
			gset.Add(group)
		}
		sys.iamUserGroupMemberships[member] = gset
	}

	return nil
}

// RemoveUsersFromGroup - remove users from group. If no users are
// given, and the group is empty, deletes the group as well.
func (sys *IAMSys) RemoveUsersFromGroup(group string, members []string) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if group == "" {
		return errInvalidArgument
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	sys.store.lock()
	defer sys.store.unlock()

	// Validate that all members exist.
	for _, member := range members {
		cr, ok := sys.iamUsersMap[member]
		if !ok {
			return errNoSuchUser
		}
		if cr.IsTemp() {
			return errIAMActionNotAllowed
		}
	}

	gi, ok := sys.iamGroupsMap[group]
	if !ok {
		return errNoSuchGroup
	}

	// Check if attempting to delete a non-empty group.
	if len(members) == 0 && len(gi.Members) != 0 {
		return errGroupNotEmpty
	}

	if len(members) == 0 {
		// len(gi.Members) == 0 here.

		// Remove the group from storage. First delete the
		// mapped policy. No-mapped-policy case is ignored.
		if err := sys.store.deleteMappedPolicy(context.Background(), group, regularUser, true); err != nil && err != errNoSuchPolicy {
			return err
		}
		if err := sys.store.deleteGroupInfo(context.Background(), group); err != nil && err != errNoSuchGroup {
			return err
		}

		// Delete from server memory
		delete(sys.iamGroupsMap, group)
		delete(sys.iamGroupPolicyMap, group)
		return nil
	}

	// Only removing members.
	s := set.CreateStringSet(gi.Members...)
	d := set.CreateStringSet(members...)
	gi.Members = s.Difference(d).ToSlice()

	err := sys.store.saveGroupInfo(context.Background(), group, gi)
	if err != nil {
		return err
	}
	sys.iamGroupsMap[group] = gi

	// update user-group membership map
	for _, member := range members {
		gset := sys.iamUserGroupMemberships[member]
		if gset == nil {
			continue
		}
		gset.Remove(group)
		sys.iamUserGroupMemberships[member] = gset
	}

	return nil
}

// SetGroupStatus - enable/disabled a group
func (sys *IAMSys) SetGroupStatus(group string, enabled bool) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return errIAMActionNotAllowed
	}

	sys.store.lock()
	defer sys.store.unlock()

	if group == "" {
		return errInvalidArgument
	}

	gi, ok := sys.iamGroupsMap[group]
	if !ok {
		return errNoSuchGroup
	}

	if enabled {
		gi.Status = statusEnabled
	} else {
		gi.Status = statusDisabled
	}

	if err := sys.store.saveGroupInfo(context.Background(), group, gi); err != nil {
		return err
	}
	sys.iamGroupsMap[group] = gi
	return nil
}

// GetGroupDescription - builds up group description
func (sys *IAMSys) GetGroupDescription(group string) (gd madmin.GroupDesc, err error) {
	if !sys.Initialized() {
		return gd, errServerNotInitialized
	}

	ps, err := sys.PolicyDBGet(group, true)
	if err != nil {
		return gd, err
	}

	// A group may be mapped to at most one policy.
	policy := ""
	if len(ps) > 0 {
		policy = ps[0]
	}

	if sys.usersSysType != MinIOUsersSysType {
		return madmin.GroupDesc{
			Name:   group,
			Policy: policy,
		}, nil
	}

	sys.store.rlock()
	defer sys.store.runlock()

	gi, ok := sys.iamGroupsMap[group]
	if !ok {
		return gd, errNoSuchGroup
	}

	return madmin.GroupDesc{
		Name:    group,
		Status:  gi.Status,
		Members: gi.Members,
		Policy:  policy,
	}, nil
}

// ListGroups - lists groups.
func (sys *IAMSys) ListGroups() (r []string, err error) {
	if !sys.Initialized() {
		return r, errServerNotInitialized
	}

	if sys.usersSysType != MinIOUsersSysType {
		return nil, errIAMActionNotAllowed
	}

	sys.store.rlock()
	fallback := sys.storeFallback
	sys.store.runlock()

	if fallback {
		if err := sys.store.loadAll(context.Background(), sys); err != nil {
			return nil, err
		}
	}

	sys.store.rlock()
	defer sys.store.runlock()

	r = make([]string, 0, len(sys.iamGroupsMap))
	for k := range sys.iamGroupsMap {
		r = append(r, k)
	}

	return r, nil
}

// PolicyDBSet - sets a policy for a user or group in the PolicyDB.
func (sys *IAMSys) PolicyDBSet(name, policy string, isGroup bool) error {
	if !sys.Initialized() {
		return errServerNotInitialized
	}

	sys.store.lock()
	defer sys.store.unlock()

	return sys.policyDBSet(name, policy, regularUser, isGroup)
}

// policyDBSet - sets a policy for user in the policy db. Assumes that caller
// has sys.Lock(). If policy == "", then policy mapping is removed.
func (sys *IAMSys) policyDBSet(name, policyName string, userType IAMUserType, isGroup bool) error {
	if name == "" {
		return errInvalidArgument
	}

	if sys.usersSysType == MinIOUsersSysType {
		if !isGroup {
			if _, ok := sys.iamUsersMap[name]; !ok {
				return errNoSuchUser
			}
		} else {
			if _, ok := sys.iamGroupsMap[name]; !ok {
				return errNoSuchGroup
			}
		}
	}

	// Handle policy mapping removal
	if policyName == "" {
		if err := sys.store.deleteMappedPolicy(context.Background(), name, userType, isGroup); err != nil && err != errNoSuchPolicy {
			return err
		}
		if !isGroup {
			delete(sys.iamUserPolicyMap, name)
		} else {
			delete(sys.iamGroupPolicyMap, name)
		}
		return nil
	}

	mp := newMappedPolicy(policyName)
	for _, policy := range mp.toSlice() {
		if _, found := sys.iamPolicyDocsMap[policy]; !found {
			logger.LogIf(GlobalContext, fmt.Errorf("%w: (%s)", errNoSuchPolicy, policy))
			return errNoSuchPolicy
		}
	}

	// Handle policy mapping set/update
	if err := sys.store.saveMappedPolicy(context.Background(), name, userType, isGroup, mp); err != nil {
		return err
	}
	if !isGroup {
		sys.iamUserPolicyMap[name] = mp
	} else {
		sys.iamGroupPolicyMap[name] = mp
	}
	return nil
}

// PolicyDBGet - gets policy set on a user or group. Since a user may
// be a member of multiple groups, this function returns an array of
// applicable policies (each group is mapped to at most one policy).
func (sys *IAMSys) PolicyDBGet(name string, isGroup bool) ([]string, error) {
	if !sys.Initialized() {
		return nil, errServerNotInitialized
	}

	if name == "" {
		return nil, errInvalidArgument
	}

	sys.store.rlock()
	defer sys.store.runlock()

	return sys.policyDBGet(name, isGroup)
}

// This call assumes that caller has the sys.RLock()
func (sys *IAMSys) policyDBGet(name string, isGroup bool) ([]string, error) {
	if isGroup {
		if _, ok := sys.iamGroupsMap[name]; !ok {
			return nil, errNoSuchGroup
		}

		mp := sys.iamGroupPolicyMap[name]
		return mp.toSlice(), nil
	}

	// When looking for a user's policies, we also check if the
	// user and the groups they are member of are enabled.
	if u, ok := sys.iamUsersMap[name]; !ok {
		return nil, errNoSuchUser
	} else if u.Status == statusDisabled {
		// User is disabled, so we return no policy - this
		// ensures the request is denied.
		return nil, nil
	}

	var policies []string

	mp := sys.iamUserPolicyMap[name]
	// returned policy could be empty
	policies = append(policies, mp.toSlice()...)

	for _, group := range sys.iamUserGroupMemberships[name].ToSlice() {
		// Skip missing or disabled groups
		gi, ok := sys.iamGroupsMap[group]
		if !ok || gi.Status == statusDisabled {
			continue
		}

		p := sys.iamGroupPolicyMap[group]
		policies = append(policies, p.toSlice()...)
	}
	return policies, nil
}

// GetCombinedPolicy returns a combined policy combining all policies
func (sys *IAMSys) GetCombinedPolicy(policies ...string) iampolicy.Policy {
	// Policies were found, evaluate all of them.
	sys.store.rlock()
	defer sys.store.runlock()

	var availablePolicies []iampolicy.Policy
	for _, pname := range policies {
		p, found := sys.iamPolicyDocsMap[pname]
		if found {
			availablePolicies = append(availablePolicies, p)
		}
	}

	if len(availablePolicies) == 0 {
		return iampolicy.Policy{}
	}

	combinedPolicy := availablePolicies[0]
	for i := 1; i < len(availablePolicies); i++ {
		combinedPolicy.Statements = append(combinedPolicy.Statements,
			availablePolicies[i].Statements...)
	}

	return combinedPolicy
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (sys *IAMSys) IsAllowed(args iampolicy.Args) bool {
	return true
}

// Set default canned policies only if not already overridden by users.
func setDefaultCannedPolicies(policies map[string]iampolicy.Policy) {
	_, ok := policies["writeonly"]
	if !ok {
		policies["writeonly"] = iampolicy.WriteOnly
	}
	_, ok = policies["readonly"]
	if !ok {
		policies["readonly"] = iampolicy.ReadOnly
	}
	_, ok = policies["readwrite"]
	if !ok {
		policies["readwrite"] = iampolicy.ReadWrite
	}
	_, ok = policies["diagnostics"]
	if !ok {
		policies["diagnostics"] = iampolicy.AdminDiagnostics
	}
}

// buildUserGroupMemberships - builds the memberships map. IMPORTANT:
// Assumes that sys.Lock is held by caller.
func (sys *IAMSys) buildUserGroupMemberships() {
	for group, gi := range sys.iamGroupsMap {
		sys.updateGroupMembershipsMap(group, &gi)
	}
}

// updateGroupMembershipsMap - updates the memberships map for a
// group. IMPORTANT: Assumes sys.Lock() is held by caller.
func (sys *IAMSys) updateGroupMembershipsMap(group string, gi *GroupInfo) {
	if gi == nil {
		return
	}
	for _, member := range gi.Members {
		v := sys.iamUserGroupMemberships[member]
		if v == nil {
			v = set.CreateStringSet(group)
		} else {
			v.Add(group)
		}
		sys.iamUserGroupMemberships[member] = v
	}
}

// removeGroupFromMembershipsMap - removes the group from every member
// in the cache. IMPORTANT: Assumes sys.Lock() is held by caller.
func (sys *IAMSys) removeGroupFromMembershipsMap(group string) {
	for member, groups := range sys.iamUserGroupMemberships {
		if !groups.Contains(group) {
			continue
		}
		groups.Remove(group)
		sys.iamUserGroupMemberships[member] = groups
	}
}

// EnableLDAPSys - enable ldap system users type.
func (sys *IAMSys) EnableLDAPSys() {
	sys.usersSysType = LDAPUsersSysType
}

// NewIAMSys - creates new config system object.
func NewIAMSys() *IAMSys {
	return &IAMSys{
		usersSysType:            MinIOUsersSysType,
		iamUsersMap:             make(map[string]auth.Credentials),
		iamPolicyDocsMap:        make(map[string]iampolicy.Policy),
		iamUserPolicyMap:        make(map[string]MappedPolicy),
		iamGroupPolicyMap:       make(map[string]MappedPolicy),
		iamGroupsMap:            make(map[string]GroupInfo),
		iamUserGroupMemberships: make(map[string]set.StringSet),
		storeFallback:           true,
	}
}
