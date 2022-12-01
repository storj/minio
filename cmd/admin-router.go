/*
 * MinIO Cloud Storage, (C) 2016, 2017, 2018, 2019 MinIO, Inc.
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
	"net/http"

	"github.com/gorilla/mux"

	"storj.io/minio/pkg/madmin"
)

const (
	adminPathPrefix         = minioReservedBucketPath + "/admin"
	adminAPIVersionV2       = madmin.AdminAPIVersionV2
	adminAPIVersion         = madmin.AdminAPIVersion
	adminAPIVersionPrefix   = SlashSeparator + adminAPIVersion
	adminAPIVersionV2Prefix = SlashSeparator + adminAPIVersionV2
)

// adminAPIHandlers provides HTTP handlers for MinIO admin API.
type adminAPIHandlers struct{}

// registerAdminRouter - Add handler functions for each service REST API routes.
func registerAdminRouter(router *mux.Router, enableConfigOps, enableIAMOps bool) {

	adminAPI := adminAPIHandlers{}
	// Admin router
	adminRouter := router.PathPrefix(adminPathPrefix).Subrouter()

	/// Service operations

	adminVersions := []string{
		adminAPIVersionPrefix,
		adminAPIVersionV2Prefix,
	}

	for _, adminVersion := range adminVersions {
		// Restart and stop MinIO service.
		adminRouter.Methods(http.MethodPost).Path(adminVersion+"/service").HandlerFunc(HTTPTraceAll(adminAPI.ServiceHandler)).Queries("action", "{action:.*}")
		// Update MinIO servers.
		adminRouter.Methods(http.MethodPost).Path(adminVersion+"/update").HandlerFunc(HTTPTraceAll(adminAPI.ServerUpdateHandler)).Queries("updateURL", "{updateURL:.*}")

		// Info operations
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/info").HandlerFunc(HTTPTraceAll(adminAPI.ServerInfoHandler))

		// StorageInfo operations
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/storageinfo").HandlerFunc(HTTPTraceAll(adminAPI.StorageInfoHandler))
		// DataUsageInfo operations
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/datausageinfo").HandlerFunc(HTTPTraceAll(adminAPI.DataUsageInfoHandler))

		if globalIsDistErasure || globalIsErasure {
			/// Heal operations

			// Heal processing endpoint.
			adminRouter.Methods(http.MethodPost).Path(adminVersion + "/heal/").HandlerFunc(HTTPTraceAll(adminAPI.HealHandler))
			adminRouter.Methods(http.MethodPost).Path(adminVersion + "/heal/{bucket}").HandlerFunc(HTTPTraceAll(adminAPI.HealHandler))
			adminRouter.Methods(http.MethodPost).Path(adminVersion + "/heal/{bucket}/{prefix:.*}").HandlerFunc(HTTPTraceAll(adminAPI.HealHandler))

			adminRouter.Methods(http.MethodPost).Path(adminVersion + "/background-heal/status").HandlerFunc(HTTPTraceAll(adminAPI.BackgroundHealStatusHandler))

			/// Health operations

		}

		// Profiling operations
		adminRouter.Methods(http.MethodPost).Path(adminVersion+"/profiling/start").HandlerFunc(HTTPTraceAll(adminAPI.StartProfilingHandler)).
			Queries("profilerType", "{profilerType:.*}")
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/profiling/download").HandlerFunc(HTTPTraceAll(adminAPI.DownloadProfilingHandler))

		// Config KV operations.
		if enableConfigOps {
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/get-config-kv").HandlerFunc(HTTPTraceHdrs(adminAPI.GetConfigKVHandler)).Queries("key", "{key:.*}")
			adminRouter.Methods(http.MethodPut).Path(adminVersion + "/set-config-kv").HandlerFunc(HTTPTraceHdrs(adminAPI.SetConfigKVHandler))
			adminRouter.Methods(http.MethodDelete).Path(adminVersion + "/del-config-kv").HandlerFunc(HTTPTraceHdrs(adminAPI.DelConfigKVHandler))
		}

		// Enable config help in all modes.
		adminRouter.Methods(http.MethodGet).Path(adminVersion+"/help-config-kv").HandlerFunc(HTTPTraceAll(adminAPI.HelpConfigKVHandler)).Queries("subSys", "{subSys:.*}", "key", "{key:.*}")

		// Config KV history operations.
		if enableConfigOps {
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/list-config-history-kv").HandlerFunc(HTTPTraceAll(adminAPI.ListConfigHistoryKVHandler)).Queries("count", "{count:[0-9]+}")
			adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/clear-config-history-kv").HandlerFunc(HTTPTraceHdrs(adminAPI.ClearConfigHistoryKVHandler)).Queries("restoreId", "{restoreId:.*}")
			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/restore-config-history-kv").HandlerFunc(HTTPTraceHdrs(adminAPI.RestoreConfigHistoryKVHandler)).Queries("restoreId", "{restoreId:.*}")
		}

		/// Config import/export bulk operations
		if enableConfigOps {
			// Get config
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/config").HandlerFunc(HTTPTraceHdrs(adminAPI.GetConfigHandler))
			// Set config
			adminRouter.Methods(http.MethodPut).Path(adminVersion + "/config").HandlerFunc(HTTPTraceHdrs(adminAPI.SetConfigHandler))
		}

		if enableIAMOps {
			// -- IAM APIs --

			// Add policy IAM
			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/add-canned-policy").HandlerFunc(HTTPTraceAll(adminAPI.AddCannedPolicy)).Queries("name", "{name:.*}")

			// Add user IAM
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/accountinfo").HandlerFunc(HTTPTraceAll(adminAPI.AccountInfoHandler))

			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/add-user").HandlerFunc(HTTPTraceHdrs(adminAPI.AddUser)).Queries("accessKey", "{accessKey:.*}")

			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-user-status").HandlerFunc(HTTPTraceHdrs(adminAPI.SetUserStatus)).Queries("accessKey", "{accessKey:.*}").Queries("status", "{status:.*}")

			// Service accounts ops
			adminRouter.Methods(http.MethodPut).Path(adminVersion + "/add-service-account").HandlerFunc(HTTPTraceHdrs(adminAPI.AddServiceAccount))
			adminRouter.Methods(http.MethodPost).Path(adminVersion+"/update-service-account").HandlerFunc(HTTPTraceHdrs(adminAPI.UpdateServiceAccount)).Queries("accessKey", "{accessKey:.*}")
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/info-service-account").HandlerFunc(HTTPTraceHdrs(adminAPI.InfoServiceAccount)).Queries("accessKey", "{accessKey:.*}")
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-service-accounts").HandlerFunc(HTTPTraceHdrs(adminAPI.ListServiceAccounts))
			adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/delete-service-account").HandlerFunc(HTTPTraceHdrs(adminAPI.DeleteServiceAccount)).Queries("accessKey", "{accessKey:.*}")

			if adminVersion == adminAPIVersionV2Prefix {
				// Info policy IAM v2
				adminRouter.Methods(http.MethodGet).Path(adminVersion+"/info-canned-policy").HandlerFunc(HTTPTraceHdrs(adminAPI.InfoCannedPolicyV2)).Queries("name", "{name:.*}")

				// List policies v2
				adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-canned-policies").HandlerFunc(HTTPTraceHdrs(adminAPI.ListCannedPoliciesV2))
			} else {
				// Info policy IAM latest
				adminRouter.Methods(http.MethodGet).Path(adminVersion+"/info-canned-policy").HandlerFunc(HTTPTraceHdrs(adminAPI.InfoCannedPolicy)).Queries("name", "{name:.*}")

				// List policies latest
				adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-canned-policies").HandlerFunc(HTTPTraceHdrs(adminAPI.ListCannedPolicies))
			}

			// Remove policy IAM
			adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/remove-canned-policy").HandlerFunc(HTTPTraceHdrs(adminAPI.RemoveCannedPolicy)).Queries("name", "{name:.*}")

			// Set user or group policy
			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-user-or-group-policy").
				HandlerFunc(HTTPTraceHdrs(adminAPI.SetPolicyForUserOrGroup)).
				Queries("policyName", "{policyName:.*}", "userOrGroup", "{userOrGroup:.*}", "isGroup", "{isGroup:true|false}")

			// Remove user IAM
			adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/remove-user").HandlerFunc(HTTPTraceHdrs(adminAPI.RemoveUser)).Queries("accessKey", "{accessKey:.*}")

			// List users
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/list-users").HandlerFunc(HTTPTraceHdrs(adminAPI.ListUsers))

			// User info
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/user-info").HandlerFunc(HTTPTraceHdrs(adminAPI.GetUserInfo)).Queries("accessKey", "{accessKey:.*}")

			// Add/Remove members from group
			adminRouter.Methods(http.MethodPut).Path(adminVersion + "/update-group-members").HandlerFunc(HTTPTraceHdrs(adminAPI.UpdateGroupMembers))

			// Get Group
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/group").HandlerFunc(HTTPTraceHdrs(adminAPI.GetGroup)).Queries("group", "{group:.*}")

			// List Groups
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/groups").HandlerFunc(HTTPTraceHdrs(adminAPI.ListGroups))

			// Set Group Status
			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-group-status").HandlerFunc(HTTPTraceHdrs(adminAPI.SetGroupStatus)).Queries("group", "{group:.*}").Queries("status", "{status:.*}")
		}

		if globalIsDistErasure || globalIsErasure {
			// GetBucketQuotaConfig
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/get-bucket-quota").HandlerFunc(
				HTTPTraceHdrs(adminAPI.GetBucketQuotaConfigHandler)).Queries("bucket", "{bucket:.*}")
			// PutBucketQuotaConfig
			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-bucket-quota").HandlerFunc(
				HTTPTraceHdrs(adminAPI.PutBucketQuotaConfigHandler)).Queries("bucket", "{bucket:.*}")

			// Bucket replication operations
			// GetBucketTargetHandler
			adminRouter.Methods(http.MethodGet).Path(adminVersion+"/list-remote-targets").HandlerFunc(
				HTTPTraceHdrs(adminAPI.ListRemoteTargetsHandler)).Queries("bucket", "{bucket:.*}", "type", "{type:.*}")
			// SetRemoteTargetHandler
			adminRouter.Methods(http.MethodPut).Path(adminVersion+"/set-remote-target").HandlerFunc(
				HTTPTraceHdrs(adminAPI.SetRemoteTargetHandler)).Queries("bucket", "{bucket:.*}")
			// RemoveRemoteTargetHandler
			adminRouter.Methods(http.MethodDelete).Path(adminVersion+"/remove-remote-target").HandlerFunc(
				HTTPTraceHdrs(adminAPI.RemoveRemoteTargetHandler)).Queries("bucket", "{bucket:.*}", "arn", "{arn:.*}")
		}

		if globalIsDistErasure {
			// Top locks
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/top/locks").HandlerFunc(HTTPTraceHdrs(adminAPI.TopLocksHandler))
			// Force unlocks paths
			adminRouter.Methods(http.MethodPost).Path(adminVersion+"/force-unlock").
				Queries("paths", "{paths:.*}").HandlerFunc(HTTPTraceHdrs(adminAPI.ForceUnlockHandler))
		}

		// HTTP Trace
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/trace").HandlerFunc(adminAPI.TraceHandler)

		// Console Logs
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/log").HandlerFunc(HTTPTraceAll(adminAPI.ConsoleLogHandler))

		// -- KMS APIs --
		//
		adminRouter.Methods(http.MethodPost).Path(adminVersion+"/kms/key/create").HandlerFunc(HTTPTraceAll(adminAPI.KMSCreateKeyHandler)).Queries("key-id", "{key-id:.*}")
		adminRouter.Methods(http.MethodGet).Path(adminVersion + "/kms/key/status").HandlerFunc(HTTPTraceAll(adminAPI.KMSKeyStatusHandler))

		if !GlobalIsGateway {
			// Keep obdinfo for backward compatibility with mc
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/obdinfo").
				HandlerFunc(HTTPTraceHdrs(adminAPI.HealthInfoHandler))
			// -- Health API --
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/healthinfo").
				HandlerFunc(HTTPTraceHdrs(adminAPI.HealthInfoHandler))
			adminRouter.Methods(http.MethodGet).Path(adminVersion + "/bandwidth").
				HandlerFunc(HTTPTraceHdrs(adminAPI.BandwidthMonitorHandler))
		}
	}

	// If none of the routes match add default error handler routes
	adminRouter.NotFoundHandler = HTTPTraceAll(ErrorResponseHandler)
	adminRouter.MethodNotAllowedHandler = HTTPTraceAll(MethodNotAllowedHandler("Admin"))
}
