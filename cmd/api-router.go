/*
 * MinIO Cloud Storage, (C) 2016-2020 MinIO, Inc.
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
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	xhttp "storj.io/minio/cmd/http"
	"storj.io/minio/pkg/wildcard"
)

func newHTTPServerFn() *xhttp.Server {
	globalObjLayerMutex.RLock()
	defer globalObjLayerMutex.RUnlock()
	return globalHTTPServer
}

func setHTTPServer(h *xhttp.Server) {
	globalObjLayerMutex.Lock()
	globalHTTPServer = h
	globalObjLayerMutex.Unlock()
}

func newObjectLayerFn() ObjectLayer {
	globalObjLayerMutex.RLock()
	defer globalObjLayerMutex.RUnlock()
	return globalObjectAPI
}

func newCachedObjectLayerFn() CacheObjectLayer {
	globalObjLayerMutex.RLock()
	defer globalObjLayerMutex.RUnlock()
	return globalCacheObjectAPI
}

func setCacheObjectLayer(c CacheObjectLayer) {
	globalObjLayerMutex.Lock()
	globalCacheObjectAPI = c
	globalObjLayerMutex.Unlock()
}

func SetObjectLayer(o ObjectLayer) {
	globalObjLayerMutex.Lock()
	globalObjectAPI = o
	globalObjLayerMutex.Unlock()
}

// ObjectAPIHandler implements and provides http handlers for S3 API.
type ObjectAPIHandlers struct {
	ObjectAPI func() ObjectLayer
	CacheAPI  func() CacheObjectLayer
}

// getHost tries its best to return the request host.
// According to section 14.23 of RFC 2616 the Host header
// can include the port number if the default value of 80 is not used.
func getHost(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.Host
	}
	return r.Host
}

func notImplementedHandler(w http.ResponseWriter, r *http.Request) {
	WriteErrorResponse(r.Context(), w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
}

type rejectedAPI struct {
	api     string
	methods []string
	queries []string
	path    string
}

var rejectedAPIs = []rejectedAPI{
	{
		api:     "inventory",
		methods: []string{http.MethodGet, http.MethodPut, http.MethodDelete},
		queries: []string{"inventory", ""},
	},
	{
		api:     "cors",
		methods: []string{http.MethodPut, http.MethodDelete},
		queries: []string{"cors", ""},
	},
	{
		api:     "metrics",
		methods: []string{http.MethodGet, http.MethodPut, http.MethodDelete},
		queries: []string{"metrics", ""},
	},
	{
		api:     "website",
		methods: []string{http.MethodPut},
		queries: []string{"website", ""},
	},
	{
		api:     "logging",
		methods: []string{http.MethodPut, http.MethodDelete},
		queries: []string{"logging", ""},
	},
	{
		api:     "accelerate",
		methods: []string{http.MethodPut, http.MethodDelete},
		queries: []string{"accelerate", ""},
	},
	{
		api:     "requestPayment",
		methods: []string{http.MethodPut, http.MethodDelete},
		queries: []string{"requestPayment", ""},
	},
	{
		api:     "torrent",
		methods: []string{http.MethodPut, http.MethodDelete, http.MethodGet},
		queries: []string{"torrent", ""},
		path:    "/{object:.+}",
	},
	{
		api:     "acl",
		methods: []string{http.MethodDelete},
		queries: []string{"acl", ""},
		path:    "/{object:.+}",
	},
	{
		api:     "acl",
		methods: []string{http.MethodDelete, http.MethodPut, http.MethodHead},
		queries: []string{"acl", ""},
	},
	{
		api:     "publicAccessBlock",
		methods: []string{http.MethodDelete, http.MethodPut, http.MethodGet},
		queries: []string{"publicAccessBlock", ""},
	},
	{
		api:     "ownershipControls",
		methods: []string{http.MethodDelete, http.MethodPut, http.MethodGet},
		queries: []string{"ownershipControls", ""},
	},
	{
		api:     "intelligent-tiering",
		methods: []string{http.MethodDelete, http.MethodPut, http.MethodGet},
		queries: []string{"intelligent-tiering", ""},
	},
	{
		api:     "analytics",
		methods: []string{http.MethodDelete, http.MethodPut, http.MethodGet},
		queries: []string{"analytics", ""},
	},
}

func rejectUnsupportedAPIs(router *mux.Router) {
	for _, r := range rejectedAPIs {
		t := router.Methods(r.methods...).
			HandlerFunc(CollectAPIStats(r.api, HTTPTraceAll(notImplementedHandler))).
			Queries(r.queries...)
		if r.path != "" {
			t.Path(r.path)
		}
	}
}

// registerAPIRouter - registers S3 compatible APIs.
func registerAPIRouter(router *mux.Router) {
	// Initialize API.
	api := ObjectAPIHandlers{
		ObjectAPI: newObjectLayerFn,
		CacheAPI:  newCachedObjectLayerFn,
	}

	// API Router
	apiRouter := router.PathPrefix(SlashSeparator).Subrouter()

	var routers []*mux.Router
	for _, domainName := range globalDomainNames {
		if IsKubernetes() {
			routers = append(routers, apiRouter.MatcherFunc(func(r *http.Request, match *mux.RouteMatch) bool {
				host, _, err := net.SplitHostPort(getHost(r))
				if err != nil {
					host = r.Host
				}
				// Make sure to skip matching minio.<domain>` this is
				// specifically meant for operator/k8s deployment
				// The reason we need to skip this is for a special
				// usecase where we need to make sure that
				// minio.<namespace>.svc.<cluster_domain> is ignored
				// by the bucketDNS style to ensure that path style
				// is available and honored at this domain.
				//
				// All other `<bucket>.<namespace>.svc.<cluster_domain>`
				// makes sure that buckets are routed through this matcher
				// to match for `<bucket>`
				return host != minioReservedBucket+"."+domainName
			}).Host("{bucket:.+}."+domainName).Subrouter())
		} else {
			routers = append(routers, apiRouter.Host("{bucket:.+}."+domainName).Subrouter())
		}
	}
	routers = append(routers, apiRouter.PathPrefix("/{bucket}").Subrouter())

	for _, router := range routers {
		rejectUnsupportedAPIs(router)
		// Object operations
		// HeadObject
		router.Methods(http.MethodHead).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("headobject", MaxClients(HTTPTraceAll(api.HeadObjectHandler))))
		// GetObjectAttributes
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("getobjectattributes", MaxClients(HTTPTraceAll(api.GetObjectAttributesHandler)))).Queries("attributes", "")
		// CopyObjectPart
		router.Methods(http.MethodPut).Path("/{object:.+}").
			HeadersRegexp(xhttp.AmzCopySource, ".*?(\\/|%2F).*?").
			HandlerFunc(CollectAPIStats("copyobjectpart", MaxClients(HTTPTraceAll(api.CopyObjectPartHandler)))).
			Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// PutObjectPart
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("putobjectpart", MaxClients(HTTPTraceHdrs(api.PutObjectPartHandler)))).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// ListObjectParts
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("listobjectparts", MaxClients(HTTPTraceAll(api.ListObjectPartsHandler)))).Queries("uploadId", "{uploadId:.*}")
		// CompleteMultipartUpload
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("completemutipartupload", MaxClients(HTTPTraceAll(api.CompleteMultipartUploadHandler)))).Queries("uploadId", "{uploadId:.*}")
		// NewMultipartUpload
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("newmultipartupload", MaxClients(HTTPTraceAll(api.NewMultipartUploadHandler)))).Queries("uploads", "")
		// AbortMultipartUpload
		router.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("abortmultipartupload", MaxClients(HTTPTraceAll(api.AbortMultipartUploadHandler)))).Queries("uploadId", "{uploadId:.*}")
		// GetObjectACL - this is a dummy call.
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("getobjectacl", MaxClients(HTTPTraceHdrs(api.GetObjectACLHandler)))).Queries("acl", "")
		// PutObjectACL - this is a dummy call.
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("putobjectacl", MaxClients(HTTPTraceHdrs(api.PutObjectACLHandler)))).Queries("acl", "")
		// GetObjectTagging
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("getobjecttagging", MaxClients(HTTPTraceHdrs(api.GetObjectTaggingHandler)))).Queries("tagging", "")
		// PutObjectTagging
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("putobjecttagging", MaxClients(HTTPTraceHdrs(api.PutObjectTaggingHandler)))).Queries("tagging", "")
		// DeleteObjectTagging
		router.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("deleteobjecttagging", MaxClients(HTTPTraceHdrs(api.DeleteObjectTaggingHandler)))).Queries("tagging", "")
		// SelectObjectContent
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("selectobjectcontent", MaxClients(HTTPTraceHdrs(api.SelectObjectContentHandler)))).Queries("select", "").Queries("select-type", "2")
		// GetObjectRetention
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("getobjectretention", MaxClients(HTTPTraceAll(api.GetObjectRetentionHandler)))).Queries("retention", "")
		// GetObjectLegalHold
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("getobjectlegalhold", MaxClients(HTTPTraceAll(api.GetObjectLegalHoldHandler)))).Queries("legal-hold", "")
		// GetObject
		router.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("getobject", MaxClients(HTTPTraceHdrs(api.GetObjectHandler))))
		// CopyObject
		router.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(xhttp.AmzCopySource, ".*?(\\/|%2F).*?").HandlerFunc(
			CollectAPIStats("copyobject", MaxClients(HTTPTraceAll(api.CopyObjectHandler))))
		// PutObjectRetention
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("putobjectretention", MaxClients(HTTPTraceAll(api.PutObjectRetentionHandler)))).Queries("retention", "")
		// PutObjectLegalHold
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("putobjectlegalhold", MaxClients(HTTPTraceAll(api.PutObjectLegalHoldHandler)))).Queries("legal-hold", "")

		// PutObject with auto-extract support for zip
		router.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(xhttp.AmzSnowballExtract, "true").HandlerFunc(
			CollectAPIStats("putobject", MaxClients(HTTPTraceHdrs(api.PutObjectExtractHandler))))

		// PutObject
		router.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("putobject", MaxClients(HTTPTraceHdrs(api.PutObjectHandler))))

		// DeleteObject
		router.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("deleteobject", MaxClients(HTTPTraceAll(api.DeleteObjectHandler))))

		// PostRestoreObject
		router.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
			CollectAPIStats("restoreobject", MaxClients(HTTPTraceAll(api.PostRestoreObjectHandler)))).Queries("restore", "")

		/// Bucket operations
		// GetBucketLocation
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketlocation", MaxClients(HTTPTraceAll(api.GetBucketLocationHandler)))).Queries("location", "")
		// GetBucketPolicy
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketpolicy", MaxClients(HTTPTraceAll(api.GetBucketPolicyHandler)))).Queries("policy", "")
		// GetBucketLifecycle
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketlifecycle", MaxClients(HTTPTraceAll(api.GetBucketLifecycleHandler)))).Queries("lifecycle", "")
		// GetBucketEncryption
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketencryption", MaxClients(HTTPTraceAll(api.GetBucketEncryptionHandler)))).Queries("encryption", "")
		// GetBucketObjectLockConfig
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketobjectlockconfiguration", MaxClients(HTTPTraceAll(api.GetBucketObjectLockConfigHandler)))).Queries("object-lock", "")
		// GetBucketReplicationConfig
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketreplicationconfiguration", MaxClients(HTTPTraceAll(api.GetBucketReplicationConfigHandler)))).Queries("replication", "")
		// GetBucketVersioning
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketversioning", MaxClients(HTTPTraceAll(api.GetBucketVersioningHandler)))).Queries("versioning", "")
		// GetBucketNotification
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketnotification", MaxClients(HTTPTraceAll(api.GetBucketNotificationHandler)))).Queries("notification", "")
		// ListenNotification
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("listennotification", MaxClients(HTTPTraceAll(api.ListenNotificationHandler)))).Queries("events", "{events:.*}")

		// Dummy Bucket Calls
		// GetBucketACL -- this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketacl", MaxClients(HTTPTraceAll(api.GetBucketACLHandler)))).Queries("acl", "")
		// PutBucketACL -- this is a dummy call.
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketacl", MaxClients(HTTPTraceAll(api.PutBucketACLHandler)))).Queries("acl", "")
		// GetBucketCors - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketcors", MaxClients(HTTPTraceAll(api.GetBucketCorsHandler)))).Queries("cors", "")
		// GetBucketWebsiteHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketwebsite", MaxClients(HTTPTraceAll(api.GetBucketWebsiteHandler)))).Queries("website", "")
		// GetBucketAccelerateHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketaccelerate", MaxClients(HTTPTraceAll(api.GetBucketAccelerateHandler)))).Queries("accelerate", "")
		// GetBucketRequestPaymentHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketrequestpayment", MaxClients(HTTPTraceAll(api.GetBucketRequestPaymentHandler)))).Queries("requestPayment", "")
		// GetBucketLoggingHandler - this is a dummy call.
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketlogging", MaxClients(HTTPTraceAll(api.GetBucketLoggingHandler)))).Queries("logging", "")
		// GetBucketTaggingHandler
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbuckettagging", MaxClients(HTTPTraceAll(api.GetBucketTaggingHandler)))).Queries("tagging", "")
		//DeleteBucketWebsiteHandler
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebucketwebsite", MaxClients(HTTPTraceAll(api.DeleteBucketWebsiteHandler)))).Queries("website", "")
		// DeleteBucketTaggingHandler
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebuckettagging", MaxClients(HTTPTraceAll(api.DeleteBucketTaggingHandler)))).Queries("tagging", "")

		// ListMultipartUploads
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("listmultipartuploads", MaxClients(HTTPTraceAll(api.ListMultipartUploadsHandler)))).Queries("uploads", "")
		// ListObjectsV2M
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("listobjectsv2M", MaxClients(HTTPTraceAll(api.ListObjectsV2MHandler)))).Queries("list-type", "2", "metadata", "true")
		// ListObjectsV2
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("listobjectsv2", MaxClients(HTTPTraceAll(api.ListObjectsV2Handler)))).Queries("list-type", "2")
		// ListObjectVersions
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("listobjectversions", MaxClients(HTTPTraceAll(api.ListObjectVersionsHandler)))).Queries("versions", "")
		// GetBucketPolicyStatus
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getpolicystatus", MaxClients(HTTPTraceAll(api.GetBucketPolicyStatusHandler)))).Queries("policyStatus", "")
		// PutBucketLifecycle
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketlifecycle", MaxClients(HTTPTraceAll(api.PutBucketLifecycleHandler)))).Queries("lifecycle", "")
		// PutBucketReplicationConfig
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketreplicationconfiguration", MaxClients(HTTPTraceAll(api.PutBucketReplicationConfigHandler)))).Queries("replication", "")
		// PutBucketEncryption
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketencryption", MaxClients(HTTPTraceAll(api.PutBucketEncryptionHandler)))).Queries("encryption", "")

		// PutBucketPolicy
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketpolicy", MaxClients(HTTPTraceAll(api.PutBucketPolicyHandler)))).Queries("policy", "")

		// PutBucketObjectLockConfig
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketobjectlockconfig", MaxClients(HTTPTraceAll(api.PutBucketObjectLockConfigHandler)))).Queries("object-lock", "")
		// PutBucketTaggingHandler
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbuckettagging", MaxClients(HTTPTraceAll(api.PutBucketTaggingHandler)))).Queries("tagging", "")
		// PutBucketVersioning
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketversioning", MaxClients(HTTPTraceAll(api.PutBucketVersioningHandler)))).Queries("versioning", "")
		// PutBucketNotification
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucketnotification", MaxClients(HTTPTraceAll(api.PutBucketNotificationHandler)))).Queries("notification", "")
		// PutBucket
		router.Methods(http.MethodPut).HandlerFunc(
			CollectAPIStats("putbucket", MaxClients(HTTPTraceAll(api.PutBucketHandler))))
		// HeadBucket
		router.Methods(http.MethodHead).HandlerFunc(
			CollectAPIStats("headbucket", MaxClients(HTTPTraceAll(api.HeadBucketHandler))))
		// PostPolicy
		router.Methods(http.MethodPost).HeadersRegexp(xhttp.ContentType, "multipart/form-data*").HandlerFunc(
			CollectAPIStats("postpolicybucket", MaxClients(HTTPTraceHdrs(api.PostPolicyBucketHandler))))
		// DeleteMultipleObjects
		router.Methods(http.MethodPost).HandlerFunc(
			CollectAPIStats("deletemultipleobjects", MaxClients(HTTPTraceAll(api.DeleteMultipleObjectsHandler)))).Queries("delete", "")
		// DeleteBucketPolicy
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebucketpolicy", MaxClients(HTTPTraceAll(api.DeleteBucketPolicyHandler)))).Queries("policy", "")
		// DeleteBucketReplication
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebucketreplicationconfiguration", MaxClients(HTTPTraceAll(api.DeleteBucketReplicationConfigHandler)))).Queries("replication", "")
		// DeleteBucketLifecycle
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebucketlifecycle", MaxClients(HTTPTraceAll(api.DeleteBucketLifecycleHandler)))).Queries("lifecycle", "")
		// DeleteBucketEncryption
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebucketencryption", MaxClients(HTTPTraceAll(api.DeleteBucketEncryptionHandler)))).Queries("encryption", "")
		// DeleteBucket
		router.Methods(http.MethodDelete).HandlerFunc(
			CollectAPIStats("deletebucket", MaxClients(HTTPTraceAll(api.DeleteBucketHandler))))
		// MinIO extension API for replication.
		//
		// GetBucketReplicationMetrics
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("getbucketreplicationmetrics", MaxClients(HTTPTraceAll(api.GetBucketReplicationMetricsHandler)))).Queries("replication-metrics", "")

		// S3 ListObjectsV1 (Legacy)
		router.Methods(http.MethodGet).HandlerFunc(
			CollectAPIStats("listobjectsv1", MaxClients(HTTPTraceAll(api.ListObjectsV1Handler))))

	}

	/// Root operation

	// ListenNotification
	apiRouter.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
		CollectAPIStats("listennotification", MaxClients(HTTPTraceAll(api.ListenNotificationHandler)))).Queries("events", "{events:.*}")

	// ListBuckets
	apiRouter.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
		CollectAPIStats("listbuckets", MaxClients(HTTPTraceAll(api.ListBucketsHandler))))

	// S3 browser with signature v4 adds '//' for ListBuckets request, so rather
	// than failing with UnknownAPIRequest we simply handle it for now.
	apiRouter.Methods(http.MethodGet).Path(SlashSeparator + SlashSeparator).HandlerFunc(
		CollectAPIStats("listbuckets", MaxClients(HTTPTraceAll(api.ListBucketsHandler))))

	// If none of the routes match add default error handler routes
	apiRouter.NotFoundHandler = CollectAPIStats("notfound", HTTPTraceAll(ErrorResponseHandler))
	apiRouter.MethodNotAllowedHandler = CollectAPIStats("methodnotallowed", HTTPTraceAll(MethodNotAllowedHandler("S3")))

}

// corsHandler handler for CORS (Cross Origin Resource Sharing)
func corsHandler(handler http.Handler) http.Handler {
	commonS3Headers := []string{
		xhttp.Date,
		xhttp.ETag,
		xhttp.ServerInfo,
		xhttp.Connection,
		xhttp.AcceptRanges,
		xhttp.ContentRange,
		xhttp.ContentEncoding,
		xhttp.ContentLength,
		xhttp.ContentType,
		xhttp.ContentDisposition,
		xhttp.LastModified,
		xhttp.ContentLanguage,
		xhttp.CacheControl,
		xhttp.RetryAfter,
		xhttp.AmzBucketRegion,
		xhttp.Expires,
		"X-Amz*",
		"x-amz*",
		"*",
	}

	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			for _, allowedOrigin := range globalAPIConfig.getCorsAllowOrigins() {
				if wildcard.MatchSimple(allowedOrigin, origin) {
					return true
				}
			}
			return false
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPut,
			http.MethodHead,
			http.MethodPost,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodPatch,
		},
		AllowedHeaders:   commonS3Headers,
		ExposedHeaders:   commonS3Headers,
		AllowCredentials: true,
	}).Handler(handler)
}
