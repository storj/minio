/*
 * MinIO Cloud Storage, (C) 2015-2020 MinIO, Inc.
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
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/gorilla/mux"
	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/storj/minio/cmd/config/storageclass"
	"github.com/storj/minio/cmd/crypto"
	xhttp "github.com/storj/minio/cmd/http"
	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/bucket/lifecycle"
	objectlock "github.com/storj/minio/pkg/bucket/object/lock"
	"github.com/storj/minio/pkg/bucket/policy"
	"github.com/storj/minio/pkg/event"
	"github.com/storj/minio/pkg/handlers"
	"github.com/storj/minio/pkg/hash"
	iampolicy "github.com/storj/minio/pkg/iam/policy"
	"github.com/storj/minio/pkg/ioutil"
	"github.com/storj/minio/pkg/s3select"
)

// supportedHeadGetReqParams - supported request parameters for GET and HEAD presigned request.
var supportedHeadGetReqParams = map[string]string{
	"response-expires":             xhttp.Expires,
	"response-content-type":        xhttp.ContentType,
	"response-cache-control":       xhttp.CacheControl,
	"response-content-encoding":    xhttp.ContentEncoding,
	"response-content-language":    xhttp.ContentLanguage,
	"response-content-disposition": xhttp.ContentDisposition,
}

const (
	compressionAlgorithmV1 = "golang/snappy/LZ77"
	compressionAlgorithmV2 = "klauspost/compress/s2"

	// When an upload exceeds encryptBufferThreshold ...
	encryptBufferThreshold = 1 << 20
	// add an input buffer of this size.
	encryptBufferSize = 1 << 20
)

// setHeadGetRespHeaders - set any requested parameters as response headers.
func setHeadGetRespHeaders(w http.ResponseWriter, reqParams url.Values) {
	for k, v := range reqParams {
		if header, ok := supportedHeadGetReqParams[strings.ToLower(k)]; ok {
			w.Header()[header] = v
		}
	}
}

// SelectObjectContentHandler - GET Object?select
// ----------
// This implementation of the GET operation retrieves object content based
// on an SQL expression. In the request, along with the sql expression, you must
// also specify a data serialization format (JSON, CSV) of the object.
func (api objectAPIHandlers) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "SelectObject")

	defer logger.AuditLog(w, r, "SelectObject", mustGetClaimsFromToken(r))

	// Fetch object stat info.
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if crypto.S3.IsRequested(r.Header) || crypto.S3KMS.IsRequested(r.Header) { // If SSE-S3 or SSE-KMS present -> AWS fails with undefined error
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL)
		return
	}

	if !objectAPI.IsEncryptionSupported() && crypto.IsRequested(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL)
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// get gateway encryption options
	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo

	// Check for auth type to return S3 compatible error.
	// type to return the correct error (NoSuchKey vs AccessDenied)
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, bucket, object); s3Error != ErrNone {
		if getRequestAuthType(r) == authTypeAnonymous {
			// As per "Permission" section in
			// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
			// If the object you request does not exist,
			// the error Amazon S3 returns depends on
			// whether you also have the s3:ListBucket
			// permission.
			// * If you have the s3:ListBucket permission
			//   on the bucket, Amazon S3 will return an
			//   HTTP status code 404 ("no such key")
			//   error.
			// * if you don’t have the s3:ListBucket
			//   permission, Amazon S3 will return an HTTP
			//   status code 403 ("access denied") error.`
			if globalPolicySys.IsAllowed(policy.Args{
				Action:          policy.ListBucketAction,
				BucketName:      bucket,
				ConditionValues: getConditionValues(r, "", "", nil),
				IsOwner:         false,
			}) {
				_, err = getObjectInfo(ctx, bucket, object, opts)
				if toAPIError(ctx, err).Code == "NoSuchKey" {
					s3Error = ErrNoSuchKey
				}
			}
		}
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// Get request range.
	rangeHeader := r.Header.Get(xhttp.Range)
	if rangeHeader != "" {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrUnsupportedRangeHeader), r.URL)
		return
	}

	if r.ContentLength <= 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEmptyRequestBody), r.URL)
		return
	}

	getObjectNInfo := objectAPI.GetObjectNInfo

	getObject := func(offset, length int64) (rc io.ReadCloser, err error) {
		isSuffixLength := false
		if offset < 0 {
			isSuffixLength = true
		}

		rs := &HTTPRangeSpec{
			IsSuffixLength: isSuffixLength,
			Start:          offset,
			End:            offset + length,
		}

		return getObjectNInfo(ctx, bucket, object, rs, r.Header, readLock, opts)
	}

	objInfo, err := getObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		if globalBucketVersioningSys.Enabled(bucket) {
			// Versioning enabled quite possibly object is deleted might be delete-marker
			// if present set the headers, no idea why AWS S3 sets these headers.
			if objInfo.VersionID != "" && objInfo.DeleteMarker {
				w.Header()[xhttp.AmzVersionID] = []string{objInfo.VersionID}
				w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(objInfo.DeleteMarker)}
			}
		}
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// filter object lock metadata if permission does not permit
	getRetPerms := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object)
	legalHoldPerms := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object)

	// filter object lock metadata if permission does not permit
	objInfo.UserDefined = objectlock.FilterObjectLockMetadata(objInfo.UserDefined, getRetPerms != ErrNone, legalHoldPerms != ErrNone)

	s3Select, err := s3select.NewS3Select(r.Body)
	if err != nil {
		if serr, ok := err.(s3select.SelectError); ok {
			encodedErrorResponse := encodeResponse(APIErrorResponse{
				Code:       serr.ErrorCode(),
				Message:    serr.ErrorMessage(),
				BucketName: bucket,
				Key:        object,
				Resource:   r.URL.Path,
				RequestID:  w.Header().Get(xhttp.AmzRequestID),
				HostID:     globalDeploymentID,
			})
			writeResponse(w, serr.HTTPStatusCode(), encodedErrorResponse, mimeXML)
		} else {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		}
		return
	}

	if err = s3Select.Open(getObject); err != nil {
		if serr, ok := err.(s3select.SelectError); ok {
			encodedErrorResponse := encodeResponse(APIErrorResponse{
				Code:       serr.ErrorCode(),
				Message:    serr.ErrorMessage(),
				BucketName: bucket,
				Key:        object,
				Resource:   r.URL.Path,
				RequestID:  w.Header().Get(xhttp.AmzRequestID),
				HostID:     globalDeploymentID,
			})
			writeResponse(w, serr.HTTPStatusCode(), encodedErrorResponse, mimeXML)
		} else {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		}
		return
	}

	// Set encryption response headers
	if objectAPI.IsEncryptionSupported() {
		if crypto.IsEncrypted(objInfo.UserDefined) {
			switch {
			case crypto.S3.IsEncrypted(objInfo.UserDefined):
				w.Header().Set(crypto.SSEHeader, crypto.SSEAlgorithmAES256)
			case crypto.SSEC.IsEncrypted(objInfo.UserDefined):
				// Validate the SSE-C Key set in the header.
				if _, err = crypto.SSEC.UnsealObjectKey(r.Header, objInfo.UserDefined, bucket, object); err != nil {
					writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
					return
				}
				w.Header().Set(crypto.SSECAlgorithm, r.Header.Get(crypto.SSECAlgorithm))
				w.Header().Set(crypto.SSECKeyMD5, r.Header.Get(crypto.SSECKeyMD5))
			}
		}
	}

	s3Select.Evaluate(w)
	s3Select.Close()

	// Notify object accessed via a GET request.
	sendEvent(eventArgs{
		EventName:    event.ObjectAccessedGet,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

// GetObjectHandler - GET Object
// ----------
// This implementation of the GET operation retrieves object. To use GET,
// you must have READ access to the object.
func (api objectAPIHandlers) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetObject")

	defer logger.AuditLog(w, r, "GetObject", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}
	if crypto.S3.IsRequested(r.Header) || crypto.S3KMS.IsRequested(r.Header) { // If SSE-S3 or SSE-KMS present -> AWS fails with undefined error
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL)
		return
	}
	if !objectAPI.IsEncryptionSupported() && crypto.IsRequested(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL)
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// get gateway encryption options
	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Check for auth type to return S3 compatible error.
	// type to return the correct error (NoSuchKey vs AccessDenied)
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, bucket, object); s3Error != ErrNone {
		if getRequestAuthType(r) == authTypeAnonymous {
			// As per "Permission" section in
			// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
			// If the object you request does not exist,
			// the error Amazon S3 returns depends on
			// whether you also have the s3:ListBucket
			// permission.
			// * If you have the s3:ListBucket permission
			//   on the bucket, Amazon S3 will return an
			//   HTTP status code 404 ("no such key")
			//   error.
			// * if you don’t have the s3:ListBucket
			//   permission, Amazon S3 will return an HTTP
			//   status code 403 ("access denied") error.`
			if globalPolicySys.IsAllowed(policy.Args{
				Action:          policy.ListBucketAction,
				BucketName:      bucket,
				ConditionValues: getConditionValues(r, "", "", nil),
				IsOwner:         false,
			}) {
				getObjectInfo := objectAPI.GetObjectInfo

				_, err = getObjectInfo(ctx, bucket, object, opts)
				if toAPIError(ctx, err).Code == "NoSuchKey" {
					s3Error = ErrNoSuchKey
				}
			}
		}
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	getObjectNInfo := objectAPI.GetObjectNInfo

	// Get request range.
	var rs *HTTPRangeSpec
	var rangeErr error
	rangeHeader := r.Header.Get(xhttp.Range)
	if rangeHeader != "" {
		rs, rangeErr = parseRequestRangeSpec(rangeHeader)
		// Handle only errInvalidRange. Ignore other
		// parse error and treat it as regular Get
		// request like Amazon S3.
		if rangeErr == errInvalidRange {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRange), r.URL)
			return
		}
		if rangeErr != nil {
			logger.LogIf(ctx, rangeErr, logger.Application)
		}
	}

	// Both 'bytes' and 'partNumber' cannot be specified at the same time
	if rs != nil && opts.PartNumber > 0 {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrBadRequest))
		return
	}

	// Validate pre-conditions if any.
	opts.CheckPrecondFn = func(oi ObjectInfo) bool {
		if checkPreconditions(ctx, w, r, oi, opts) {
			return true
		}

		return false
	}

	gr, err := getObjectNInfo(ctx, bucket, object, rs, r.Header, readLock, opts)
	if err != nil {
		if isErrPreconditionFailed(err) {
			return
		}
		if globalBucketVersioningSys.Enabled(bucket) && gr != nil {
			// Versioning enabled quite possibly object is deleted might be delete-marker
			// if present set the headers, no idea why AWS S3 sets these headers.
			if gr.ObjInfo.VersionID != "" && gr.ObjInfo.DeleteMarker {
				w.Header()[xhttp.AmzVersionID] = []string{gr.ObjInfo.VersionID}
				w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(gr.ObjInfo.DeleteMarker)}
			}
		}
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	defer gr.Close()
	objInfo := gr.ObjInfo

	// filter object lock metadata if permission does not permit
	getRetPerms := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object)
	legalHoldPerms := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object)

	// filter object lock metadata if permission does not permit
	objInfo.UserDefined = objectlock.FilterObjectLockMetadata(objInfo.UserDefined, getRetPerms != ErrNone, legalHoldPerms != ErrNone)

	// Set encryption response headers
	if objectAPI.IsEncryptionSupported() {
		if crypto.IsEncrypted(objInfo.UserDefined) {
			switch {
			case crypto.S3.IsEncrypted(objInfo.UserDefined):
				w.Header().Set(crypto.SSEHeader, crypto.SSEAlgorithmAES256)
			case crypto.SSEC.IsEncrypted(objInfo.UserDefined):
				w.Header().Set(crypto.SSECAlgorithm, r.Header.Get(crypto.SSECAlgorithm))
				w.Header().Set(crypto.SSECKeyMD5, r.Header.Get(crypto.SSECKeyMD5))
			}
		}
	}

	if err = setObjectHeaders(w, objInfo, rs, opts); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Set Parts Count Header
	if opts.PartNumber > 0 && len(objInfo.Parts) > 0 {
		setPartsCountHeaders(w, objInfo)
	}

	setHeadGetRespHeaders(w, r.URL.Query())

	statusCodeWritten := false
	httpWriter := ioutil.WriteOnClose(w)
	if rs != nil || opts.PartNumber > 0 {
		statusCodeWritten = true
		w.WriteHeader(http.StatusPartialContent)
	}

	// Write object content to response body
	if _, err = io.Copy(httpWriter, gr); err != nil {
		if !httpWriter.HasWritten() && !statusCodeWritten {
			// write error response only if no data or headers has been written to client yet
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		}
		return
	}

	if err = httpWriter.Close(); err != nil {
		if !httpWriter.HasWritten() && !statusCodeWritten { // write error response only if no data or headers has been written to client yet
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
	}

	// Notify object accessed via a GET request.
	sendEvent(eventArgs{
		EventName:    event.ObjectAccessedGet,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

// HeadObjectHandler - HEAD Object
// -----------
// The HEAD operation retrieves metadata from an object without returning the object itself.
func (api objectAPIHandlers) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "HeadObject")

	defer logger.AuditLog(w, r, "HeadObject", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}
	if crypto.S3.IsRequested(r.Header) || crypto.S3KMS.IsRequested(r.Header) { // If SSE-S3 or SSE-KMS present -> AWS fails with undefined error
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrBadRequest))
		return
	}
	if !objectAPI.IsEncryptionSupported() && crypto.IsRequested(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL)
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, bucket, object); s3Error != ErrNone {
		if getRequestAuthType(r) == authTypeAnonymous {
			// As per "Permission" section in
			// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectHEAD.html
			// If the object you request does not exist,
			// the error Amazon S3 returns depends on
			// whether you also have the s3:ListBucket
			// permission.
			// * If you have the s3:ListBucket permission
			//   on the bucket, Amazon S3 will return an
			//   HTTP status code 404 ("no such key")
			//   error.
			// * if you don’t have the s3:ListBucket
			//   permission, Amazon S3 will return an HTTP
			//   status code 403 ("access denied") error.`
			if globalPolicySys.IsAllowed(policy.Args{
				Action:          policy.ListBucketAction,
				BucketName:      bucket,
				ConditionValues: getConditionValues(r, "", "", nil),
				IsOwner:         false,
			}) {
				_, err = getObjectInfo(ctx, bucket, object, opts)
				if toAPIError(ctx, err).Code == "NoSuchKey" {
					s3Error = ErrNoSuchKey
				}
			}
		}
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(s3Error))
		return
	}

	objInfo, err := getObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		if globalBucketVersioningSys.Enabled(bucket) {
			if !objInfo.VersionPurgeStatus.Empty() {
				// Shows the replication status of a permanent delete of a version
				w.Header()[xhttp.MinIODeleteReplicationStatus] = []string{string(objInfo.VersionPurgeStatus)}
			}
			if !objInfo.ReplicationStatus.Empty() && objInfo.DeleteMarker {
				w.Header()[xhttp.MinIODeleteMarkerReplicationStatus] = []string{string(objInfo.ReplicationStatus)}
			}
			// Versioning enabled quite possibly object is deleted might be delete-marker
			// if present set the headers, no idea why AWS S3 sets these headers.
			if objInfo.VersionID != "" && objInfo.DeleteMarker {
				w.Header()[xhttp.AmzVersionID] = []string{objInfo.VersionID}
				w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(objInfo.DeleteMarker)}
			}
		}
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}

	// filter object lock metadata if permission does not permit
	getRetPerms := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object)
	legalHoldPerms := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object)

	// filter object lock metadata if permission does not permit
	objInfo.UserDefined = objectlock.FilterObjectLockMetadata(objInfo.UserDefined, getRetPerms != ErrNone, legalHoldPerms != ErrNone)

	// Validate pre-conditions if any.
	if checkPreconditions(ctx, w, r, objInfo, opts) {
		return
	}

	// Get request range.
	var rs *HTTPRangeSpec
	rangeHeader := r.Header.Get(xhttp.Range)
	if rangeHeader != "" {
		if rs, err = parseRequestRangeSpec(rangeHeader); err != nil {
			// Handle only errInvalidRange. Ignore other
			// parse error and treat it as regular Get
			// request like Amazon S3.
			if err == errInvalidRange {
				writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrInvalidRange))
				return
			}

			logger.LogIf(ctx, err)
		}
	}

	// Both 'bytes' and 'partNumber' cannot be specified at the same time
	if rs != nil && opts.PartNumber > 0 {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrBadRequest))
		return
	}

	// Set encryption response headers
	if objectAPI.IsEncryptionSupported() {
		if crypto.IsEncrypted(objInfo.UserDefined) {
			switch {
			case crypto.S3.IsEncrypted(objInfo.UserDefined):
				w.Header().Set(crypto.SSEHeader, crypto.SSEAlgorithmAES256)
			case crypto.SSEC.IsEncrypted(objInfo.UserDefined):
				// Validate the SSE-C Key set in the header.
				if _, err = crypto.SSEC.UnsealObjectKey(r.Header, objInfo.UserDefined, bucket, object); err != nil {
					writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
					return
				}
				w.Header().Set(crypto.SSECAlgorithm, r.Header.Get(crypto.SSECAlgorithm))
				w.Header().Set(crypto.SSECKeyMD5, r.Header.Get(crypto.SSECKeyMD5))
			}
		}
	}

	// Set standard object headers.
	if err = setObjectHeaders(w, objInfo, rs, opts); err != nil {
		writeErrorResponseHeadersOnly(w, toAPIError(ctx, err))
		return
	}

	// Set Parts Count Header
	if opts.PartNumber > 0 && len(objInfo.Parts) > 0 {
		setPartsCountHeaders(w, objInfo)
	}

	// Set any additional requested response headers.
	setHeadGetRespHeaders(w, r.URL.Query())

	// Successful response.
	if rs != nil || opts.PartNumber > 0 {
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	// Notify object accessed via a HEAD request.
	sendEvent(eventArgs{
		EventName:    event.ObjectAccessedHead,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

// Extract metadata relevant for an CopyObject operation based on conditional
// header values specified in X-Amz-Metadata-Directive.
func getCpObjMetadataFromHeader(ctx context.Context, r *http.Request, userMeta map[string]string) (map[string]string, error) {
	// Make a copy of the supplied metadata to avoid
	// to change the original one.
	defaultMeta := make(map[string]string, len(userMeta))
	for k, v := range userMeta {
		defaultMeta[k] = v
	}

	// remove SSE Headers from source info
	crypto.RemoveSSEHeaders(defaultMeta)

	// Storage class is special, it can be replaced regardless of the
	// metadata directive, if set should be preserved and replaced
	// to the destination metadata.
	sc := r.Header.Get(xhttp.AmzStorageClass)
	if sc == "" {
		sc = r.URL.Query().Get(xhttp.AmzStorageClass)
	}

	// if x-amz-metadata-directive says REPLACE then
	// we extract metadata from the input headers.
	if isDirectiveReplace(r.Header.Get(xhttp.AmzMetadataDirective)) {
		emetadata, err := extractMetadata(ctx, r)
		if err != nil {
			return nil, err
		}
		if sc != "" {
			emetadata[xhttp.AmzStorageClass] = sc
		}
		return emetadata, nil
	}

	if sc != "" {
		defaultMeta[xhttp.AmzStorageClass] = sc
	}

	// if x-amz-metadata-directive says COPY then we
	// return the default metadata.
	if isDirectiveCopy(r.Header.Get(xhttp.AmzMetadataDirective)) {
		return defaultMeta, nil
	}

	// Copy is default behavior if not x-amz-metadata-directive is set.
	return defaultMeta, nil
}

// getRemoteInstanceTransport contains a singleton roundtripper.
var (
	getRemoteInstanceTransport     *http.Transport
	getRemoteInstanceTransportOnce sync.Once
)

// Returns a minio-go Client configured to access remote host described by destDNSRecord
// Applicable only in a federated deployment
var getRemoteInstanceClient = func(r *http.Request, host string) (*miniogo.Core, error) {
	if newObjectLayerFn() == nil {
		return nil, errServerNotInitialized
	}

	cred := getReqAccessCred(r, globalServerRegion)
	// In a federated deployment, all the instances share config files
	// and hence expected to have same credentials.
	core, err := miniogo.NewCore(host, &miniogo.Options{
		Creds:     credentials.NewStaticV4(cred.AccessKey, cred.SecretKey, ""),
		Secure:    globalIsSSL,
		Transport: getRemoteInstanceTransport,
	})
	if err != nil {
		return nil, err
	}
	return core, nil
}

// Check if the destination bucket is on a remote site, this code only gets executed
// when federation is enabled, ie when globalDNSConfig is non 'nil'.
//
// This function is similar to isRemoteCallRequired but specifically for COPY object API
// if destination and source are same we do not need to check for destination bucket
// to exist locally.
func isRemoteCopyRequired(ctx context.Context, srcBucket, dstBucket string, objAPI ObjectLayer) bool {
	if srcBucket == dstBucket {
		return false
	}
	return isRemoteCallRequired(ctx, dstBucket, objAPI)
}

// Check if the bucket is on a remote site, this code only gets executed when federation is enabled.
func isRemoteCallRequired(ctx context.Context, bucket string, objAPI ObjectLayer) bool {
	return false
}

// CopyObjectHandler - Copy Object
// ----------
// This implementation of the PUT operation adds an object to a bucket
// while reading the object from another source.
// Notice: The S3 client can send secret keys in headers for encryption related jobs,
// the handler should ensure to remove these keys before sending them to the object layer.
// Currently these keys are:
//   - X-Amz-Server-Side-Encryption-Customer-Key
//   - X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key
func (api objectAPIHandlers) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "CopyObject")

	defer logger.AuditLog(w, r, "CopyObject", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
	return
}

// PutObjectHandler - PUT Object
// ----------
// This implementation of the PUT operation adds an object to a bucket.
// Notice: The S3 client can send secret keys in headers for encryption related jobs,
// the handler should ensure to remove these keys before sending them to the object layer.
// Currently these keys are:
//   - X-Amz-Server-Side-Encryption-Customer-Key
//   - X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key
func (api objectAPIHandlers) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutObject")
	defer logger.AuditLog(w, r, "PutObject", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	if !objectAPI.IsEncryptionSupported() && crypto.IsRequested(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// X-Amz-Copy-Source shouldn't be set for this call.
	if _, ok := r.Header[xhttp.AmzCopySource]; ok {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL)
		return
	}

	// Validate storage class metadata if present
	if sc := r.Header.Get(xhttp.AmzStorageClass); sc != "" {
		if !storageclass.IsValid(sc) {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL)
			return
		}
	}

	// Get Content-Md5 sent by client and verify if valid
	md5Bytes, err := checkValidMD5(r.Header)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidDigest), r.URL)
		return
	}

	/// if Content-Length is unknown/missing, deny the request
	size := r.ContentLength
	rAuthType := getRequestAuthType(r)
	if rAuthType == authTypeStreamingSigned {
		if sizeStr, ok := r.Header[xhttp.AmzDecodedContentLength]; ok {
			if sizeStr[0] == "" {
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
				return
			}
			size, err = strconv.ParseInt(sizeStr[0], 10, 64)
			if err != nil {
				writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
				return
			}
		}
	}
	if size == -1 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	/// maximum Upload size for objects in a single operation
	if isMaxObjectSize(size) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL)
		return
	}

	metadata, err := extractMetadata(ctx, r)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	if objTags := r.Header.Get(xhttp.AmzObjectTagging); objTags != "" {
		if !objectAPI.IsTaggingSupported() {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
			return
		}

		if _, err := tags.ParseObjectTags(objTags); err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}

		metadata[xhttp.AmzObjectTagging] = objTags
	}

	var (
		md5hex    = hex.EncodeToString(md5Bytes)
		sha256hex = ""
		reader    io.Reader
		s3Err     APIErrorCode
		putObject = objectAPI.PutObject
	)
	reader = r.Body

	// Check if put is allowed
	if s3Err = isPutActionAllowed(ctx, rAuthType, bucket, object, r, iampolicy.PutObjectAction); s3Err != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
		return
	}

	switch rAuthType {
	case authTypeStreamingSigned:
		// Initialize stream signature verifier.
		reader, s3Err = newSignV4ChunkedReader(r)
		if s3Err != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
			return
		}
	case authTypeSignedV2, authTypePresignedV2:
		s3Err = isReqAuthenticatedV2(r)
		if s3Err != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
			return
		}

	case authTypePresigned, authTypeSigned:
		if s3Err = reqSignatureV4Verify(r, globalServerRegion, serviceS3); s3Err != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL)
			return
		}
		if !skipContentSha256Cksum(r) {
			sha256hex = getContentSha256Cksum(r, serviceS3)
		}
	}

	actualSize := size

	if objectAPI.IsCompressionSupported() && isCompressible(r.Header, object) && size > 0 {
		// Storing the compression metadata.
		metadata[ReservedMetadataPrefix+"compression"] = compressionAlgorithmV2
		metadata[ReservedMetadataPrefix+"actual-size"] = strconv.FormatInt(size, 10)

		actualReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize, globalCLIContext.StrictS3Compat)
		if err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}

		// Set compression metrics.
		s2c := newS2CompressReader(actualReader)
		defer s2c.Close()
		reader = s2c
		size = -1   // Since compressed size is un-predictable.
		md5hex = "" // Do not try to verify the content.
		sha256hex = ""
	}

	hashReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize, globalCLIContext.StrictS3Compat)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	rawReader := hashReader
	pReader := NewPutObjReader(rawReader, nil, nil)

	// get gateway encryption options
	var opts ObjectOptions
	opts, err = putOpts(ctx, r, bucket, object, metadata)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Create the object..
	objInfo, err := putObject(ctx, bucket, object, pReader, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	setPutObjHeaders(w, objInfo, false)

	writeSuccessResponseHeadersOnly(w)

	// Notify object created event.
	sendEvent(eventArgs{
		EventName:    event.ObjectCreatedPut,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

/// Multipart objectAPIHandlers

// NewMultipartUploadHandler - New multipart upload.
// Notice: The S3 client can send secret keys in headers for encryption related jobs,
// the handler should ensure to remove these keys before sending them to the object layer.
// Currently these keys are:
//   - X-Amz-Server-Side-Encryption-Customer-Key
//   - X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key
func (api objectAPIHandlers) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "NewMultipartUpload")

	defer logger.AuditLog(w, r, "NewMultipartUpload", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	if !objectAPI.IsEncryptionSupported() && crypto.IsRequested(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// Validate storage class metadata if present
	if sc := r.Header.Get(xhttp.AmzStorageClass); sc != "" {
		if !storageclass.IsValid(sc) {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL)
			return
		}
	}

	// Extract metadata that needs to be saved.
	metadata, err := extractMetadata(ctx, r)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	opts, err := putOpts(ctx, r, bucket, object, metadata)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	newMultipartUpload := objectAPI.NewMultipartUpload

	uploadID, err := newMultipartUpload(ctx, bucket, object, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	response := generateInitiateMultipartUploadResponse(bucket, object, uploadID)
	encodedSuccessResponse := encodeResponse(response)

	// Write success response.
	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// CopyObjectPartHandler - uploads a part by copying data from an existing object as data source.
func (api objectAPIHandlers) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "CopyObjectPart")

	defer logger.AuditLog(w, r, "CopyObjectPart", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
	return
}

// PutObjectPartHandler - uploads an incoming part for an ongoing multipart operation.
func (api objectAPIHandlers) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutObjectPart")

	defer logger.AuditLog(w, r, "PutObjectPart", mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	if !objectAPI.IsEncryptionSupported() && crypto.IsRequested(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// X-Amz-Copy-Source shouldn't be set for this call.
	if _, ok := r.Header[xhttp.AmzCopySource]; ok {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL)
		return
	}

	// get Content-Md5 sent by client and verify if valid
	md5Bytes, err := checkValidMD5(r.Header)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidDigest), r.URL)
		return
	}

	/// if Content-Length is unknown/missing, throw away
	size := r.ContentLength

	rAuthType := getRequestAuthType(r)
	// For auth type streaming signature, we need to gather a different content length.
	if rAuthType == authTypeStreamingSigned {
		if sizeStr, ok := r.Header[xhttp.AmzDecodedContentLength]; ok {
			if sizeStr[0] == "" {
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
				return
			}
			size, err = strconv.ParseInt(sizeStr[0], 10, 64)
			if err != nil {
				writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
				return
			}
		}
	}
	if size == -1 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	/// maximum Upload size for multipart objects in a single operation
	if isMaxAllowedPartSize(size) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL)
		return
	}

	uploadID := r.URL.Query().Get(xhttp.UploadID)
	partIDString := r.URL.Query().Get(xhttp.PartNumber)

	partID, err := strconv.Atoi(partIDString)
	if err != nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPart), r.URL)
		return
	}

	// check partID with maximum part ID for multipart objects
	if isMaxPartID(partID) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMaxParts), r.URL)
		return
	}

	var (
		md5hex    = hex.EncodeToString(md5Bytes)
		sha256hex = ""
		reader    io.Reader
		s3Error   APIErrorCode
	)
	reader = r.Body
	if s3Error = isPutActionAllowed(ctx, rAuthType, bucket, object, r, iampolicy.PutObjectAction); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	switch rAuthType {
	case authTypeStreamingSigned:
		// Initialize stream signature verifier.
		reader, s3Error = newSignV4ChunkedReader(r)
		if s3Error != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
			return
		}
	case authTypeSignedV2, authTypePresignedV2:
		if s3Error = isReqAuthenticatedV2(r); s3Error != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
			return
		}
	case authTypePresigned, authTypeSigned:
		if s3Error = reqSignatureV4Verify(r, globalServerRegion, serviceS3); s3Error != ErrNone {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
			return
		}

		if !skipContentSha256Cksum(r) {
			sha256hex = getContentSha256Cksum(r, serviceS3)
		}
	}

	actualSize := size

	// get encryption options
	var opts ObjectOptions

	mi, err := objectAPI.GetMultipartInfo(ctx, bucket, object, uploadID, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Read compression metadata preserved in the init multipart for the decision.
	_, isCompressed := mi.UserDefined[ReservedMetadataPrefix+"compression"]

	if objectAPI.IsCompressionSupported() && isCompressed {
		actualReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize, globalCLIContext.StrictS3Compat)
		if err != nil {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}

		// Set compression metrics.
		s2c := newS2CompressReader(actualReader)
		defer s2c.Close()
		reader = s2c
		size = -1   // Since compressed size is un-predictable.
		md5hex = "" // Do not try to verify the content.
		sha256hex = ""
	}

	hashReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize, globalCLIContext.StrictS3Compat)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	rawReader := hashReader
	pReader := NewPutObjReader(rawReader, nil, nil)

	putObjectPart := objectAPI.PutObjectPart

	partInfo, err := putObjectPart(ctx, bucket, object, uploadID, partID, pReader, opts)
	if err != nil {
		// Verify if the underlying error is signature mismatch.
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	etag := partInfo.ETag

	// We must not use the http.Header().Set method here because some (broken)
	// clients expect the ETag header key to be literally "ETag" - not "Etag" (case-sensitive).
	// Therefore, we have to set the ETag directly as map entry.
	w.Header()[xhttp.ETag] = []string{"\"" + etag + "\""}

	writeSuccessResponseHeadersOnly(w)
}

// AbortMultipartUploadHandler - Abort multipart upload
func (api objectAPIHandlers) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AbortMultipartUpload")

	defer logger.AuditLog(w, r, "AbortMultipartUpload", mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}
	abortMultipartUpload := objectAPI.AbortMultipartUpload

	if s3Error := checkRequestAuthType(ctx, r, policy.AbortMultipartUploadAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	uploadID, _, _, _, s3Error := getObjectResources(r.URL.Query())
	if s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}
	opts := ObjectOptions{}
	if err := abortMultipartUpload(ctx, bucket, object, uploadID, opts); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	writeSuccessNoContent(w)
}

// ListObjectPartsHandler - List object parts
func (api objectAPIHandlers) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "ListObjectParts")

	defer logger.AuditLog(w, r, "ListObjectParts", mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.ListMultipartUploadPartsAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	uploadID, partNumberMarker, maxParts, encodingType, s3Error := getObjectResources(r.URL.Query())
	if s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}
	if partNumberMarker < 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPartNumberMarker), r.URL)
		return
	}
	if maxParts < 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMaxParts), r.URL)
		return
	}

	opts := ObjectOptions{}
	listPartsInfo, err := objectAPI.ListObjectParts(ctx, bucket, object, uploadID, partNumberMarker, maxParts, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	response := generateListPartsResponse(listPartsInfo, encodingType)
	encodedSuccessResponse := encodeResponse(response)

	// Write success response.
	writeSuccessResponseXML(w, encodedSuccessResponse)
}

type whiteSpaceWriter struct {
	http.ResponseWriter
	http.Flusher
	written bool
}

func (w *whiteSpaceWriter) Write(b []byte) (n int, err error) {
	n, err = w.ResponseWriter.Write(b)
	w.written = true
	return
}

func (w *whiteSpaceWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// Send empty whitespaces every 10 seconds to the client till completeMultiPartUpload() is
// done so that the client does not time out. Downside is we might send 200 OK and
// then send error XML. But accoording to S3 spec the client is supposed to check
// for error XML even if it received 200 OK. But for erasure this is not a problem
// as completeMultiPartUpload() is quick. Even For FS, it would not be an issue as
// we do background append as and when the parts arrive and completeMultiPartUpload
// is quick. Only in a rare case where parts would be out of order will
// FS:completeMultiPartUpload() take a longer time.
func sendWhiteSpace(w http.ResponseWriter) <-chan bool {
	doneCh := make(chan bool)
	go func() {
		ticker := time.NewTicker(time.Second * 10)
		headerWritten := false
		for {
			select {
			case <-ticker.C:
				// Write header if not written yet.
				if !headerWritten {
					w.Write([]byte(xml.Header))
					headerWritten = true
				}

				// Once header is written keep writing empty spaces
				// which are ignored by client SDK XML parsers.
				// This occurs when server takes long time to completeMultiPartUpload()
				w.Write([]byte(" "))
				w.(http.Flusher).Flush()
			case doneCh <- headerWritten:
				ticker.Stop()
				return
			}
		}

	}()
	return doneCh
}

// CompleteMultipartUploadHandler - Complete multipart upload.
func (api objectAPIHandlers) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "CompleteMultipartUpload")

	defer logger.AuditLog(w, r, "CompleteMultipartUpload", mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	// Content-Length is required and should be non-zero
	if r.ContentLength <= 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL)
		return
	}

	// Get upload id.
	uploadID, _, _, _, s3Error := getObjectResources(r.URL.Query())
	if s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	complMultipartUpload := &CompleteMultipartUpload{}
	if err = xmlDecoder(r.Body, complMultipartUpload, r.ContentLength); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}
	if len(complMultipartUpload.Parts) == 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedXML), r.URL)
		return
	}
	if !sort.IsSorted(CompletedParts(complMultipartUpload.Parts)) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPartOrder), r.URL)
		return
	}

	// Reject retention or governance headers if set, CompleteMultipartUpload spec
	// does not use these headers, and should not be passed down to checkPutObjectLockAllowed
	if objectlock.IsObjectLockRequested(r.Header) || objectlock.IsObjectLockGovernanceBypassSet(r.Header) {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL)
		return
	}

	// Complete parts.
	completeParts := make([]CompletePart, 0, len(complMultipartUpload.Parts))
	for _, part := range complMultipartUpload.Parts {
		part.ETag = canonicalizeETag(part.ETag)
		completeParts = append(completeParts, part)
	}

	completeMultiPartUpload := objectAPI.CompleteMultipartUpload

	// This code is specifically to handle the requirements for slow
	// complete multipart upload operations on FS mode.
	writeErrorResponseWithoutXMLHeader := func(ctx context.Context, w http.ResponseWriter, err APIError, reqURL *url.URL) {
		switch err.Code {
		case "SlowDown", "XMinioServerNotInitialized", "XMinioReadQuorum", "XMinioWriteQuorum":
			// Set retxry-after header to indicate user-agents to retry request after 120secs.
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
			w.Header().Set(xhttp.RetryAfter, "120")
		}

		// Generate error response.
		errorResponse := getAPIErrorResponse(ctx, err, reqURL.Path,
			w.Header().Get(xhttp.AmzRequestID), globalDeploymentID)
		encodedErrorResponse, _ := xml.Marshal(errorResponse)
		setCommonHeaders(w)
		w.Header().Set(xhttp.ContentType, string(mimeXML))
		w.Write(encodedErrorResponse)
		w.(http.Flusher).Flush()
	}

	setEventStreamHeaders(w)

	w = &whiteSpaceWriter{ResponseWriter: w, Flusher: w.(http.Flusher)}
	completeDoneCh := sendWhiteSpace(w)
	objInfo, err := completeMultiPartUpload(ctx, bucket, object, uploadID, completeParts, ObjectOptions{})
	// Stop writing white spaces to the client. Note that close(doneCh) style is not used as it
	// can cause white space to be written after we send XML response in a race condition.
	headerWritten := <-completeDoneCh
	if err != nil {
		if headerWritten {
			writeErrorResponseWithoutXMLHeader(ctx, w, toAPIError(ctx, err), r.URL)
		} else {
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		}
		return
	}

	// Get object location.
	location := getObjectLocation(r, globalDomainNames, bucket, object)
	// Generate complete multipart response.
	response := generateCompleteMultpartUploadResponse(bucket, object, location, objInfo.ETag)
	var encodedSuccessResponse []byte
	if !headerWritten {
		encodedSuccessResponse = encodeResponse(response)
	} else {
		encodedSuccessResponse, err = xml.Marshal(response)
		if err != nil {
			writeErrorResponseWithoutXMLHeader(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
	}

	setPutObjHeaders(w, objInfo, false)

	// Write success response.
	writeSuccessResponseXML(w, encodedSuccessResponse)

	// Notify object created event.
	sendEvent(eventArgs{
		EventName:    event.ObjectCreatedCompleteMultipartUpload,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

/// Delete objectAPIHandlers

// DeleteObjectHandler - delete an object
func (api objectAPIHandlers) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteObject")

	defer logger.AuditLog(w, r, "DeleteObject", mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.DeleteObjectAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	opts, err := delOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETE.html
	objInfo, err := deleteObject(ctx, objectAPI, bucket, object, w, r, opts)
	if err != nil {
		switch err.(type) {
		case BucketNotFound:
			// When bucket doesn't exist specially handle it.
			writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
			return
		}
		// Ignore delete object errors while replying to client, since we are suppposed to reply only 204.
	}

	setPutObjHeaders(w, objInfo, true)
	writeSuccessNoContent(w)
}

// GetObjectTaggingHandler - GET object tagging
func (api objectAPIHandlers) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "GetObjectTagging")
	defer logger.AuditLog(w, r, "GetObjectTagging", mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	if !objAPI.IsTaggingSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	// Allow getObjectTagging if policy action is set.
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectTaggingAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Get object tags
	tags, err := objAPI.GetObjectTags(ctx, bucket, object, opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	if opts.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{opts.VersionID}
	}

	writeSuccessResponseXML(w, encodeResponse(tags))
}

// PutObjectTaggingHandler - PUT object tagging
func (api objectAPIHandlers) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PutObjectTagging")
	defer logger.AuditLog(w, r, "PutObjectTagging", mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}
	if !objAPI.IsTaggingSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	// Allow putObjectTagging if policy action is set
	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectTaggingAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	tags, err := tags.ParseObjectXML(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Put object tags
	err = objAPI.PutObjectTags(ctx, bucket, object, tags.String(), opts)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	if opts.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{opts.VersionID}
	}

	writeSuccessResponseHeadersOnly(w)
}

// DeleteObjectTaggingHandler - DELETE object tagging
func (api objectAPIHandlers) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "DeleteObjectTagging")
	defer logger.AuditLog(w, r, "DeleteObjectTagging", mustGetClaimsFromToken(r))

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}
	if !objAPI.IsTaggingSupported() {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Allow deleteObjectTagging if policy action is set
	if s3Error := checkRequestAuthType(ctx, r, policy.DeleteObjectTaggingAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Delete object tags
	if err = objAPI.DeleteObjectTags(ctx, bucket, object, opts); err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	if opts.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{opts.VersionID}
	}

	writeSuccessNoContent(w)
}

// RestoreObjectHandler - POST restore object handler.
// ----------
func (api objectAPIHandlers) PostRestoreObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "PostRestoreObject")
	defer logger.AuditLog(w, r, "PostRestoreObject", mustGetClaimsFromToken(r))
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := url.PathUnescape(vars["object"])
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	// Fetch object stat info.
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL)
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo

	// Check for auth type to return S3 compatible error.
	if s3Error := checkRequestAuthType(ctx, r, policy.RestoreObjectAction, bucket, object); s3Error != ErrNone {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL)
		return
	}

	if r.ContentLength <= 0 {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEmptyRequestBody), r.URL)
		return
	}

	objInfo, err := getObjectInfo(ctx, bucket, object, ObjectOptions{})
	if err != nil {
		writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
		return
	}

	if objInfo.TransitionStatus != lifecycle.TransitionComplete {
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidObjectState), r.URL)
		return
	}

	rreq, err := parseRestoreRequest(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
		apiErr.Description = err.Error()
		writeErrorResponse(ctx, w, apiErr, r.URL)
		return
	}
	// validate the request
	if err := rreq.validate(ctx, objectAPI); err != nil {
		apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
		apiErr.Description = err.Error()
		writeErrorResponse(ctx, w, apiErr, r.URL)
		return
	}
	statusCode := http.StatusOK
	alreadyRestored := false
	if err == nil {
		if objInfo.RestoreOngoing && rreq.Type != SelectRestoreRequest {
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrObjectRestoreAlreadyInProgress), r.URL)
			return
		}
		if !objInfo.RestoreOngoing && !objInfo.RestoreExpires.IsZero() {
			statusCode = http.StatusAccepted
			alreadyRestored = true
		}
	}
	// set or upgrade restore expiry
	restoreExpiry := lifecycle.ExpectedExpiryTime(time.Now(), rreq.Days)
	metadata := cloneMSS(objInfo.UserDefined)

	// update self with restore metadata
	if rreq.Type != SelectRestoreRequest {
		objInfo.metadataOnly = true // Perform only metadata updates.
		ongoingReq := true
		if alreadyRestored {
			ongoingReq = false
		}
		metadata[xhttp.AmzRestoreExpiryDays] = strconv.Itoa(rreq.Days)
		metadata[xhttp.AmzRestoreRequestDate] = time.Now().UTC().Format(http.TimeFormat)
		if alreadyRestored {
			metadata[xhttp.AmzRestore] = fmt.Sprintf("ongoing-request=%t, expiry-date=%s", ongoingReq, restoreExpiry.Format(http.TimeFormat))
		} else {
			metadata[xhttp.AmzRestore] = fmt.Sprintf("ongoing-request=%t", ongoingReq)
		}
		objInfo.UserDefined = metadata
		if _, err := objectAPI.CopyObject(GlobalContext, bucket, object, bucket, object, objInfo, ObjectOptions{
			VersionID: objInfo.VersionID,
		}, ObjectOptions{
			VersionID: objInfo.VersionID,
		}); err != nil {
			logger.LogIf(ctx, fmt.Errorf("Unable to update replication metadata for %s: %s", objInfo.VersionID, err))
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidObjectState), r.URL)
			return
		}
		// for previously restored object, just update the restore expiry
		if alreadyRestored {
			return
		}
	}

	restoreObject := mustGetUUID()
	if rreq.OutputLocation.S3.BucketName != "" {
		w.Header()[xhttp.AmzRestoreOutputPath] = []string{pathJoin(rreq.OutputLocation.S3.BucketName, rreq.OutputLocation.S3.Prefix, restoreObject)}
	}
	w.WriteHeader(statusCode)
	// Notify object restore started via a POST request.
	sendEvent(eventArgs{
		EventName:  event.ObjectRestorePostInitiated,
		BucketName: bucket,
		Object:     objInfo,
		ReqParams:  extractReqParams(r),
		UserAgent:  r.UserAgent(),
		Host:       handlers.GetSourceIP(r),
	})
	// now process the restore in background
	go func() {
		rctx := GlobalContext
		if !rreq.SelectParameters.IsEmpty() {
			getObject := func(offset, length int64) (rc io.ReadCloser, err error) {
				isSuffixLength := false
				if offset < 0 {
					isSuffixLength = true
				}

				rs := &HTTPRangeSpec{
					IsSuffixLength: isSuffixLength,
					Start:          offset,
					End:            offset + length,
				}

				return getTransitionedObjectReader(rctx, bucket, object, rs, r.Header, objInfo, ObjectOptions{
					VersionID: objInfo.VersionID,
				})
			}
			if err = rreq.SelectParameters.Open(getObject); err != nil {
				if serr, ok := err.(s3select.SelectError); ok {
					encodedErrorResponse := encodeResponse(APIErrorResponse{
						Code:       serr.ErrorCode(),
						Message:    serr.ErrorMessage(),
						BucketName: bucket,
						Key:        object,
						Resource:   r.URL.Path,
						RequestID:  w.Header().Get(xhttp.AmzRequestID),
						HostID:     globalDeploymentID,
					})
					writeResponse(w, serr.HTTPStatusCode(), encodedErrorResponse, mimeXML)
				} else {
					writeErrorResponse(ctx, w, toAPIError(ctx, err), r.URL)
				}
				return
			}
			nr := httptest.NewRecorder()
			rw := logger.NewResponseWriter(nr)
			rw.LogErrBody = true
			rw.LogAllBody = true
			rreq.SelectParameters.Evaluate(rw)
			rreq.SelectParameters.Close()
			return
		}
		if err := restoreTransitionedObject(rctx, bucket, object, objectAPI, objInfo, rreq, restoreExpiry); err != nil {
			return
		}

		// Notify object restore completed via a POST request.
		sendEvent(eventArgs{
			EventName:  event.ObjectRestorePostCompleted,
			BucketName: bucket,
			Object:     objInfo,
			ReqParams:  extractReqParams(r),
			UserAgent:  r.UserAgent(),
			Host:       handlers.GetSourceIP(r),
		})
	}()
}
