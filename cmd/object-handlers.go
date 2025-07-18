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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/sio"

	"storj.io/minio/cmd/config/storageclass"
	"storj.io/minio/cmd/crypto"
	xhttp "storj.io/minio/cmd/http"
	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/bucket/lifecycle"
	objectlock "storj.io/minio/pkg/bucket/object/lock"
	"storj.io/minio/pkg/bucket/policy"
	"storj.io/minio/pkg/bucket/replication"
	"storj.io/minio/pkg/etag"
	"storj.io/minio/pkg/event"
	"storj.io/minio/pkg/handlers"
	"storj.io/minio/pkg/hash"
	iampolicy "storj.io/minio/pkg/iam/policy"
	"storj.io/minio/pkg/ioutil"
	xnet "storj.io/minio/pkg/net"
	"storj.io/minio/pkg/s3select"
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
func (api ObjectAPIHandlers) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "SelectObject")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	// Fetch object stat info.
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if crypto.S3.IsRequested(r.Header) || crypto.S3KMS.IsRequested(r.Header) { // If SSE-S3 or SSE-KMS present -> AWS fails with undefined error
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := crypto.IsRequested(r.Header); ok && !objectAPI.IsEncryptionSupported() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL, guessIsBrowserReq(r))
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// get gateway encryption options
	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo
	if api.CacheAPI() != nil {
		getObjectInfo = api.CacheAPI().GetObjectInfo
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
				_, err = getObjectInfo(ctx, bucket, object, opts)
				if ToAPIError(ctx, err).Code == "NoSuchKey" {
					s3Error = ErrNoSuchKey
				}
			}
		}
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	// Get request range.
	rangeHeader := r.Header.Get(xhttp.Range)
	if rangeHeader != "" {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrUnsupportedRangeHeader), r.URL, guessIsBrowserReq(r))
		return
	}

	if r.ContentLength <= 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEmptyRequestBody), r.URL, guessIsBrowserReq(r))
		return
	}

	getObjectNInfo := objectAPI.GetObjectNInfo
	if api.CacheAPI() != nil {
		getObjectNInfo = api.CacheAPI().GetObjectNInfo
	}

	getObject := func(offset, length int64) (rc io.ReadCloser, err error) {
		isSuffixLength := false
		if offset < 0 {
			isSuffixLength = true
		}

		if length > 0 {
			length--
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
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// filter object lock metadata if permission does not permit
	getRetPerms := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object)
	legalHoldPerms := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object)

	// filter object lock metadata if permission does not permit
	objInfo.UserDefined = objectlock.FilterObjectLockMetadata(objInfo.UserDefined, getRetPerms != ErrNone, legalHoldPerms != ErrNone)

	if objectAPI.IsEncryptionSupported() {
		if _, err = DecryptObjectInfo(&objInfo, r); err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	s3Select, err := s3select.NewS3Select(r.Body)
	if err != nil {
		if serr, ok := err.(s3select.SelectError); ok {
			encodedErrorResponse := EncodeResponse(APIErrorResponse{
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
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		}
		return
	}
	defer s3Select.Close()

	if err = s3Select.Open(getObject); err != nil {
		if serr, ok := err.(s3select.SelectError); ok {
			encodedErrorResponse := EncodeResponse(APIErrorResponse{
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
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		}
		return
	}

	// Set encryption response headers
	if objectAPI.IsEncryptionSupported() {
		switch kind, _ := crypto.IsEncrypted(objInfo.UserDefined); kind {
		case crypto.S3:
			w.Header().Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
		case crypto.SSEC:
			// Validate the SSE-C Key set in the header.
			if _, err = crypto.SSEC.UnsealObjectKey(r.Header, objInfo.UserDefined, bucket, object); err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerAlgorithm, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerAlgorithm))
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerKeyMD5, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerKeyMD5))
		}
	}

	s3Select.Evaluate(w)

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
func (api ObjectAPIHandlers) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetObject")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}
	if crypto.S3.IsRequested(r.Header) || crypto.S3KMS.IsRequested(r.Header) { // If SSE-S3 or SSE-KMS present -> AWS fails with undefined error
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := crypto.IsRequested(r.Header); !objectAPI.IsEncryptionSupported() && ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL, guessIsBrowserReq(r))
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// get gateway encryption options
	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
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
				if api.CacheAPI() != nil {
					getObjectInfo = api.CacheAPI().GetObjectInfo
				}

				_, err = getObjectInfo(ctx, bucket, object, opts)
				if ToAPIError(ctx, err).Code == "NoSuchKey" {
					s3Error = ErrNoSuchKey
				}
			}
		}
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	getObjectNInfo := objectAPI.GetObjectNInfo
	if api.CacheAPI() != nil {
		getObjectNInfo = api.CacheAPI().GetObjectNInfo
	}

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
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRange), r.URL, guessIsBrowserReq(r))
			return
		}
		if rangeErr != nil {
			logger.LogIf(ctx, rangeErr, logger.Application)
		}
	}

	// Both 'bytes' and 'partNumber' cannot be specified at the same time
	if rs != nil && opts.PartNumber > 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRangePartNumber), r.URL, guessIsBrowserReq(r))
		return
	}

	// Validate pre-conditions if any.
	opts.CheckPrecondFn = func(oi ObjectInfo) bool {
		if objectAPI.IsEncryptionSupported() {
			if _, err := DecryptObjectInfo(&oi, r); err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return true
			}
		}

		return checkPreconditions(ctx, w, r, oi, opts)
	}

	gr, err := getObjectNInfo(ctx, bucket, object, rs, r.Header, readLock, opts)
	if err != nil {
		var (
			reader *GetObjectReader
			proxy  bool
		)
		if isProxyable(ctx, bucket) {
			// proxy to replication target if active-active replication is in place.
			reader, proxy = proxyGetToReplicationTarget(ctx, bucket, object, rs, r.Header, opts)
			if reader != nil && proxy {
				gr = reader
			}
		}
		if reader == nil || !proxy {
			if isErrPreconditionFailed(err) {
				return
			}
			if globalBucketVersioningSys.Enabled(bucket) && gr != nil {
				if !gr.ObjInfo.VersionPurgeStatus.Empty() {
					// Shows the replication status of a permanent delete of a version
					w.Header()[xhttp.MinIODeleteReplicationStatus] = []string{string(gr.ObjInfo.VersionPurgeStatus)}
				}
				if !gr.ObjInfo.ReplicationStatus.Empty() && gr.ObjInfo.DeleteMarker {
					w.Header()[xhttp.MinIODeleteMarkerReplicationStatus] = []string{string(gr.ObjInfo.ReplicationStatus)}
				}

				// Versioning enabled quite possibly object is deleted might be delete-marker
				// if present set the headers, no idea why AWS S3 sets these headers.
				if gr.ObjInfo.VersionID != "" && gr.ObjInfo.DeleteMarker {
					w.Header()[xhttp.AmzVersionID] = []string{gr.ObjInfo.VersionID}
					w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(gr.ObjInfo.DeleteMarker)}
				}
			}
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
	}
	defer gr.Close()

	objInfo := gr.ObjInfo

	// Automatically remove the object/version is an expiry lifecycle rule can be applied
	if lc, err := globalLifecycleSys.Get(bucket); err == nil {
		action := evalActionFromLifecycle(ctx, *lc, objInfo, false)
		if action == lifecycle.DeleteAction || action == lifecycle.DeleteVersionAction {
			globalExpiryState.queueExpiryTask(objInfo, action == lifecycle.DeleteVersionAction)
			writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrNoSuchKey))
			return
		}
	}

	// filter object lock metadata if permission does not permit
	getRetPerms := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object)
	legalHoldPerms := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object)

	// filter object lock metadata if permission does not permit
	objInfo.UserDefined = objectlock.FilterObjectLockMetadata(objInfo.UserDefined, getRetPerms != ErrNone, legalHoldPerms != ErrNone)

	// Set encryption response headers
	if objectAPI.IsEncryptionSupported() {
		switch kind, _ := crypto.IsEncrypted(objInfo.UserDefined); kind {
		case crypto.S3:
			w.Header().Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
		case crypto.SSEC:
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerAlgorithm, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerAlgorithm))
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerKeyMD5, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerKeyMD5))
		}
	}

	if err = setObjectHeaders(w, objInfo, rs, opts); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
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
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
		if !xnet.IsNetworkOrHostDown(err, true) { // do not need to log disconnected clients
			logger.LogIf(ctx, fmt.Errorf("Unable to write all the data to client %w", err))
		}
		return
	}

	if err = httpWriter.Close(); err != nil {
		if !httpWriter.HasWritten() && !statusCodeWritten { // write error response only if no data or headers has been written to client yet
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
		if !xnet.IsNetworkOrHostDown(err, true) { // do not need to log disconnected clients
			logger.LogIf(ctx, fmt.Errorf("Unable to write all the data to client %w", err))
		}
		return
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

// GetObjectAttributes.
func (api ObjectAPIHandlers) GetObjectAttributesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetObjectAttributes")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	writeArgumentErrorResponse := func(apiErr APIError, argumentName, argumentValue string) {
		response := ObjectAttributesErrorResponse{
			ArgumentName:     argumentName,
			ArgumentValue:    argumentValue,
			APIErrorResponse: getAPIErrorResponse(ctx, apiErr, r.URL.Path, w.Header().Get(xhttp.AmzRequestID), globalDeploymentID),
		}
		writeResponse(w, apiErr.HTTPStatusCode, EncodeResponse(response), mimeXML)
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		var invalidVersionErr InvalidVersionID
		switch {
		case errors.As(err, &invalidVersionErr):
			writeArgumentErrorResponse(ToAPIError(ctx, err), "versionId", invalidVersionErr.VersionID)
		default:
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		}
		return
	}

	objInfo, err := objectAPI.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	requestedAttributes := strings.TrimSpace(r.Header.Get(xhttp.AmzObjectAttributes))
	if requestedAttributes == "" {
		writeArgumentErrorResponse(errorCodes.ToAPIErr(ErrInvalidAttributeName), strings.ToLower(xhttp.AmzObjectAttributes), "")
		return
	}

	// TODO: checksum and object parts are not supported yet.
	var response ObjectAttributesResponse
	for _, name := range strings.Split(requestedAttributes, ",") {
		switch name {
		case xhttp.ETag:
			response.ETag = objInfo.ETag
		case xhttp.StorageClass:
			response.StorageClass = storageclass.STANDARD
			if objInfo.StorageClass != "" {
				response.StorageClass = objInfo.StorageClass
			}
		case xhttp.ObjectSize:
			response.ObjectSize = objInfo.Size
		case xhttp.Checksum:
		case xhttp.ObjectParts:
		default:
			writeArgumentErrorResponse(errorCodes.ToAPIErr(ErrInvalidAttributeName), strings.ToLower(xhttp.AmzObjectAttributes), name)
			return
		}
	}

	if objInfo.VersionID != "" {
		w.Header().Set(xhttp.AmzVersionID, objInfo.VersionID)
	}
	w.Header().Set(xhttp.LastModified, objInfo.ModTime.UTC().Format(http.TimeFormat))

	WriteSuccessResponseXML(w, EncodeResponse(response))
}

// HeadObjectHandler - HEAD Object
// -----------
// The HEAD operation retrieves metadata from an object without returning the object itself.
func (api ObjectAPIHandlers) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "HeadObject")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrServerNotInitialized))
		return
	}
	if crypto.S3.IsRequested(r.Header) || crypto.S3KMS.IsRequested(r.Header) { // If SSE-S3 or SSE-KMS present -> AWS fails with undefined error
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrBadRequest))
		return
	}
	if _, ok := crypto.IsRequested(r.Header); !objectAPI.IsEncryptionSupported() && ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrBadRequest), r.URL, guessIsBrowserReq(r))
		return
	}
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo
	if api.CacheAPI() != nil {
		getObjectInfo = api.CacheAPI().GetObjectInfo
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		writeErrorResponseHeadersOnly(w, ToAPIError(ctx, err))
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
				if ToAPIError(ctx, err).Code == "NoSuchKey" {
					s3Error = ErrNoSuchKey
				}
			}
		}
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(s3Error))
		return
	}

	objInfo, err := getObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		var (
			proxy bool
			perr  error
			oi    ObjectInfo
		)
		// proxy HEAD to replication target if active-active replication configured on bucket
		if isProxyable(ctx, bucket) {
			oi, proxy, perr = proxyHeadToReplicationTarget(ctx, bucket, object, opts)
			if proxy && perr == nil {
				objInfo = oi
			}
		}
		if !proxy || perr != nil {
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
			writeErrorResponseHeadersOnly(w, ToAPIError(ctx, err))
			return
		}
	}

	// Automatically remove the object/version is an expiry lifecycle rule can be applied
	if lc, err := globalLifecycleSys.Get(bucket); err == nil {
		action := evalActionFromLifecycle(ctx, *lc, objInfo, false)
		if action == lifecycle.DeleteAction || action == lifecycle.DeleteVersionAction {
			globalExpiryState.queueExpiryTask(objInfo, action == lifecycle.DeleteVersionAction)
			writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrNoSuchKey))
			return
		}
	}

	// filter object lock metadata if permission does not permit
	getRetPerms := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object)
	legalHoldPerms := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object)

	// filter object lock metadata if permission does not permit
	objInfo.UserDefined = objectlock.FilterObjectLockMetadata(objInfo.UserDefined, getRetPerms != ErrNone, legalHoldPerms != ErrNone)

	if objectAPI.IsEncryptionSupported() {
		if _, err = DecryptObjectInfo(&objInfo, r); err != nil {
			writeErrorResponseHeadersOnly(w, ToAPIError(ctx, err))
			return
		}
	}

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
		writeErrorResponseHeadersOnly(w, errorCodes.ToAPIErr(ErrInvalidRangePartNumber))
		return
	}

	// Set encryption response headers
	if objectAPI.IsEncryptionSupported() {
		switch kind, _ := crypto.IsEncrypted(objInfo.UserDefined); kind {
		case crypto.S3:
			w.Header().Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
		case crypto.SSEC:
			// Validate the SSE-C Key set in the header.
			if _, err = crypto.SSEC.UnsealObjectKey(r.Header, objInfo.UserDefined, bucket, object); err != nil {
				writeErrorResponseHeadersOnly(w, ToAPIError(ctx, err))
				return
			}
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerAlgorithm, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerAlgorithm))
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerKeyMD5, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerKeyMD5))
		}
	}

	// Set standard object headers.
	if err = setObjectHeaders(w, objInfo, rs, opts); err != nil {
		writeErrorResponseHeadersOnly(w, ToAPIError(ctx, err))
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

// CopyObjectHandler - Copy Object
// ----------
// This implementation of the PUT operation adds an object to a bucket
// while reading the object from another source.
// Notice: The S3 client can send secret keys in headers for encryption related jobs,
// the handler should ensure to remove these keys before sending them to the object layer.
// Currently these keys are:
//   - X-Amz-Server-Side-Encryption-Customer-Key
//   - X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key
func (api ObjectAPIHandlers) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "CopyObject")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := crypto.IsRequested(r.Header); ok {
		if GlobalIsGateway {
			if crypto.SSEC.IsRequested(r.Header) && !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		} else {
			if !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	vars := mux.Vars(r)
	dstBucket := vars["bucket"]
	dstObject, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, dstBucket, dstObject); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	// Read escaped copy source path to check for parameters.
	cpSrcPath := r.Header.Get(xhttp.AmzCopySource)
	var vid string
	if u, err := url.Parse(cpSrcPath); err == nil {
		vid = strings.TrimSpace(u.Query().Get(xhttp.VersionID))
		// Note that url.Parse does the unescaping
		cpSrcPath = u.Path
	}

	srcBucket, srcObject := path2BucketObject(cpSrcPath)
	// If source object is empty or bucket is empty, reply back invalid copy source.
	if srcObject == "" || srcBucket == "" {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL, guessIsBrowserReq(r))
		return
	}

	if vid != "" && vid != nullVersionID {
		_, err := uuid.Parse(vid)
		if err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, VersionNotFound{
				Bucket:    srcBucket,
				Object:    srcObject,
				VersionID: vid,
			}), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, srcBucket, srcObject); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	// Check if metadata directive is valid.
	if !isDirectiveValid(r.Header.Get(xhttp.AmzMetadataDirective)) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMetadataDirective), r.URL, guessIsBrowserReq(r))
		return
	}

	// check if tag directive is valid
	if !isDirectiveValid(r.Header.Get(xhttp.AmzTagDirective)) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidTagDirective), r.URL, guessIsBrowserReq(r))
		return
	}

	// Validate storage class metadata if present
	dstSc := r.Header.Get(xhttp.AmzStorageClass)
	if dstSc != "" && !storageclass.IsValid(dstSc) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL, guessIsBrowserReq(r))
		return
	}

	// Check if bucket encryption is enabled
	_, err = globalBucketSSEConfigSys.Get(dstBucket)
	// This request header needs to be set prior to setting ObjectOptions
	if (globalAutoEncryption || err == nil) && !crypto.SSEC.IsRequested(r.Header) {
		r.Header.Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
	}

	var srcOpts, dstOpts ObjectOptions
	srcOpts, err = copySrcOpts(ctx, r, srcBucket, srcObject)
	if err != nil {
		logger.LogIf(ctx, err)
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	srcOpts.VersionID = vid

	// convert copy src encryption options for GET calls
	var getOpts = ObjectOptions{VersionID: srcOpts.VersionID, Versioned: srcOpts.Versioned}
	getSSE := encrypt.SSE(srcOpts.ServerSideEncryption)
	if getSSE != srcOpts.ServerSideEncryption {
		getOpts.ServerSideEncryption = getSSE
	}

	dstOpts, err = copyDstOpts(ctx, r, dstBucket, dstObject, nil)
	if err != nil {
		logger.LogIf(ctx, err)
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	cpSrcDstSame := isStringEqual(pathJoin(srcBucket, srcObject), pathJoin(dstBucket, dstObject))

	getObjectNInfo := objectAPI.GetObjectNInfo
	if api.CacheAPI() != nil {
		getObjectNInfo = api.CacheAPI().GetObjectNInfo
	}

	checkCopyPrecondFn := func(o ObjectInfo) bool {
		if objectAPI.IsEncryptionSupported() {
			if _, err := DecryptObjectInfo(&o, r); err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return true
			}
		}
		return checkCopyObjectPreconditions(ctx, w, r, o)
	}
	getOpts.CheckPrecondFn = checkCopyPrecondFn

	// FIXME: a possible race exists between a parallel
	// GetObject v/s CopyObject with metadata updates, ideally
	// we should be holding write lock here but it is not
	// possible due to other constraints such as knowing
	// the type of source content etc.
	lock := noLock
	if !cpSrcDstSame {
		lock = readLock
	}

	var rs *HTTPRangeSpec
	gr, err := getObjectNInfo(ctx, srcBucket, srcObject, rs, r.Header, lock, getOpts)
	if err != nil {
		if isErrPreconditionFailed(err) {
			return
		}
		if globalBucketVersioningSys.Enabled(srcBucket) && gr != nil {
			// Versioning enabled quite possibly object is deleted might be delete-marker
			// if present set the headers, no idea why AWS S3 sets these headers.
			if gr.ObjInfo.VersionID != "" && gr.ObjInfo.DeleteMarker {
				w.Header()[xhttp.AmzVersionID] = []string{gr.ObjInfo.VersionID}
				w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(gr.ObjInfo.DeleteMarker)}
			}
		}
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	defer gr.Close()
	srcInfo := gr.ObjInfo

	// maximum Upload size for object in a single CopyObject operation.
	if isMaxObjectSize(srcInfo.Size) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL, guessIsBrowserReq(r))
		return
	}

	// We have to copy metadata only if source and destination are same.
	// this changes for encryption which can be observed below.
	if cpSrcDstSame {
		srcInfo.metadataOnly = true
	}

	var chStorageClass bool
	if dstSc != "" {
		chStorageClass = true
		srcInfo.metadataOnly = false
	}

	var reader io.Reader = gr

	// Set the actual size to the compressed/decrypted size if encrypted.
	actualSize, err := srcInfo.GetActualSize()
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	length := actualSize

	if !cpSrcDstSame {
		if err := enforceBucketQuota(ctx, dstBucket, actualSize); err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	// Check if either the source is encrypted or the destination will be encrypted.
	_, objectEncryption := crypto.IsRequested(r.Header)
	objectEncryption = objectEncryption || crypto.IsSourceEncrypted(srcInfo.UserDefined)

	var compressMetadata map[string]string
	// No need to compress for remote etcd calls
	// Pass the decompressed stream to such calls.
	isDstCompressed := objectAPI.IsCompressionSupported() &&
		isCompressible(r.Header, dstObject) && !cpSrcDstSame && !objectEncryption
	if isDstCompressed {
		compressMetadata = make(map[string]string, 2)
		// Preserving the compression metadata.
		compressMetadata[ReservedMetadataPrefix+"compression"] = compressionAlgorithmV2
		compressMetadata[ReservedMetadataPrefix+"actual-size"] = strconv.FormatInt(actualSize, 10)

		s2c := newS2CompressReader(reader, actualSize)
		defer s2c.Close()
		reader = etag.Wrap(s2c, reader)
		length = -1
	} else {
		delete(srcInfo.UserDefined, ReservedMetadataPrefix+"compression")
		delete(srcInfo.UserDefined, ReservedMetadataPrefix+"actual-size")
		reader = gr
	}

	srcInfo.Reader, err = hash.NewReader(reader, length, "", "", actualSize)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	pReader := NewPutObjReader(srcInfo.Reader)

	// Handle encryption
	var encMetadata = make(map[string]string)
	if objectAPI.IsEncryptionSupported() {
		// Encryption parameters not applicable for this object.
		if _, ok := crypto.IsEncrypted(srcInfo.UserDefined); !ok && crypto.SSECopy.IsRequested(r.Header) {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, errInvalidEncryptionParameters), r.URL, guessIsBrowserReq(r))
			return
		}
		// Encryption parameters not present for this object.
		if crypto.SSEC.IsEncrypted(srcInfo.UserDefined) && !crypto.SSECopy.IsRequested(r.Header) {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidSSECustomerAlgorithm), r.URL, guessIsBrowserReq(r))
			return
		}

		var oldKey, newKey []byte
		var objEncKey crypto.ObjectKey
		sseCopyS3 := crypto.S3.IsEncrypted(srcInfo.UserDefined)
		sseCopyC := crypto.SSEC.IsEncrypted(srcInfo.UserDefined) && crypto.SSECopy.IsRequested(r.Header)
		sseC := crypto.SSEC.IsRequested(r.Header)
		sseS3 := crypto.S3.IsRequested(r.Header)

		isSourceEncrypted := sseCopyC || sseCopyS3
		isTargetEncrypted := sseC || sseS3

		if sseC {
			newKey, err = ParseSSECustomerRequest(r)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
		}

		// If src == dst and either
		// - the object is encrypted using SSE-C and two different SSE-C keys are present
		// - the object is encrypted using SSE-S3 and the SSE-S3 header is present
		// - the object storage class is not changing
		// then execute a key rotation.
		if cpSrcDstSame && (sseCopyC && sseC) && !chStorageClass {
			oldKey, err = ParseSSECopyCustomerRequest(r.Header, srcInfo.UserDefined)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}

			for k, v := range srcInfo.UserDefined {
				if strings.HasPrefix(strings.ToLower(k), ReservedMetadataPrefixLower) {
					encMetadata[k] = v
				}
			}

			// In case of SSE-S3 oldKey and newKey aren't used - the KMS manages the keys.
			if err = rotateKey(oldKey, newKey, srcBucket, srcObject, encMetadata); err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}

			// Since we are rotating the keys, make sure to update the metadata.
			srcInfo.metadataOnly = true
			srcInfo.keyRotation = true
		} else {
			if isSourceEncrypted || isTargetEncrypted {
				// We are not only copying just metadata instead
				// we are creating a new object at this point, even
				// if source and destination are same objects.
				if !srcInfo.keyRotation {
					srcInfo.metadataOnly = false
				}
			}

			// Calculate the size of the target object
			var targetSize int64

			switch {
			case isDstCompressed:
				targetSize = -1
			case !isSourceEncrypted && !isTargetEncrypted:
				targetSize, _ = srcInfo.GetActualSize()
			case isSourceEncrypted && isTargetEncrypted:
				objInfo := ObjectInfo{Size: actualSize}
				targetSize = objInfo.EncryptedSize()
			case !isSourceEncrypted && isTargetEncrypted:
				targetSize = srcInfo.EncryptedSize()
			case isSourceEncrypted && !isTargetEncrypted:
				targetSize, _ = srcInfo.DecryptedSize()
			}

			if isTargetEncrypted {
				var encReader io.Reader
				encReader, objEncKey, err = newEncryptReader(srcInfo.Reader, newKey, dstBucket, dstObject, encMetadata, sseS3)
				if err != nil {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
					return
				}
				reader = etag.Wrap(encReader, srcInfo.Reader)
			}

			if isSourceEncrypted {
				// Remove all source encrypted related metadata to
				// avoid copying them in target object.
				crypto.RemoveInternalEntries(srcInfo.UserDefined)
			}

			// do not try to verify encrypted content
			srcInfo.Reader, err = hash.NewReader(reader, targetSize, "", "", actualSize)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}

			if isTargetEncrypted {
				pReader, err = pReader.WithEncryption(srcInfo.Reader, &objEncKey)
				if err != nil {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
					return
				}
			}
		}
	}

	srcInfo.PutObjReader = pReader

	srcInfo.UserDefined, err = getCpObjMetadataFromHeader(ctx, r, srcInfo.UserDefined)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objTags := srcInfo.UserTags
	// If x-amz-tagging-directive header is REPLACE, get passed tags.
	if isDirectiveReplace(r.Header.Get(xhttp.AmzTagDirective)) {
		objTags = r.Header.Get(xhttp.AmzObjectTagging)
		if _, err := tags.ParseObjectTags(objTags); err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
		if GlobalIsGateway {
			srcInfo.UserDefined[xhttp.AmzTagDirective] = replaceDirective
		}
	}

	if objTags != "" {
		srcInfo.UserDefined[xhttp.AmzObjectTagging] = objTags
	}
	srcInfo.UserDefined = filterReplicationStatusMetadata(srcInfo.UserDefined)

	srcInfo.UserDefined = objectlock.FilterObjectLockMetadata(srcInfo.UserDefined, true, true)
	retPerms := isPutActionAllowed(ctx, getRequestAuthType(r), dstBucket, dstObject, r, iampolicy.PutObjectRetentionAction)

	dstOpts.IfNoneMatch = r.Header.Values(xhttp.IfNoneMatch)

	// apply default bucket configuration/governance headers for dest side.
	retentionMode, retentionDate, legalHold, s3Err := parseObjectLockHeaders(ctx, r, dstBucket, dstObject, retPerms)
	if s3Err == ErrNone {
		if retentionMode.Valid() {
			if dstOpts.Retention == nil {
				dstOpts.Retention = &objectlock.ObjectRetention{}
			}
			dstOpts.Retention.Mode = retentionMode
			dstOpts.Retention.RetainUntilDate = retentionDate
		}
		if legalHold.Status.Valid() {
			dstOpts.LegalHold = &legalHold.Status
		}
	}

	if s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}
	if rs := r.Header.Get(xhttp.AmzBucketReplicationStatus); rs != "" {
		srcInfo.UserDefined[xhttp.AmzBucketReplicationStatus] = rs
	}
	if ok, _ := mustReplicate(ctx, r, dstBucket, dstObject, srcInfo.UserDefined, srcInfo.ReplicationStatus.String()); ok {
		srcInfo.UserDefined[xhttp.AmzBucketReplicationStatus] = replication.Pending.String()
	}
	// Store the preserved compression metadata.
	for k, v := range compressMetadata {
		srcInfo.UserDefined[k] = v
	}

	// We need to preserve the encryption headers set in EncryptRequest,
	// so we do not want to override them, copy them instead.
	for k, v := range encMetadata {
		srcInfo.UserDefined[k] = v
	}

	// Ensure that metadata does not contain sensitive information
	crypto.RemoveSensitiveEntries(srcInfo.UserDefined)

	// If we see legacy source, metadataOnly we have to overwrite the content.
	if srcInfo.Legacy {
		srcInfo.metadataOnly = false
	}

	// Check if x-amz-metadata-directive or x-amz-tagging-directive was not set to REPLACE and source,
	// destination are same objects. Apply this restriction also when
	// metadataOnly is true indicating that we are not overwriting the object.
	// if encryption is enabled we do not need explicit "REPLACE" metadata to
	// be enabled as well - this is to allow for key-rotation.
	if !isDirectiveReplace(r.Header.Get(xhttp.AmzMetadataDirective)) && !isDirectiveReplace(r.Header.Get(xhttp.AmzTagDirective)) &&
		srcInfo.metadataOnly && srcOpts.VersionID == "" && !objectEncryption {
		// If x-amz-metadata-directive is not set to REPLACE then we need
		// to error out if source and destination are same.
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopyDest), r.URL, guessIsBrowserReq(r))
		return
	}

	copyObjectFn := objectAPI.CopyObject
	if api.CacheAPI() != nil {
		copyObjectFn = api.CacheAPI().CopyObject
	}

	// Copy source object to destination, if source and destination
	// object is same then only metadata is updated.
	objInfo, err := copyObjectFn(ctx, srcBucket, srcObject, dstBucket, dstObject, srcInfo, srcOpts, dstOpts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	objInfo.ETag = getDecryptedETag(r.Header, objInfo, false)
	response := generateCopyObjectResponse(objInfo.ETag, objInfo.ModTime)
	encodedSuccessResponse := EncodeResponse(response)
	if replicate, sync := mustReplicate(ctx, r, dstBucket, dstObject, objInfo.UserDefined, objInfo.ReplicationStatus.String()); replicate {
		scheduleReplication(ctx, objInfo.Clone(), objectAPI, sync, replication.ObjectReplicationType)
	}

	setPutObjHeaders(w, objInfo, false)
	// We must not use the http.Header().Set method here because some (broken)
	// clients expect the x-amz-copy-source-version-id header key to be literally
	// "x-amz-copy-source-version-id"- not in canonicalized form, preserve it.
	if srcOpts.VersionID != "" {
		w.Header()[strings.ToLower(xhttp.AmzCopySourceVersionID)] = []string{srcOpts.VersionID}
	}

	// Write success response.
	WriteSuccessResponseXML(w, encodedSuccessResponse)

	// Notify object created event.
	sendEvent(eventArgs{
		EventName:    event.ObjectCreatedCopy,
		BucketName:   dstBucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

// PutObjectHandler - PUT Object
// ----------
// This implementation of the PUT operation adds an object to a bucket.
// Notice: The S3 client can send secret keys in headers for encryption related jobs,
// the handler should ensure to remove these keys before sending them to the object layer.
// Currently these keys are:
//   - X-Amz-Server-Side-Encryption-Customer-Key
//   - X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key
func (api ObjectAPIHandlers) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutObject")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := crypto.IsRequested(r.Header); ok {
		if GlobalIsGateway {
			if crypto.SSEC.IsRequested(r.Header) && !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		} else {
			if !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// X-Amz-Copy-Source shouldn't be set for this call.
	if _, ok := r.Header[xhttp.AmzCopySource]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL, guessIsBrowserReq(r))
		return
	}

	// Validate storage class metadata if present
	if sc := r.Header.Get(xhttp.AmzStorageClass); sc != "" {
		// Allow ONEZONE here only, we don't want to make it valid elsewhere
		if sc != storageclass.ONEZONE && !storageclass.IsValid(sc) {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	clientETag, err := etag.FromContentMD5(r.Header)
	if err != nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidDigest), r.URL, guessIsBrowserReq(r))
		return
	}

	/// if Content-Length is unknown/missing, deny the request
	size := r.ContentLength
	// S3 appears to error if a Content-Length header is missing, regardless of
	// determinable length.
	if _, err := strconv.ParseInt(r.Header.Get(xhttp.ContentLength), 10, 64); err != nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
		return
	}
	rAuthType := getRequestAuthType(r)
	if rAuthType == authTypeStreamingSigned {
		if sizeStr, ok := r.Header[xhttp.AmzDecodedContentLength]; ok {
			if sizeStr[0] == "" {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
				return
			}
			size, err = strconv.ParseInt(sizeStr[0], 10, 64)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}
	if size == -1 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
		return
	}

	/// maximum Upload size for objects in a single operation
	if isMaxObjectSize(size) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL, guessIsBrowserReq(r))
		return
	}

	metadata, err := extractMetadata(ctx, r)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Convert ONEZONE storage class to STANDARD (unset)
	if val, exists := metadata[xhttp.AmzStorageClass]; exists && val == storageclass.ONEZONE {
		delete(metadata, xhttp.AmzStorageClass)
	}

	if objTags := r.Header.Get(xhttp.AmzObjectTagging); objTags != "" {
		if !objectAPI.IsTaggingSupported() {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
			return
		}

		if _, err := tags.ParseObjectTags(objTags); err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}

		metadata[xhttp.AmzObjectTagging] = objTags
	}

	var (
		md5hex              = clientETag.String()
		sha256hex           = ""
		reader    io.Reader = r.Body
		s3Err     APIErrorCode
		putObject = objectAPI.PutObject
	)

	// Check if put is allowed
	if s3Err = isPutActionAllowed(ctx, rAuthType, bucket, object, r, iampolicy.PutObjectAction); s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	switch rAuthType {
	case authTypeStreamingSigned:
		// Initialize stream signature verifier.
		reader, s3Err = newSignV4ChunkedReader(r)
		if s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}
	case authTypeSignedV2, authTypePresignedV2:
		s3Err = isReqAuthenticatedV2(r)
		if s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}

	case authTypePresigned, authTypeSigned:
		if s3Err = reqSignatureV4Verify(r, globalServerRegion, serviceS3); s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}
		if !skipContentSha256Cksum(r) {
			sha256hex = getContentSha256Cksum(r, serviceS3)
		}
	}

	if err := enforceBucketQuota(ctx, bucket, size); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Check if bucket encryption is enabled
	_, err = globalBucketSSEConfigSys.Get(bucket)
	// This request header needs to be set prior to setting ObjectOptions
	if (globalAutoEncryption || err == nil) && !crypto.SSEC.IsRequested(r.Header) {
		r.Header.Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
	}

	actualSize := size
	if objectAPI.IsCompressionSupported() && isCompressible(r.Header, object) && size > 0 {
		// Storing the compression metadata.
		metadata[ReservedMetadataPrefix+"compression"] = compressionAlgorithmV2
		metadata[ReservedMetadataPrefix+"actual-size"] = strconv.FormatInt(size, 10)

		actualReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize)
		if err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}

		// Set compression metrics.
		s2c := newS2CompressReader(actualReader, actualSize)
		defer s2c.Close()
		reader = etag.Wrap(s2c, actualReader)
		size = -1   // Since compressed size is un-predictable.
		md5hex = "" // Do not try to verify the content.
		sha256hex = ""
	}

	hashReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	rawReader := hashReader
	pReader := NewPutObjReader(rawReader)

	// get gateway encryption options
	var opts ObjectOptions
	opts, err = putOpts(ctx, r, bucket, object, metadata)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if api.CacheAPI() != nil {
		putObject = api.CacheAPI().PutObject
	}

	retPerms := isPutActionAllowed(ctx, getRequestAuthType(r), bucket, object, r, iampolicy.PutObjectRetentionAction)

	opts.IfNoneMatch = r.Header.Values(xhttp.IfNoneMatch)

	retentionMode, retentionDate, legalHold, s3Err := parseObjectLockHeaders(ctx, r, bucket, object, retPerms)
	if s3Err == ErrNone {
		if retentionMode.Valid() {
			if opts.Retention == nil {
				opts.Retention = &objectlock.ObjectRetention{}
			}
			opts.Retention.Mode = retentionMode
			opts.Retention.RetainUntilDate = retentionDate
		}
		if legalHold.Status.Valid() {
			opts.LegalHold = &legalHold.Status
		}
	}

	if s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	if ok, _ := mustReplicate(ctx, r, bucket, object, metadata, ""); ok {
		metadata[xhttp.AmzBucketReplicationStatus] = replication.Pending.String()
	}
	if r.Header.Get(xhttp.AmzBucketReplicationStatus) == replication.Replica.String() {
		if s3Err = isPutActionAllowed(ctx, getRequestAuthType(r), bucket, object, r, iampolicy.ReplicateObjectAction); s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}
	}
	var objectEncryptionKey crypto.ObjectKey
	if objectAPI.IsEncryptionSupported() {
		if _, ok := crypto.IsRequested(r.Header); ok && !HasSuffix(object, SlashSeparator) { // handle SSE requests
			if crypto.SSECopy.IsRequested(r.Header) {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, errInvalidEncryptionParameters), r.URL, guessIsBrowserReq(r))
				return
			}

			reader, objectEncryptionKey, err = EncryptRequest(hashReader, r, bucket, object, metadata)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}

			wantSize := int64(-1)
			if size >= 0 {
				info := ObjectInfo{Size: size}
				wantSize = info.EncryptedSize()
			}

			// do not try to verify encrypted content
			hashReader, err = hash.NewReader(etag.Wrap(reader, hashReader), wantSize, "", "", actualSize)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
			pReader, err = pReader.WithEncryption(hashReader, &objectEncryptionKey)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	// Ensure that metadata does not contain sensitive information
	crypto.RemoveSensitiveEntries(metadata)

	// Create the object..
	objInfo, err := putObject(ctx, bucket, object, pReader, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	switch kind, encrypted := crypto.IsEncrypted(objInfo.UserDefined); {
	case encrypted:
		switch kind {
		case crypto.S3:
			w.Header().Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
			objInfo.ETag, _ = DecryptETag(objectEncryptionKey, ObjectInfo{ETag: objInfo.ETag})
		case crypto.SSEC:
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerAlgorithm, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerAlgorithm))
			w.Header().Set(xhttp.AmzServerSideEncryptionCustomerKeyMD5, r.Header.Get(xhttp.AmzServerSideEncryptionCustomerKeyMD5))

			if len(objInfo.ETag) >= 32 && strings.Count(objInfo.ETag, "-") != 1 {
				objInfo.ETag = objInfo.ETag[len(objInfo.ETag)-32:]
			}
		}
	case objInfo.IsCompressed():
		if !strings.HasSuffix(objInfo.ETag, "-1") {
			objInfo.ETag = objInfo.ETag + "-1"
		}
	}
	if replicate, sync := mustReplicate(ctx, r, bucket, object, metadata, ""); replicate {
		scheduleReplication(ctx, objInfo.Clone(), objectAPI, sync, replication.ObjectReplicationType)
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

// PutObjectExtractHandler - PUT Object extract is an extended API
// based off from AWS Snowball feature to auto extract compressed
// stream will be extracted in the same directory it is stored in
// and the folder structures will be built out accordingly.
func (api ObjectAPIHandlers) PutObjectExtractHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutObjectExtract")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := crypto.IsRequested(r.Header); ok {
		if GlobalIsGateway {
			if crypto.SSEC.IsRequested(r.Header) && !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		} else {
			if !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// X-Amz-Copy-Source shouldn't be set for this call.
	if _, ok := r.Header[xhttp.AmzCopySource]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL, guessIsBrowserReq(r))
		return
	}

	// Validate storage class metadata if present
	sc := r.Header.Get(xhttp.AmzStorageClass)
	if sc != "" {
		if !storageclass.IsValid(sc) {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	clientETag, err := etag.FromContentMD5(r.Header)
	if err != nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidDigest), r.URL, guessIsBrowserReq(r))
		return
	}

	/// if Content-Length is unknown/missing, deny the request
	size := r.ContentLength
	rAuthType := getRequestAuthType(r)
	if rAuthType == authTypeStreamingSigned {
		if sizeStr, ok := r.Header[xhttp.AmzDecodedContentLength]; ok {
			if sizeStr[0] == "" {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
				return
			}
			size, err = strconv.ParseInt(sizeStr[0], 10, 64)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	if size == -1 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
		return
	}

	/// maximum Upload size for objects in a single operation
	if isMaxObjectSize(size) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL, guessIsBrowserReq(r))
		return
	}

	var (
		md5hex              = clientETag.String()
		sha256hex           = ""
		reader    io.Reader = r.Body
		s3Err     APIErrorCode
		putObject = objectAPI.PutObject
	)

	// Check if put is allowed
	if s3Err = isPutActionAllowed(ctx, rAuthType, bucket, object, r, iampolicy.PutObjectAction); s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	switch rAuthType {
	case authTypeStreamingSigned:
		// Initialize stream signature verifier.
		reader, s3Err = newSignV4ChunkedReader(r)
		if s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}
	case authTypeSignedV2, authTypePresignedV2:
		s3Err = isReqAuthenticatedV2(r)
		if s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}

	case authTypePresigned, authTypeSigned:
		if s3Err = reqSignatureV4Verify(r, globalServerRegion, serviceS3); s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}
		if !skipContentSha256Cksum(r) {
			sha256hex = getContentSha256Cksum(r, serviceS3)
		}
	}

	hreader, err := hash.NewReader(reader, size, md5hex, sha256hex, size)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if err := enforceBucketQuota(ctx, bucket, size); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Check if bucket encryption is enabled
	_, err = globalBucketSSEConfigSys.Get(bucket)
	// This request header needs to be set prior to setting ObjectOptions
	if (globalAutoEncryption || err == nil) && !crypto.SSEC.IsRequested(r.Header) {
		r.Header.Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
	}

	retPerms := isPutActionAllowed(ctx, getRequestAuthType(r), bucket, object, r, iampolicy.PutObjectRetentionAction)

	if api.CacheAPI() != nil {
		putObject = api.CacheAPI().PutObject
	}

	putObjectTar := func(reader io.Reader, info os.FileInfo, object string) {
		size := info.Size()
		metadata := map[string]string{
			xhttp.AmzStorageClass: sc,
		}

		actualSize := size
		if objectAPI.IsCompressionSupported() && isCompressible(r.Header, object) && size > 0 {
			// Storing the compression metadata.
			metadata[ReservedMetadataPrefix+"compression"] = compressionAlgorithmV2
			metadata[ReservedMetadataPrefix+"actual-size"] = strconv.FormatInt(size, 10)

			actualReader, err := hash.NewReader(reader, size, "", "", actualSize)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}

			// Set compression metrics.
			s2c := newS2CompressReader(actualReader, actualSize)
			defer s2c.Close()
			reader = etag.Wrap(s2c, actualReader)
			size = -1 // Since compressed size is un-predictable.
		}

		hashReader, err := hash.NewReader(reader, size, "", "", actualSize)
		if err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}

		rawReader := hashReader
		pReader := NewPutObjReader(rawReader)

		// get encryption options
		opts, err := putOpts(ctx, r, bucket, object, metadata)
		if err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
		opts.MTime = info.ModTime()

		opts.IfNoneMatch = r.Header.Values(xhttp.IfNoneMatch)

		retentionMode, retentionDate, legalHold, s3Err := parseObjectLockHeaders(ctx, r, bucket, object, retPerms)
		if s3Err == ErrNone {
			if retentionMode.Valid() {
				if opts.Retention == nil {
					opts.Retention = &objectlock.ObjectRetention{}
				}
				opts.Retention.Mode = retentionMode
				opts.Retention.RetainUntilDate = retentionDate
			}
			if legalHold.Status.Valid() {
				opts.LegalHold = &legalHold.Status
			}
		}

		if s3Err != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
			return
		}

		if ok, _ := mustReplicate(ctx, r, bucket, object, metadata, ""); ok {
			metadata[xhttp.AmzBucketReplicationStatus] = replication.Pending.String()
		}

		if r.Header.Get(xhttp.AmzBucketReplicationStatus) == replication.Replica.String() {
			if s3Err = isPutActionAllowed(ctx, getRequestAuthType(r), bucket, object, r, iampolicy.ReplicateObjectAction); s3Err != ErrNone {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
				return
			}
		}

		var objectEncryptionKey crypto.ObjectKey
		if objectAPI.IsEncryptionSupported() {
			if _, ok := crypto.IsRequested(r.Header); ok && !HasSuffix(object, SlashSeparator) { // handle SSE requests
				if crypto.SSECopy.IsRequested(r.Header) {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, errInvalidEncryptionParameters), r.URL, guessIsBrowserReq(r))
					return
				}

				reader, objectEncryptionKey, err = EncryptRequest(hashReader, r, bucket, object, metadata)
				if err != nil {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
					return
				}

				wantSize := int64(-1)
				if size >= 0 {
					info := ObjectInfo{Size: size}
					wantSize = info.EncryptedSize()
				}

				// do not try to verify encrypted content
				hashReader, err = hash.NewReader(etag.Wrap(reader, hashReader), wantSize, "", "", actualSize)
				if err != nil {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
					return
				}

				pReader, err = pReader.WithEncryption(hashReader, &objectEncryptionKey)
				if err != nil {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
					return
				}
			}
		}

		// Ensure that metadata does not contain sensitive information
		crypto.RemoveSensitiveEntries(metadata)

		// Create the object..
		objInfo, err := putObject(ctx, bucket, object, pReader, opts)
		if err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}

		if replicate, sync := mustReplicate(ctx, r, bucket, object, metadata, ""); replicate {
			scheduleReplication(ctx, objInfo.Clone(), objectAPI, sync, replication.ObjectReplicationType)
		}

	}

	untar(hreader, putObjectTar)

	w.Header()[xhttp.ETag] = []string{`"` + hex.EncodeToString(hreader.MD5Current()) + `"`}
	writeSuccessResponseHeadersOnly(w)
}

/// Multipart ObjectAPIHandlers

// NewMultipartUploadHandler - New multipart upload.
// Notice: The S3 client can send secret keys in headers for encryption related jobs,
// the handler should ensure to remove these keys before sending them to the object layer.
// Currently these keys are:
//   - X-Amz-Server-Side-Encryption-Customer-Key
//   - X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key
func (api ObjectAPIHandlers) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "NewMultipartUpload")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := crypto.IsRequested(r.Header); ok {
		if GlobalIsGateway {
			if crypto.SSEC.IsRequested(r.Header) && !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		} else {
			if !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	// Check if bucket encryption is enabled
	_, err = globalBucketSSEConfigSys.Get(bucket)
	// This request header needs to be set prior to setting ObjectOptions
	if (globalAutoEncryption || err == nil) && !crypto.SSEC.IsRequested(r.Header) {
		r.Header.Set(xhttp.AmzServerSideEncryption, xhttp.AmzEncryptionAES)
	}

	// Validate storage class metadata if present
	if sc := r.Header.Get(xhttp.AmzStorageClass); sc != "" {
		if !storageclass.IsValid(sc) {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidStorageClass), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	var encMetadata = map[string]string{}

	if objectAPI.IsEncryptionSupported() {
		if _, ok := crypto.IsRequested(r.Header); ok {
			if err = setEncryptionMetadata(r, bucket, object, encMetadata); err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
			// Set this for multipart only operations, we need to differentiate during
			// decryption if the file was actually multipart or not.
			encMetadata[ReservedMetadataPrefix+"Encrypted-Multipart"] = ""
		}
	}

	// Extract metadata that needs to be saved.
	metadata, err := extractMetadata(ctx, r)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if ok, _ := mustReplicate(ctx, r, bucket, object, metadata, ""); ok {
		metadata[xhttp.AmzBucketReplicationStatus] = replication.Pending.String()
	}
	// We need to preserve the encryption headers set in EncryptRequest,
	// so we do not want to override them, copy them instead.
	for k, v := range encMetadata {
		metadata[k] = v
	}

	// Ensure that metadata does not contain sensitive information
	crypto.RemoveSensitiveEntries(metadata)

	if objectAPI.IsCompressionSupported() && isCompressible(r.Header, object) {
		// Storing the compression metadata.
		metadata[ReservedMetadataPrefix+"compression"] = compressionAlgorithmV2
	}

	opts, err := putOpts(ctx, r, bucket, object, metadata)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	retPerms := isPutActionAllowed(ctx, getRequestAuthType(r), bucket, object, r, iampolicy.PutObjectRetentionAction)

	retentionMode, retentionDate, legalHold, s3Err := parseObjectLockHeaders(ctx, r, bucket, object, retPerms)
	if s3Err == ErrNone {
		if retentionMode.Valid() {
			if opts.Retention == nil {
				opts.Retention = &objectlock.ObjectRetention{}
			}
			opts.Retention.Mode = retentionMode
			opts.Retention.RetainUntilDate = retentionDate
		}
		if legalHold.Status.Valid() {
			opts.LegalHold = &legalHold.Status
		}
	}

	if s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	uploadID, err := objectAPI.NewMultipartUpload(ctx, bucket, object, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	response := generateInitiateMultipartUploadResponse(bucket, object, uploadID)
	encodedSuccessResponse := EncodeResponse(response)

	// Write success response.
	WriteSuccessResponseXML(w, encodedSuccessResponse)
}

// CopyObjectPartHandler - uploads a part by copying data from an existing object as data source.
func (api ObjectAPIHandlers) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "CopyObjectPart")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	if _, ok := r.Header[http.CanonicalHeaderKey(xhttp.AmzCopySourceIfModifiedSince)]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[http.CanonicalHeaderKey(xhttp.AmzCopySourceIfUnmodifiedSince)]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[http.CanonicalHeaderKey(xhttp.AmzCopySourceIfNoneMatch)]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[http.CanonicalHeaderKey(xhttp.AmzCopySourceIfMatch)]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := r.Header[xhttp.AmzServerSideEncryptionCustomerAlgorithm]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[xhttp.AmzServerSideEncryptionCustomerKey]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[xhttp.AmzServerSideEncryptionCustomerKeyMD5]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[xhttp.AmzServerSideEncryptionCopyCustomerAlgorithm]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[xhttp.AmzServerSideEncryptionCopyCustomerKey]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[xhttp.AmzServerSideEncryptionCopyCustomerKeyMD5]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := r.Header[http.CanonicalHeaderKey("x-amz-request-payer")]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := r.Header[http.CanonicalHeaderKey("x-amz-expected-bucket-owner")]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}
	if _, ok := r.Header[http.CanonicalHeaderKey("x-amz-source-expected-bucket-owner")]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	vars := mux.Vars(r)
	dstBucket := vars["bucket"]
	dstObject, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, dstBucket, dstObject); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	// Read escaped copy source path to check for parameters.
	cpSrcPath := r.Header.Get(xhttp.AmzCopySource)
	var vid string
	if u, err := url.Parse(cpSrcPath); err == nil {
		vid = strings.TrimSpace(u.Query().Get(xhttp.VersionID))
		// Note that url.Parse does the unescaping
		cpSrcPath = u.Path
	}

	srcBucket, srcObject := path2BucketObject(cpSrcPath)
	// If source object is empty or bucket is empty, reply back invalid copy source.
	if srcObject == "" || srcBucket == "" {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, srcBucket, srcObject); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	uploadID := r.URL.Query().Get(xhttp.UploadID)
	partIDString := r.URL.Query().Get(xhttp.PartNumber)

	partID, err := strconv.Atoi(partIDString)
	if err != nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPart), r.URL, guessIsBrowserReq(r))
		return
	}

	// check partID with maximum part ID for multipart objects
	if isMaxPartID(partID) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMaxParts), r.URL, guessIsBrowserReq(r))
		return
	}

	startOffset, length := int64(0), int64(-1)

	// Get request range.
	if rangeHeader := r.Header.Get(xhttp.AmzCopySourceRange); rangeHeader != "" {
		if rs, err := parseCopyPartRangeSpec(rangeHeader); err != nil {
			logger.LogIf(ctx, err)
			writeCopyPartErr(ctx, w, err, r.URL, guessIsBrowserReq(r))
			return
		} else if rs != nil {
			startOffset, length = rs.Start, rs.End-rs.Start+1
		}
	}

	/// maximum copy size for multipart objects in a single operation
	if isMaxAllowedPartSize(length) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL, guessIsBrowserReq(r))
		return
	}

	partInfo, err := api.ObjectAPI().CopyObjectPart(
		ctx,
		srcBucket, srcObject, dstBucket, dstObject, uploadID,
		partID,
		startOffset, length,
		ObjectInfo{},
		ObjectOptions{VersionID: vid}, ObjectOptions{},
	)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	response := generateCopyObjectPartResponse(partInfo.ETag, partInfo.LastModified)
	encodedSuccessResponse := EncodeResponse(response)

	if vid != "" {
		w.Header().Set(xhttp.AmzCopySourceVersionID, vid)
	}

	// Write success response.
	WriteSuccessResponseXML(w, encodedSuccessResponse)
}

// PutObjectPartHandler - uploads an incoming part for an ongoing multipart operation.
func (api ObjectAPIHandlers) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutObjectPart")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if crypto.S3KMS.IsRequested(r.Header) { // SSE-KMS is not supported
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, ok := crypto.IsRequested(r.Header); ok {
		if GlobalIsGateway {
			if crypto.SSEC.IsRequested(r.Header) && !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		} else {
			if !objectAPI.IsEncryptionSupported() {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// X-Amz-Copy-Source shouldn't be set for this call.
	if _, ok := r.Header[xhttp.AmzCopySource]; ok {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidCopySource), r.URL, guessIsBrowserReq(r))
		return
	}

	clientETag, err := etag.FromContentMD5(r.Header)
	if err != nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidDigest), r.URL, guessIsBrowserReq(r))
		return
	}

	/// if Content-Length is unknown/missing, throw away
	size := r.ContentLength

	rAuthType := getRequestAuthType(r)
	// For auth type streaming signature, we need to gather a different content length.
	if rAuthType == authTypeStreamingSigned {
		if sizeStr, ok := r.Header[xhttp.AmzDecodedContentLength]; ok {
			if sizeStr[0] == "" {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
				return
			}
			size, err = strconv.ParseInt(sizeStr[0], 10, 64)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}
	if size == -1 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
		return
	}

	/// maximum Upload size for multipart objects in a single operation
	if isMaxAllowedPartSize(size) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEntityTooLarge), r.URL, guessIsBrowserReq(r))
		return
	}

	uploadID := r.URL.Query().Get(xhttp.UploadID)
	partIDString := r.URL.Query().Get(xhttp.PartNumber)

	partID, err := strconv.Atoi(partIDString)
	if err != nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPart), r.URL, guessIsBrowserReq(r))
		return
	}

	// check partID with maximum part ID for multipart objects
	if isMaxPartID(partID) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMaxParts), r.URL, guessIsBrowserReq(r))
		return
	}

	var (
		md5hex              = clientETag.String()
		sha256hex           = ""
		reader    io.Reader = r.Body
		s3Error   APIErrorCode
	)
	if s3Error = isPutActionAllowed(ctx, rAuthType, bucket, object, r, iampolicy.PutObjectAction); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	switch rAuthType {
	case authTypeStreamingSigned:
		// Initialize stream signature verifier.
		reader, s3Error = newSignV4ChunkedReader(r)
		if s3Error != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
			return
		}
	case authTypeSignedV2, authTypePresignedV2:
		if s3Error = isReqAuthenticatedV2(r); s3Error != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
			return
		}
	case authTypePresigned, authTypeSigned:
		if s3Error = reqSignatureV4Verify(r, globalServerRegion, serviceS3); s3Error != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
			return
		}

		if !skipContentSha256Cksum(r) {
			sha256hex = getContentSha256Cksum(r, serviceS3)
		}
	}

	if err := enforceBucketQuota(ctx, bucket, size); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	actualSize := size

	// get encryption options
	var opts ObjectOptions
	if crypto.SSEC.IsRequested(r.Header) {
		opts, err = getOpts(ctx, r, bucket, object)
		if err != nil {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	hashReader, err := hash.NewReader(reader, size, md5hex, sha256hex, actualSize)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	rawReader := hashReader
	pReader := NewPutObjReader(rawReader)

	putObjectPart := objectAPI.PutObjectPart

	partInfo, err := putObjectPart(ctx, bucket, object, uploadID, partID, pReader, opts)
	if err != nil {
		// Verify if the underlying error is signature mismatch.
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
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
func (api ObjectAPIHandlers) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "AbortMultipartUpload")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}
	abortMultipartUpload := objectAPI.AbortMultipartUpload

	if s3Error := checkRequestAuthType(ctx, r, policy.AbortMultipartUploadAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	uploadID, _, _, _, s3Error := getObjectResources(r.URL.Query())
	if s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}
	opts := ObjectOptions{}
	if err := abortMultipartUpload(ctx, bucket, object, uploadID, opts); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	writeSuccessNoContent(w)
}

// ListObjectPartsHandler - List object parts
func (api ObjectAPIHandlers) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "ListObjectParts")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.ListMultipartUploadPartsAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	uploadID, partNumberMarker, maxParts, encodingType, s3Error := getObjectResources(r.URL.Query())
	if s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}
	if partNumberMarker < 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPartNumberMarker), r.URL, guessIsBrowserReq(r))
		return
	}
	if maxParts < 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidMaxParts), r.URL, guessIsBrowserReq(r))
		return
	}

	opts := ObjectOptions{}
	listPartsInfo, err := objectAPI.ListObjectParts(ctx, bucket, object, uploadID, partNumberMarker, maxParts, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	var ssec bool
	if _, ok := crypto.IsEncrypted(listPartsInfo.UserDefined); ok && objectAPI.IsEncryptionSupported() {
		var key []byte
		if crypto.SSEC.IsEncrypted(listPartsInfo.UserDefined) {
			ssec = true
		}
		var objectEncryptionKey []byte
		if crypto.S3.IsEncrypted(listPartsInfo.UserDefined) {
			// Calculating object encryption key
			objectEncryptionKey, err = decryptObjectInfo(key, bucket, object, listPartsInfo.UserDefined)
			if err != nil {
				WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
				return
			}
		}
		for i := range listPartsInfo.Parts {
			curp := listPartsInfo.Parts[i]
			curp.ETag = tryDecryptETag(objectEncryptionKey, curp.ETag, ssec)
			if !ssec {
				var partSize uint64
				partSize, err = sio.DecryptedSize(uint64(curp.Size))
				if err != nil {
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
					return
				}
				curp.Size = int64(partSize)
			}
			listPartsInfo.Parts[i] = curp
		}
	}

	response := generateListPartsResponse(listPartsInfo, encodingType)
	encodedSuccessResponse := EncodeResponse(response)

	// Write success response.
	WriteSuccessResponseXML(w, encodedSuccessResponse)
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
func (api ObjectAPIHandlers) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "CompleteMultipartUpload")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	// Content-Length is required and should be non-zero
	if r.ContentLength <= 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
		return
	}

	// Get upload id.
	uploadID, _, _, _, s3Error := getObjectResources(r.URL.Query())
	if s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	complMultipartUpload := &CompleteMultipartUpload{}
	if err = xmlDecoder(r.Body, complMultipartUpload, r.ContentLength); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	if len(complMultipartUpload.Parts) == 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMalformedXML), r.URL, guessIsBrowserReq(r))
		return
	}
	if !sort.IsSorted(CompletedParts(complMultipartUpload.Parts)) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPartOrder), r.URL, guessIsBrowserReq(r))
		return
	}

	// Reject retention or governance headers if set, CompleteMultipartUpload spec
	// does not use these headers, and should not be passed down to parseObjectLockHeaders
	if objectlock.IsObjectLockRequested(r.Header) || objectlock.IsObjectLockGovernanceBypassSet(r.Header) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidRequest), r.URL, guessIsBrowserReq(r))
		return
	}

	if _, _, _, s3Err := parseObjectLockHeaders(ctx, r, bucket, object, ErrNone); s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Complete parts.
	completeParts := make([]CompletePart, 0, len(complMultipartUpload.Parts))
	for _, part := range complMultipartUpload.Parts {
		part.ETag = canonicalizeETag(part.ETag)
		completeParts = append(completeParts, part)
	}

	opts := ObjectOptions{
		IfNoneMatch: r.Header.Values(xhttp.IfNoneMatch),
	}

	completeMultiPartUpload := objectAPI.CompleteMultipartUpload

	// This code is specifically to handle the requirements for slow
	// complete multipart upload operations on FS mode.
	writeErrorResponseWithoutXMLHeader := func(ctx context.Context, w http.ResponseWriter, err APIError, reqURL *url.URL) {
		switch err.Code {
		case "SlowDown", "XMinioServerNotInitialized", "XMinioReadQuorum", "XMinioWriteQuorum":
			// Set retxry-after header to indicate user-agents to retry request after 120secs.
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
			w.Header().Set(xhttp.RetryAfter, storjRetryAfter)
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
	objInfo, err := completeMultiPartUpload(ctx, bucket, object, uploadID, completeParts, opts)
	// Stop writing white spaces to the client. Note that close(doneCh) style is not used as it
	// can cause white space to be written after we send XML response in a race condition.
	headerWritten := <-completeDoneCh
	if err != nil {
		if headerWritten {
			writeErrorResponseWithoutXMLHeader(ctx, w, ToAPIError(ctx, err), r.URL)
		} else {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		}
		return
	}

	// Get object location.
	location := getObjectLocation(r, globalDomainNames, bucket, object)
	// Generate complete multipart response.
	response := generateCompleteMultpartUploadResponse(bucket, object, location, objInfo.ETag)
	var encodedSuccessResponse []byte
	if !headerWritten {
		encodedSuccessResponse = EncodeResponse(response)
	} else {
		encodedSuccessResponse, err = xml.Marshal(response)
		if err != nil {
			writeErrorResponseWithoutXMLHeader(ctx, w, ToAPIError(ctx, err), r.URL)
			return
		}
	}

	setPutObjHeaders(w, objInfo, false)
	if replicate, sync := mustReplicate(ctx, r, bucket, object, objInfo.UserDefined, objInfo.ReplicationStatus.String()); replicate {
		scheduleReplication(ctx, objInfo.Clone(), objectAPI, sync, replication.ObjectReplicationType)
	}

	// Write success response.
	WriteSuccessResponseXML(w, encodedSuccessResponse)

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

/// Delete ObjectAPIHandlers

// DeleteObjectHandler - delete an object
func (api ObjectAPIHandlers) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "DeleteObject")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.DeleteObjectAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo
	if api.CacheAPI() != nil {
		getObjectInfo = api.CacheAPI().GetObjectInfo
	}

	opts, err := delOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	var (
		hasLockEnabled, hasLifecycleConfig bool
		goi                                ObjectInfo
		gerr                               error
	)
	replicateDeletes := hasReplicationRules(ctx, bucket, []ObjectToDelete{{ObjectName: object, VersionID: opts.VersionID}})
	if rcfg, _ := globalBucketObjectLockSys.Get(bucket); rcfg.LockEnabled {
		hasLockEnabled = true
	}
	if _, err := globalBucketMetadataSys.GetLifecycleConfig(bucket); err == nil {
		hasLifecycleConfig = true
	}
	if replicateDeletes || hasLockEnabled || hasLifecycleConfig {
		goi, gerr = getObjectInfo(ctx, bucket, object, ObjectOptions{
			VersionID: opts.VersionID,
		})
	}

	replicateDel, replicateSync := checkReplicateDelete(ctx, bucket, ObjectToDelete{ObjectName: object, VersionID: opts.VersionID}, goi, gerr)
	if replicateDel {
		if opts.VersionID != "" {
			opts.VersionPurgeStatus = Pending
		} else {
			opts.DeleteMarkerReplicationStatus = string(replication.Pending)
		}
	}

	vID := opts.VersionID
	if r.Header.Get(xhttp.AmzBucketReplicationStatus) == replication.Replica.String() {
		// check if replica has permission to be deleted.
		if apiErrCode := checkRequestAuthType(ctx, r, policy.ReplicateDeleteAction, bucket, object); apiErrCode != ErrNone {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(apiErrCode), r.URL, guessIsBrowserReq(r))
			return
		}
		opts.DeleteMarkerReplicationStatus = replication.Replica.String()
		if opts.VersionPurgeStatus.Empty() {
			// opts.VersionID holds delete marker version ID to replicate and not yet present on disk
			vID = ""
		}
	}

	apiErr := ErrNone
	if rcfg, _ := globalBucketObjectLockSys.Get(bucket); rcfg.LockEnabled {
		if vID != "" {
			apiErr = enforceRetentionBypassForDelete(ctx, r, bucket, ObjectToDelete{
				ObjectName: object,
				VersionID:  vID,
			}, goi, gerr)
			if apiErr != ErrNone && apiErr != ErrNoSuchKey {
				WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(apiErr), r.URL, guessIsBrowserReq(r))
				return
			}
		}
	}

	if apiErr == ErrNoSuchKey {
		writeSuccessNoContent(w)
		return
	}

	deleteObject := objectAPI.DeleteObject
	if api.CacheAPI() != nil {
		deleteObject = api.CacheAPI().DeleteObject
	}

	// http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectDELETE.html
	objInfo, err := deleteObject(ctx, bucket, object, opts)
	if err != nil {
		if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	if objInfo.Name == "" {
		writeSuccessNoContent(w)
		return
	}

	setPutObjHeaders(w, objInfo, true)
	writeSuccessNoContent(w)

	eventName := event.ObjectRemovedDelete
	if objInfo.DeleteMarker {
		eventName = event.ObjectRemovedDeleteMarkerCreated
	}

	// Notify object deleted event.
	sendEvent(eventArgs{
		EventName:    eventName,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})

	if replicateDel {
		dmVersionID := ""
		versionID := ""
		if objInfo.DeleteMarker {
			dmVersionID = objInfo.VersionID
		} else {
			versionID = objInfo.VersionID
		}
		dobj := DeletedObjectVersionInfo{
			DeletedObject: DeletedObject{
				ObjectName:                    object,
				VersionID:                     versionID,
				DeleteMarkerVersionID:         dmVersionID,
				DeleteMarkerReplicationStatus: string(objInfo.ReplicationStatus),
				DeleteMarkerMTime:             DeleteMarkerMTime{objInfo.ModTime},
				DeleteMarker:                  objInfo.DeleteMarker,
				VersionPurgeStatus:            objInfo.VersionPurgeStatus,
			},
			Bucket: bucket,
		}
		scheduleReplicationDelete(ctx, dobj, objectAPI, replicateSync)
	}

	if goi.TransitionStatus == lifecycle.TransitionComplete { // clean up transitioned tier
		deleteTransitionedObject(ctx, objectAPI, bucket, object, lifecycle.ObjectOpts{
			Name:             object,
			UserTags:         goi.UserTags,
			VersionID:        goi.VersionID,
			DeleteMarker:     goi.DeleteMarker,
			TransitionStatus: goi.TransitionStatus,
			IsLatest:         goi.IsLatest,
		}, false, true)
	}
}

// PutObjectLegalHoldHandler - set legal hold configuration to object,
func (api ObjectAPIHandlers) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutObjectLegalHold")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	// Check permissions to perform this legal hold operation
	if s3Err := checkRequestAuthType(ctx, r, policy.PutObjectLegalHoldAction, bucket, object); s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	if !hasContentMD5(r.Header) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentMD5), r.URL, guessIsBrowserReq(r))
		return
	}

	legalHold, err := objectlock.ParseObjectLegalHold(r.Body)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if err = objectAPI.SetObjectLegalHold(ctx, bucket, object, opts.VersionID, legalHold); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	writeSuccessResponseHeadersOnly(w)
}

// GetObjectLegalHoldHandler - get legal hold configuration to object,
func (api ObjectAPIHandlers) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetObjectLegalHold")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectLegalHoldAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	legalHold, err := objectAPI.GetObjectLegalHold(ctx, bucket, object, opts.VersionID)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if legalHold.IsEmpty() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNoSuchObjectLockConfiguration), r.URL, guessIsBrowserReq(r))
		return
	}

	WriteSuccessResponseXML(w, EncodeResponse(legalHold))
}

// PutObjectRetentionHandler - set object hold configuration to object,
func (api ObjectAPIHandlers) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutObjectRetention")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	_, _, _, s3Err := validateSignature(getRequestAuthType(r), r)
	if s3Err != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
		return
	}

	if !hasContentMD5(r.Header) {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentMD5), r.URL, guessIsBrowserReq(r))
		return
	}

	objRetention, err := objectlock.ParseObjectRetention(r.Body)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// if requesting governance bypass, object layer only removes the active
	// retention if retention is nil.
	governanceBypassSet := objectlock.IsObjectLockGovernanceBypassSet(r.Header)
	if governanceBypassSet && objRetention.Mode == "" && objRetention.RetainUntilDate.IsZero() {
		objRetention = nil
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if err = objectAPI.SetObjectRetention(ctx, bucket, object, opts.VersionID, ObjectOptions{
		Retention:                 objRetention,
		BypassGovernanceRetention: governanceBypassSet,
	}); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	writeSuccessResponseHeadersOnly(w)
}

// GetObjectRetentionHandler - get object retention configuration of object,
func (api ObjectAPIHandlers) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetObjectRetention")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectRetentionAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objRetention, err := objectAPI.GetObjectRetention(ctx, bucket, object, opts.VersionID)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if !objRetention.Mode.Valid() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNoSuchObjectLockConfiguration), r.URL, guessIsBrowserReq(r))
		return
	}

	WriteSuccessResponseXML(w, EncodeResponse(objRetention))
}

// GetObjectTaggingHandler - GET object tagging
func (api ObjectAPIHandlers) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetObjectTagging")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if !objAPI.IsTaggingSupported() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	// Allow getObjectTagging if policy action is set.
	if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectTaggingAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Get object tags
	tags, err := objAPI.GetObjectTags(ctx, bucket, object, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if opts.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{opts.VersionID}
	}

	WriteSuccessResponseXML(w, EncodeResponse(tags))
}

// PutObjectTaggingHandler - PUT object tagging
func (api ObjectAPIHandlers) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutObjectTagging")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}
	if !objAPI.IsTaggingSupported() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	// Allow putObjectTagging if policy action is set
	if s3Error := checkRequestAuthType(ctx, r, policy.PutObjectTaggingAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	tags, err := tags.ParseObjectXML(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	replicate, sync := mustReplicate(ctx, r, bucket, object, map[string]string{xhttp.AmzObjectTagging: tags.String()}, "")
	if replicate {
		opts.UserDefined = make(map[string]string)
		opts.UserDefined[xhttp.AmzBucketReplicationStatus] = replication.Pending.String()
	}

	tagsStr := tags.String()

	// Put object tags
	objInfo, err := objAPI.PutObjectTags(ctx, bucket, object, tagsStr, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if replicate {
		scheduleReplication(ctx, objInfo.Clone(), objAPI, sync, replication.MetadataReplicationType)
	}

	if objInfo.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{objInfo.VersionID}
	}

	writeSuccessResponseHeadersOnly(w)

	sendEvent(eventArgs{
		EventName:    event.ObjectCreatedPutTagging,
		BucketName:   bucket,
		Object:       objInfo,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})

}

// DeleteObjectTaggingHandler - DELETE object tagging
func (api ObjectAPIHandlers) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "DeleteObjectTagging")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objAPI := api.ObjectAPI()
	if objAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}
	if !objAPI.IsTaggingSupported() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Allow deleteObjectTagging if policy action is set
	if s3Error := checkRequestAuthType(ctx, r, policy.DeleteObjectTaggingAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	opts, err := getOpts(ctx, r, bucket, object)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	oi, err := objAPI.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	replicate, sync := mustReplicate(ctx, r, bucket, object, map[string]string{xhttp.AmzObjectTagging: oi.UserTags}, "")
	if replicate {
		opts.UserDefined = make(map[string]string)
		opts.UserDefined[xhttp.AmzBucketReplicationStatus] = replication.Pending.String()
	}

	oi, err = objAPI.DeleteObjectTags(ctx, bucket, object, opts)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if replicate {
		scheduleReplication(ctx, oi.Clone(), objAPI, sync, replication.MetadataReplicationType)
	}

	if oi.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{oi.VersionID}
	}
	writeSuccessNoContent(w)

	sendEvent(eventArgs{
		EventName:    event.ObjectCreatedDeleteTagging,
		BucketName:   bucket,
		Object:       oi,
		ReqParams:    extractReqParams(r),
		RespElements: extractRespElements(w),
		UserAgent:    r.UserAgent(),
		Host:         handlers.GetSourceIP(r),
	})
}

// RestoreObjectHandler - POST restore object handler.
// ----------
func (api ObjectAPIHandlers) PostRestoreObjectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PostRestoreObject")
	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object, err := unescapePath(vars["object"])
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Fetch object stat info.
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	getObjectInfo := objectAPI.GetObjectInfo
	if api.CacheAPI() != nil {
		getObjectInfo = api.CacheAPI().GetObjectInfo
	}

	// Check for auth type to return S3 compatible error.
	if s3Error := checkRequestAuthType(ctx, r, policy.RestoreObjectAction, bucket, object); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	if r.ContentLength <= 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrEmptyRequestBody), r.URL, guessIsBrowserReq(r))
		return
	}

	objInfo, err := getObjectInfo(ctx, bucket, object, ObjectOptions{})
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if objInfo.TransitionStatus != lifecycle.TransitionComplete {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidObjectState), r.URL, guessIsBrowserReq(r))
		return
	}

	rreq, err := parseRestoreRequest(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
		apiErr.Description = err.Error()
		WriteErrorResponse(ctx, w, apiErr, r.URL, guessIsBrowserReq(r))
		return
	}
	// validate the request
	if err := rreq.validate(ctx, objectAPI); err != nil {
		apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
		apiErr.Description = err.Error()
		WriteErrorResponse(ctx, w, apiErr, r.URL, guessIsBrowserReq(r))
		return
	}
	statusCode := http.StatusOK
	alreadyRestored := false
	if err == nil {
		if objInfo.RestoreOngoing && rreq.Type != SelectRestoreRequest {
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrObjectRestoreAlreadyInProgress), r.URL, guessIsBrowserReq(r))
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
			WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidObjectState), r.URL, guessIsBrowserReq(r))
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
					encodedErrorResponse := EncodeResponse(APIErrorResponse{
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
					WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
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
