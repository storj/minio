/*
 * MinIO Cloud Storage, (C) 2020 MinIO, Inc.
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
	"encoding/xml"
	"io"
	"net/http"

	humanize "github.com/dustin/go-humanize"
	"github.com/gorilla/mux"

	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/bucket/policy"
	"storj.io/minio/pkg/bucket/versioning"
)

const (
	bucketVersioningConfig = "versioning.xml"

	// Maximum size of bucket versioning configuration payload sent to the PutBucketVersioningHandler.
	maxBucketVersioningConfigSize = 1 * humanize.MiByte
)

// PutBucketVersioningHandler - PUT Bucket Versioning.
// ----------
func (api ObjectAPIHandlers) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutBucketVersioning")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketVersioningAction, bucket, ""); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	v, err := versioning.ParseConfig(io.LimitReader(r.Body, maxBucketVersioningConfigSize))
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	_, err = xml.Marshal(v)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if err = objectAPI.SetBucketVersioning(ctx, bucket, v); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	writeSuccessResponseHeadersOnly(w)
}

// GetBucketVersioningHandler - GET Bucket Versioning.
// ----------
func (api ObjectAPIHandlers) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetBucketVersioning")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucket := vars["bucket"]

	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketVersioningAction, bucket, ""); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	config, err := objectAPI.GetBucketVersioning(ctx, bucket)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	configData, err := xml.Marshal(config)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// Write bucket versioning configuration to client
	WriteSuccessResponseXML(w, configData)

}
