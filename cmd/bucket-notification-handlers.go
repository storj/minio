/*
 * MinIO Cloud Storage, (C) 2016, 2017, 2018 MinIO, Inc.
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
	"reflect"

	"github.com/gorilla/mux"

	"storj.io/minio/cmd/logger"
	"storj.io/minio/pkg/bucket/policy"
	"storj.io/minio/pkg/event"
)

const (
	bucketConfigPrefix       = "buckets"
	bucketNotificationConfig = "notification.xml"
)

// GetBucketNotificationHandler - This HTTP handler returns event notification configuration
// as per http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html.
// It returns empty configuration if its not set.
func (api ObjectAPIHandlers) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "GetBucketNotification")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	vars := mux.Vars(r)
	bucketName := vars["bucket"]

	objAPI := api.objectAPI()
	if objAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if !objAPI.IsNotificationSupported() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	if s3Error := checkRequestAuthType(ctx, r, policy.GetBucketNotificationAction, bucketName, ""); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	_, err := objAPI.GetBucketInfo(ctx, bucketName)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	config, err := globalBucketMetadataSys.GetNotificationConfig(bucketName)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}
	config.SetRegion(globalServerRegion)
	if err = config.Validate(globalServerRegion, GlobalNotificationSys.targetList); err != nil {
		arnErr, ok := err.(*event.ErrARNNotFound)
		if ok {
			for i, queue := range config.QueueList {
				// Remove ARN not found queues, because we previously allowed
				// adding unexpected entries into the config.
				//
				// With newer config disallowing changing / turning off
				// notification targets without removing ARN in notification
				// configuration we won't see this problem anymore.
				if reflect.DeepEqual(queue.ARN, arnErr.ARN) && i < len(config.QueueList) {
					config.QueueList = append(config.QueueList[:i],
						config.QueueList[i+1:]...)
				}
				// This is a one time activity we shall do this
				// here and allow stale ARN to be removed. We shall
				// never reach a stage where we will have stale
				// notification configs.
			}
		} else {
			WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
			return
		}
	}

	configData, err := xml.Marshal(config)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	WriteSuccessResponseXML(w, configData)
}

// PutBucketNotificationHandler - This HTTP handler stores given notification configuration as per
// http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html.
func (api ObjectAPIHandlers) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	ctx := NewContext(r, w, "PutBucketNotification")

	defer logger.AuditLog(ctx, w, r, mustGetClaimsFromToken(r))

	objectAPI := api.objectAPI()
	if objectAPI == nil {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrServerNotInitialized), r.URL, guessIsBrowserReq(r))
		return
	}

	if !objectAPI.IsNotificationSupported() {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrNotImplemented), r.URL, guessIsBrowserReq(r))
		return
	}

	vars := mux.Vars(r)
	bucketName := vars["bucket"]

	if s3Error := checkRequestAuthType(ctx, r, policy.PutBucketNotificationAction, bucketName, ""); s3Error != ErrNone {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Error), r.URL, guessIsBrowserReq(r))
		return
	}

	_, err := objectAPI.GetBucketInfo(ctx, bucketName)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	// PutBucketNotification always needs a Content-Length.
	if r.ContentLength <= 0 {
		WriteErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrMissingContentLength), r.URL, guessIsBrowserReq(r))
		return
	}

	config, err := event.ParseConfig(io.LimitReader(r.Body, r.ContentLength), globalServerRegion, GlobalNotificationSys.targetList)
	if err != nil {
		apiErr := errorCodes.ToAPIErr(ErrMalformedXML)
		if event.IsEventError(err) {
			apiErr = ToAPIError(ctx, err)
		}
		WriteErrorResponse(ctx, w, apiErr, r.URL, guessIsBrowserReq(r))
		return
	}

	configData, err := xml.Marshal(config)
	if err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	if err = globalBucketMetadataSys.Update(bucketName, bucketNotificationConfig, configData); err != nil {
		WriteErrorResponse(ctx, w, ToAPIError(ctx, err), r.URL, guessIsBrowserReq(r))
		return
	}

	rulesMap := config.ToRulesMap()
	GlobalNotificationSys.AddRulesMap(bucketName, rulesMap)

	writeSuccessResponseHeadersOnly(w)
}
