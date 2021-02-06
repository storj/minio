/*
 * MinIO Cloud Storage, (C) 2018, 2019 MinIO, Inc.
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
	"fmt"
	"net/url"

	"github.com/storj/minio/pkg/bucket/policy"
	"github.com/storj/minio/pkg/event"
)

type eventArgs struct {
	EventName    event.Name
	BucketName   string
	Object       ObjectInfo
	ReqParams    map[string]string
	RespElements map[string]string
	Host         string
	UserAgent    string
}

// ToEvent - converts to notification event.
func (args eventArgs) ToEvent(escape bool) event.Event {
	eventTime := UTCNow()
	uniqueID := fmt.Sprintf("%X", eventTime.UnixNano())

	respElements := map[string]string{
		"x-amz-request-id":        args.RespElements["requestId"],
		"x-minio-origin-endpoint": globalMinioEndpoint, // MinIO specific custom elements.
	}
	// Add deployment as part of
	if globalDeploymentID != "" {
		respElements["x-minio-deployment-id"] = globalDeploymentID
	}
	if args.RespElements["content-length"] != "" {
		respElements["content-length"] = args.RespElements["content-length"]
	}
	keyName := args.Object.Name
	if escape {
		keyName = url.QueryEscape(args.Object.Name)
	}
	newEvent := event.Event{
		EventVersion:      "2.0",
		EventSource:       "minio:s3",
		AwsRegion:         args.ReqParams["region"],
		EventTime:         eventTime.Format(event.AMZTimeFormat),
		EventName:         args.EventName,
		UserIdentity:      event.Identity{PrincipalID: args.ReqParams["accessKey"]},
		RequestParameters: args.ReqParams,
		ResponseElements:  respElements,
		S3: event.Metadata{
			SchemaVersion:   "1.0",
			ConfigurationID: "Config",
			Bucket: event.Bucket{
				Name:          args.BucketName,
				OwnerIdentity: event.Identity{PrincipalID: args.ReqParams["accessKey"]},
				ARN:           policy.ResourceARNPrefix + args.BucketName,
			},
			Object: event.Object{
				Key:       keyName,
				VersionID: args.Object.VersionID,
				Sequencer: uniqueID,
			},
		},
		Source: event.Source{
			Host:      args.Host,
			UserAgent: args.UserAgent,
		},
	}

	if args.EventName != event.ObjectRemovedDelete && args.EventName != event.ObjectRemovedDeleteMarkerCreated {
		newEvent.S3.Object.ETag = args.Object.ETag
		newEvent.S3.Object.Size = args.Object.Size
		newEvent.S3.Object.ContentType = args.Object.ContentType
		newEvent.S3.Object.UserMetadata = args.Object.UserDefined
	}

	return newEvent
}

func sendEvent(args eventArgs) {
	return
}
