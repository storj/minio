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
	"context"
	"io"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/tags"

	objectlock "storj.io/minio/pkg/bucket/object/lock"
	"storj.io/minio/pkg/bucket/policy"
	"storj.io/minio/pkg/bucket/versioning"
	"storj.io/minio/pkg/madmin"
)

// CheckPreconditionFn returns true if precondition check failed.
type CheckPreconditionFn func(o ObjectInfo) bool

// GetObjectInfoFn is the signature of GetObjectInfo function.
type GetObjectInfoFn func(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error)

// ObjectOptions represents object options for ObjectLayer object operations
type ObjectOptions struct {
	ServerSideEncryption encrypt.ServerSide
	VersionSuspended     bool           // indicates if the bucket was previously versioned but is currently suspended.
	Versioned            bool           // indicates if the bucket is versioned
	WalkVersions         bool           // indicates if the we are interested in walking versions
	VersionID            string         // Specifies the versionID which needs to be overwritten or read
	MTime                time.Time      // Is only set in POST/PUT operations
	Expires              time.Time      // Is only used in POST/PUT operations
	PostPolicy           PostPolicyForm // Is only used in POST/PUT operations

	Retention                 *objectlock.ObjectRetention // Optional retention configuration for the object
	BypassGovernanceRetention bool                        // Is only useful for DeleteObject(s)
	LegalHold                 *objectlock.LegalHoldStatus // Optional legal hold status for the object

	IfNoneMatch []string // Optional for conditional operations

	DeleteMarker                  bool                                                  // Is only set in DELETE operations for delete marker replication
	UserDefined                   map[string]string                                     // only set in case of POST/PUT operations
	PartNumber                    int                                                   // only useful in case of GetObject/HeadObject
	CheckPrecondFn                CheckPreconditionFn                                   // only set during GetObject/HeadObject/CopyObjectPart preconditional valuation
	DeleteMarkerReplicationStatus string                                                // Is only set in DELETE operations
	VersionPurgeStatus            VersionPurgeStatusType                                // Is only set in DELETE operations for delete marker version to be permanently deleted.
	TransitionStatus              string                                                // status of the transition
	NoLock                        bool                                                  // indicates to lower layers if the caller is expecting to hold locks.
	ProxyRequest                  bool                                                  // only set for GET/HEAD in active-active replication scenario
	ProxyHeaderSet                bool                                                  // only set for GET/HEAD in active-active replication scenario
	ParentIsObject                func(ctx context.Context, bucket, parent string) bool // Used to verify if parent is an object.
	Quiet                         bool                                                  // Is only useful for DeleteObjects

	// Use the maximum parity (N/2), used when
	// saving server configuration files
	MaxParity bool
}

// BucketOptions represents bucket options for ObjectLayer bucket operations
type BucketOptions struct {
	Location          string
	LockEnabled       bool
	VersioningEnabled bool
}

// LockType represents required locking for ObjectLayer operations
type LockType int

const (
	noLock LockType = iota
	readLock
	writeLock
)

// BackendMetrics - represents bytes served from backend
type BackendMetrics struct {
	bytesReceived uint64
	bytesSent     uint64
	requestStats  RequestStats
}

// ObjectLayer implements primitives for object API layer.
type ObjectLayer interface {
	// Locking operations on object.
	NewNSLock(bucket string, objects ...string) RWLocker

	// Storage operations.
	Shutdown(context.Context) error
	NSScanner(ctx context.Context, bf *BloomFilter, updates chan<- madmin.DataUsageInfo) error

	BackendInfo() madmin.BackendInfo
	StorageInfo(ctx context.Context) (StorageInfo, []error)
	LocalStorageInfo(ctx context.Context) (StorageInfo, []error)

	// Bucket operations.
	MakeBucketWithLocation(ctx context.Context, bucket string, opts BucketOptions) error
	GetBucketInfo(ctx context.Context, bucket string) (bucketInfo BucketInfo, err error)
	ListBuckets(ctx context.Context) (buckets []BucketInfo, err error)
	DeleteBucket(ctx context.Context, bucket string, forceDelete bool) error
	ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (result ListObjectsInfo, err error)
	ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, fetchOwner bool, startAfter string) (result ListObjectsV2Info, err error)
	ListObjectVersions(ctx context.Context, bucket, prefix, marker, versionMarker, delimiter string, maxKeys int) (result ListObjectVersionsInfo, err error)
	// Walk lists all objects including versions, delete markers.
	Walk(ctx context.Context, bucket, prefix string, results chan<- ObjectInfo, opts ObjectOptions) error

	SetBucketVersioning(ctx context.Context, bucket string, versioning *versioning.Versioning) (err error)
	GetBucketVersioning(ctx context.Context, bucket string) (*versioning.Versioning, error)

	GetBucketTagging(ctx context.Context, bucket string) (*tags.Tags, error)
	SetBucketTagging(ctx context.Context, bucket string, tags *tags.Tags) error

	GetObjectLockConfig(ctx context.Context, bucket string) (*objectlock.Config, error)
	SetObjectLockConfig(ctx context.Context, bucket string, config *objectlock.Config) error

	// Object operations.

	// GetObjectNInfo returns a GetObjectReader that satisfies the
	// ReadCloser interface. The Close method unlocks the object
	// after reading, so it must always be called after usage.
	//
	// IMPORTANTLY, when implementations return err != nil, this
	// function MUST NOT return a non-nil ReadCloser.
	GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (reader *GetObjectReader, err error)
	GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error)
	PutObject(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error)
	CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error)
	DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error)
	DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []DeleteObjectsError, error)

	SetObjectRetention(ctx context.Context, bucket, object, versionID string, opts ObjectOptions) (err error)
	GetObjectRetention(ctx context.Context, bucket, object, versionID string) (*objectlock.ObjectRetention, error)

	SetObjectLegalHold(ctx context.Context, bucket, object, versionID string, legalHold *objectlock.ObjectLegalHold) (err error)
	GetObjectLegalHold(ctx context.Context, bucket, object, versionID string) (*objectlock.ObjectLegalHold, error)

	// Multipart operations.
	ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (result ListMultipartsInfo, err error)
	NewMultipartUpload(ctx context.Context, bucket, object string, opts ObjectOptions) (uploadID string, err error)
	CopyObjectPart(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, uploadID string, partID int,
		startOffset int64, length int64, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (info PartInfo, err error)
	PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *PutObjReader, opts ObjectOptions) (info PartInfo, err error)
	GetMultipartInfo(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) (info MultipartInfo, err error)
	ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker int, maxParts int, opts ObjectOptions) (result ListPartsInfo, err error)
	AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) error
	CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []CompletePart, opts ObjectOptions) (objInfo ObjectInfo, err error)

	// Policy operations
	SetBucketPolicy(context.Context, string, *policy.Policy) error
	GetBucketPolicy(context.Context, string) (*policy.Policy, error)
	DeleteBucketPolicy(context.Context, string) error

	// Supported operations check
	IsNotificationSupported() bool
	IsListenSupported() bool
	IsEncryptionSupported() bool
	IsTaggingSupported() bool
	IsCompressionSupported() bool

	SetDriveCounts() []int // list of erasure stripe size for each pool in order.

	// Healing operations.
	HealFormat(ctx context.Context, dryRun bool) (madmin.HealResultItem, error)
	HealBucket(ctx context.Context, bucket string, opts madmin.HealOpts) (madmin.HealResultItem, error)
	HealObject(ctx context.Context, bucket, object, versionID string, opts madmin.HealOpts) (madmin.HealResultItem, error)
	HealObjects(ctx context.Context, bucket, prefix string, opts madmin.HealOpts, fn HealObjectFn) error

	// Backend related metrics
	GetMetrics(ctx context.Context) (*BackendMetrics, error)

	// Returns health of the backend
	Health(ctx context.Context, opts HealthOptions) HealthResult
	ReadHealth(ctx context.Context) bool

	// Metadata operations
	PutObjectMetadata(context.Context, string, string, ObjectOptions) (ObjectInfo, error)

	// ObjectTagging operations
	PutObjectTags(context.Context, string, string, string, ObjectOptions) (ObjectInfo, error)
	GetObjectTags(context.Context, string, string, ObjectOptions) (*tags.Tags, error)
	DeleteObjectTags(context.Context, string, string, ObjectOptions) (ObjectInfo, error)
}

// GetObject - TODO(aead): This function just acts as an adapter for GetObject tests and benchmarks
// since the GetObject method of the ObjectLayer interface has been removed. Once, the
// tests are adjusted to use GetObjectNInfo this function can be removed.
func GetObject(ctx context.Context, api ObjectLayer, bucket, object string, startOffset int64, length int64, writer io.Writer, etag string, opts ObjectOptions) (err error) {
	var header http.Header
	if etag != "" {
		header.Set("ETag", etag)
	}
	Range := &HTTPRangeSpec{Start: startOffset, End: startOffset + length}

	reader, err := api.GetObjectNInfo(ctx, bucket, object, Range, header, readLock, opts)
	if err != nil {
		return err
	}
	defer reader.Close()

	_, err = io.Copy(writer, reader)
	return err
}
