/*
 * MinIO Cloud Storage, (C) 2019 MinIO, Inc.
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

package http

// Standard S3 HTTP response constants
const (
	LastModified       = "Last-Modified"
	Date               = "Date"
	ETag               = "ETag"
	ContentType        = "Content-Type"
	ContentMD5         = "Content-Md5"
	ContentEncoding    = "Content-Encoding"
	Expires            = "Expires"
	ContentLength      = "Content-Length"
	ContentLanguage    = "Content-Language"
	ContentRange       = "Content-Range"
	Connection         = "Connection"
	AcceptRanges       = "Accept-Ranges"
	AmzBucketRegion    = "X-Amz-Bucket-Region"
	ServerInfo         = "Server"
	RetryAfter         = "Retry-After"
	Location           = "Location"
	CacheControl       = "Cache-Control"
	ContentDisposition = "Content-Disposition"
	Authorization      = "Authorization"
	Action             = "Action"
	Range              = "Range"
)

// Non standard S3 HTTP response constants
const (
	XCache       = "X-Cache"
	XCacheLookup = "X-Cache-Lookup"
)

// Standard S3 HTTP request constants
const (
	IfModifiedSince   = "If-Modified-Since"
	IfUnmodifiedSince = "If-Unmodified-Since"
	IfMatch           = "If-Match"
	IfNoneMatch       = "If-None-Match"

	// S3 storage class
	AmzStorageClass = "x-amz-storage-class"

	// S3 object version ID
	AmzVersionID    = "x-amz-version-id"
	AmzDeleteMarker = "x-amz-delete-marker"

	// S3 object tagging
	AmzObjectTagging = "X-Amz-Tagging"
	AmzTagCount      = "x-amz-tagging-count"
	AmzTagDirective  = "X-Amz-Tagging-Directive"

	// S3 transition restore
	AmzRestore            = "x-amz-restore"
	AmzRestoreExpiryDays  = "X-Amz-Restore-Expiry-Days"
	AmzRestoreRequestDate = "X-Amz-Restore-Request-Date"
	AmzRestoreOutputPath  = "x-amz-restore-output-path"

	// S3 extensions
	AmzCopySourceIfModifiedSince   = "x-amz-copy-source-if-modified-since"
	AmzCopySourceIfUnmodifiedSince = "x-amz-copy-source-if-unmodified-since"

	AmzCopySourceIfNoneMatch = "x-amz-copy-source-if-none-match"
	AmzCopySourceIfMatch     = "x-amz-copy-source-if-match"

	AmzCopySource                 = "X-Amz-Copy-Source"
	AmzCopySourceVersionID        = "X-Amz-Copy-Source-Version-Id"
	AmzCopySourceRange            = "X-Amz-Copy-Source-Range"
	AmzMetadataDirective          = "X-Amz-Metadata-Directive"
	AmzObjectLockMode             = "X-Amz-Object-Lock-Mode"
	AmzObjectLockRetainUntilDate  = "X-Amz-Object-Lock-Retain-Until-Date"
	AmzObjectLockLegalHold        = "X-Amz-Object-Lock-Legal-Hold"
	AmzObjectLockBypassGovernance = "X-Amz-Bypass-Governance-Retention"
	AmzBucketReplicationStatus    = "X-Amz-Replication-Status"
	AmzSnowballExtract            = "X-Amz-Meta-Snowball-Auto-Extract"

	// Multipart parts count
	AmzMpPartsCount = "x-amz-mp-parts-count"

	// Object date/time of expiration
	AmzExpiration = "x-amz-expiration"

	// Dummy putBucketACL
	AmzACL = "x-amz-acl"

	// Signature V4 related contants.
	AmzContentSha256        = "X-Amz-Content-Sha256"
	AmzDate                 = "X-Amz-Date"
	AmzAlgorithm            = "X-Amz-Algorithm"
	AmzExpires              = "X-Amz-Expires"
	AmzSignedHeaders        = "X-Amz-SignedHeaders"
	AmzSignature            = "X-Amz-Signature"
	AmzCredential           = "X-Amz-Credential"
	AmzSecurityToken        = "X-Amz-Security-Token"
	AmzDecodedContentLength = "X-Amz-Decoded-Content-Length"

	// GetObjectAttributes header and request attributes.
	AmzObjectAttributes = "X-Amz-Object-Attributes"
	StorageClass        = "StorageClass"
	ObjectSize          = "ObjectSize"
	Checksum            = "Checksum"
	ObjectParts         = "ObjectParts"

	AmzMetaUnencryptedContentLength = "X-Amz-Meta-X-Amz-Unencrypted-Content-Length"
	AmzMetaUnencryptedContentMD5    = "X-Amz-Meta-X-Amz-Unencrypted-Content-Md5"

	// AWS server-side encryption headers for SSE-S3, SSE-KMS and SSE-C.
	AmzServerSideEncryption                      = "X-Amz-Server-Side-Encryption"
	AmzServerSideEncryptionKmsID                 = AmzServerSideEncryption + "-Aws-Kms-Key-Id"
	AmzServerSideEncryptionKmsContext            = AmzServerSideEncryption + "-Context"
	AmzServerSideEncryptionCustomerAlgorithm     = AmzServerSideEncryption + "-Customer-Algorithm"
	AmzServerSideEncryptionCustomerKey           = AmzServerSideEncryption + "-Customer-Key"
	AmzServerSideEncryptionCustomerKeyMD5        = AmzServerSideEncryption + "-Customer-Key-Md5"
	AmzServerSideEncryptionCopyCustomerAlgorithm = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm"
	AmzServerSideEncryptionCopyCustomerKey       = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"
	AmzServerSideEncryptionCopyCustomerKeyMD5    = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5"

	AmzEncryptionAES = "AES256"
	AmzEncryptionKMS = "aws:kms"

	// Signature v2 related constants
	AmzSignatureV2 = "Signature"
	AmzAccessKeyID = "AWSAccessKeyId"

	// Response request id.
	AmzRequestID = "x-amz-request-id"

	// Deployment id.
	MinioDeploymentID = "x-minio-deployment-id"

	// Server-Status
	MinIOServerStatus = "x-minio-server-status"

	// Delete special flag to force delete a bucket
	MinIOForceDelete = "x-minio-force-delete"

	// Header indicates if the mtime should be preserved by client
	MinIOSourceMTime = "x-minio-source-mtime"

	// Header indicates if the etag should be preserved by client
	MinIOSourceETag = "x-minio-source-etag"

	// Writes expected write quorum
	MinIOWriteQuorum = "x-minio-write-quorum"

	// Reports number of drives currently healing
	MinIOHealingDrives = "x-minio-healing-drives"

	// Header indicates if the delete marker should be preserved by client
	MinIOSourceDeleteMarker = "x-minio-source-deletemarker"

	// Header indicates if the delete marker version needs to be purged.
	MinIOSourceDeleteMarkerDelete = "x-minio-source-deletemarker-delete"

	// Header indicates permanent delete replication status.
	MinIODeleteReplicationStatus = "X-Minio-Replication-Delete-Status"
	// Header indicates delete-marker replication status.
	MinIODeleteMarkerReplicationStatus = "X-Minio-Replication-DeleteMarker-Status"
	// Header indicates if its a GET/HEAD proxy request for active-active replication
	MinIOSourceProxyRequest = "X-Minio-Source-Proxy-Request"
	// Header indicates that this request is a replication request to create a REPLICA
	MinIOSourceReplicationRequest = "X-Minio-Source-Replication-Request"
)

// Common http query params S3 API
const (
	VersionID = "versionId"

	PartNumber = "partNumber"

	UploadID = "uploadId"
)
