package router

import "net/http"

// HandlerType is an enum for handlers.
type HandlerType string

const (
	// Bucket APIs

	// ListBuckets https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
	ListBuckets = "ListBuckets"

	// CreateBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
	CreateBucket = "CreateBucket"

	// HeadBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
	HeadBucket = "HeadBucket"

	// DeleteBucket https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
	DeleteBucket = "DeleteBucket"

	// Object APIs

	// ListObjects https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html
	ListObjects = "ListObjects"

	// ListObjectsV2 https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
	ListObjectsV2 = "ListObjectsV2"

	// PutObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
	PutObject = "PutObject"

	// HeadObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
	HeadObject = "HeadObject"

	// GetObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
	GetObject = "GetObject"

	// DeleteObject https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html
	DeleteObject = "DeleteObject"
)

// Handler implements the S3 API contract.
type Handler interface {
	// Get should return a handler function for the given type or nil if
	// not implemented.
	Get(HandlerType) http.HandlerFunc
}
