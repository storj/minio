package model

import (
	"encoding/xml"
)

// Owner - bucket owner/principal
// TODO: Figure out if we can either leave this off entirely, leave out the
// ID/DisplayName, or if we really do have to set the to empty strings (or as
// minio does to some globally defined default ID).
type Owner struct {
	ID          string
	DisplayName string
}

// Bucket container for bucket metadata
type Bucket struct {
	Name         string
	CreationDate ISO8601
}

// ListBucketsResponse - format for list buckets response
type ListBucketsResponse struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult" json:"-"`

	Owner Owner

	// Container for one or more buckets.
	Buckets struct {
		Buckets []Bucket `xml:"Bucket"`
	} // Buckets are nested
}
