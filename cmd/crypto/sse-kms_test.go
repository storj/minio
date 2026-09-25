// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package crypto

import (
	"encoding/base64"
	"testing"
)

func TestS3KMSParseMetadataContext(t *testing.T) {
	metadata := S3KMS.CreateMetadata(nil, "key-id", []byte("sealed-kms-key"), SealedKey{
		Algorithm: SealAlgorithm,
	})
	metadata[MetaContext] = base64.StdEncoding.EncodeToString([]byte(`{"bucket":"bucket/object"}`))

	_, _, _, ctx, err := S3KMS.ParseMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx["bucket"]; got != "bucket/object" {
		t.Fatalf("got context %v", ctx)
	}
}
