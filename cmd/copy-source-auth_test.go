/*
 * Copyright (C) 2026 Storj Labs, Inc.
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
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	xhttp "storj.io/minio/cmd/http"
	"storj.io/minio/pkg/auth"
)

// TestUnsignedCopySourceRejected verifies that an unsigned x-amz-copy-source
// header can't turn a PutObject request (e.g. a presigned upload URL) into a
// server-side CopyObject that reads with the signer's permissions.
func TestUnsignedCopySourceRejected(t *testing.T) {
	defer DetectTestLeak(t)()
	// CopyObject is registered before PutObject, as in the production router,
	// so any PUT with an x-amz-copy-source header is routed to CopyObject.
	ExecObjectLayerAPITest(t, testUnsignedCopySourceRejected, []string{"CopyObject", "PutObject"})
}

func testUnsignedCopySourceRejected(obj ObjectLayer, instanceType, bucketName string, apiRouter http.Handler,
	credentials auth.Credentials, t *testing.T) {
	ctx := context.Background()

	secretBucket := getRandomBucketName()
	if err := obj.MakeBucketWithLocation(ctx, secretBucket, BucketOptions{}); err != nil {
		t.Fatalf("%s: unable to create bucket: %v", instanceType, err)
	}
	secret := []byte("top secret content")
	if _, err := obj.PutObject(ctx, secretBucket, "secret", mustGetPutObjReader(t, bytes.NewReader(secret), int64(len(secret)), "", ""), ObjectOptions{}); err != nil {
		t.Fatalf("%s: unable to upload secret object: %v", instanceType, err)
	}
	copySource := SlashSeparator + secretBucket + SlashSeparator + "secret"
	upload := []byte("uploaded content")

	presigned := func(objectName string) *http.Request {
		req, err := newTestRequest(http.MethodPut, getPutObjectURL("", bucketName, objectName), int64(len(upload)), bytes.NewReader(upload))
		if err != nil {
			t.Fatalf("%s: unable to create request: %v", instanceType, err)
		}
		if err = preSignV4(req, credentials.AccessKey, credentials.SecretKey, 600); err != nil {
			t.Fatalf("%s: unable to presign request: %v", instanceType, err)
		}
		return req
	}

	headerSigned := func(objectName string, headers map[string]string) *http.Request {
		req, err := newTestSignedRequestV4(http.MethodPut, getPutObjectURL("", bucketName, objectName), int64(len(upload)), bytes.NewReader(upload),
			credentials.AccessKey, credentials.SecretKey, headers)
		if err != nil {
			t.Fatalf("%s: unable to create signed request: %v", instanceType, err)
		}
		return req
	}

	serve := func(req *http.Request) int {
		// net/http servers keep the Content-Length header on incoming requests.
		req.Header.Set(xhttp.ContentLength, strconv.FormatInt(req.ContentLength, 10))
		rec := httptest.NewRecorder()
		apiRouter.ServeHTTP(rec, req)
		return rec.Code
	}

	assertContent := func(objectName string, expected []byte) {
		reader, err := obj.GetObjectNInfo(ctx, bucketName, objectName, nil, nil, readLock, ObjectOptions{})
		if err != nil {
			t.Fatalf("%s: unable to read %s: %v", instanceType, objectName, err)
		}
		defer reader.Close()
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			t.Fatalf("%s: unable to read %s: %v", instanceType, objectName, err)
		}
		if !bytes.Equal(data, expected) {
			t.Fatalf("%s: %s has content %q, expected %q", instanceType, objectName, data, expected)
		}
	}

	assertMissing := func(objectName string) {
		if _, err := obj.GetObjectInfo(ctx, bucketName, objectName, ObjectOptions{}); err == nil {
			t.Fatalf("%s: %s must not exist", instanceType, objectName)
		}
	}

	// Sanity check: the presigned upload URL itself works.
	if code := serve(presigned("plain-upload")); code != http.StatusOK {
		t.Fatalf("%s: presigned PutObject returned %d, expected %d", instanceType, code, http.StatusOK)
	}
	assertContent("plain-upload", upload)

	// Presigned upload URL + unsigned x-amz-copy-source must not copy.
	req := presigned("presigned-copy")
	req.Header.Set(xhttp.AmzCopySource, copySource)
	if code := serve(req); code != http.StatusBadRequest {
		t.Errorf("%s: presigned PUT with unsigned copy source returned %d, expected %d", instanceType, code, http.StatusBadRequest)
	}
	assertMissing("presigned-copy")

	// Other x-amz-copy-source-* headers must also be signed.
	req = presigned("presigned-copy-range")
	req.Header.Set(xhttp.AmzCopySourceRange, "bytes=0-1")
	if code := serve(req); code != http.StatusBadRequest {
		t.Errorf("%s: presigned PUT with unsigned copy source range returned %d, expected %d", instanceType, code, http.StatusBadRequest)
	}
	assertMissing("presigned-copy-range")

	// Header-signed request + x-amz-copy-source added after signing must not copy.
	req = headerSigned("header-copy", nil)
	req.Header.Set(xhttp.AmzCopySource, copySource)
	if code := serve(req); code != http.StatusBadRequest {
		t.Errorf("%s: signed PUT with unsigned copy source returned %d, expected %d", instanceType, code, http.StatusBadRequest)
	}
	assertMissing("header-copy")

	// A copy with a signed x-amz-copy-source keeps working.
	req = headerSigned("signed-copy", map[string]string{xhttp.AmzCopySource: copySource})
	if code := serve(req); code != http.StatusOK {
		t.Fatalf("%s: CopyObject with signed copy source returned %d, expected %d", instanceType, code, http.StatusOK)
	}
	assertContent("signed-copy", secret)
}
