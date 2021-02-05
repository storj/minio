// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

/*
 * MinIO Go Library for Amazon S3 Compatible Cloud Storage
 * Copyright 2015-2017 MinIO, Inc.
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

package auth

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccessKey    = "juny7fppw4yjrunf5byyu2gvmioq"
	testSecretKey    = "jzvyyf3q6y43shv2mi6er4e2qwsjimriwcwutl5c5oaieum5qzdy6"
	maxPresignExpiry = 604800
)

func TestAWSMiddleware(t *testing.T) {
	testCases := []struct {
		bucketName string
		accessKey  string
		secretKey  string

		expectedRespStatus int
		locationResponse   []byte
		errorResponse      APIErrorResponse
		shouldPass         bool
	}{
		{
			bucketName:         "bob",
			accessKey:          testAccessKey,
			secretKey:          testSecretKey,
			expectedRespStatus: 200,
			shouldPass:         true,
		},
		{
			bucketName:         "jones",
			accessKey:          testAccessKey,
			secretKey:          "bob",
			expectedRespStatus: 403,
			shouldPass:         false,
		},
	}

	handler := AWSMiddleware(&testSecretKeyGetter{}, []string{"gateway.local"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessKey := AccessKeyIDFromRequest(r)
		require.Equal(t, testAccessKey, accessKey)
		_, err := w.Write([]byte("all is well"))
		require.NoError(t, err)
	}))

	body := []byte("helloworld")
	contentLength := int64(len(body))

	for i, testCase := range testCases {
		testCase := testCase
		for _, method := range []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodConnect,
			http.MethodOptions,
			http.MethodTrace,
		} {
			method := method
			t.Run(fmt.Sprintf("testCase %d with method %s", i, method), func(t *testing.T) {
				reqV2, err := newTestSignedRequest(method, getBucketLocationURL("gateway.local", testCase.bucketName), contentLength, bytes.NewReader(body), testCase.accessKey, testCase.secretKey, signerV2)
				require.NoError(t, err)
				reqV4, err := newTestSignedRequest(method, getBucketLocationURL("gateway.local", testCase.bucketName), contentLength, bytes.NewReader(body), testCase.accessKey, testCase.secretKey, signerV4)
				require.NoError(t, err)
				reqPreV2, err := newTestRequest(http.MethodPost, getBucketLocationURL("gateway.local", testCase.bucketName), contentLength, bytes.NewReader(body))
				require.NoError(t, err)
				require.NoError(t, preSignV2(reqPreV2, testCase.accessKey, testCase.secretKey, maxPresignExpiry))
				reqPreV4, err := newTestRequest(http.MethodPost, getBucketLocationURL("gateway.local", testCase.bucketName), contentLength, bytes.NewReader(body))
				require.NoError(t, err)
				require.NoError(t, preSignV4(reqPreV4, testCase.accessKey, testCase.secretKey, maxPresignExpiry))
				for _, req := range []*http.Request{reqV2, reqV4, reqPreV2, reqPreV4} {
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					resp := rec.Result()
					assert.Equal(t, testCase.expectedRespStatus, resp.StatusCode)
					require.NoError(t, resp.Body.Close())
				}
			})
		}
	}
}

type testSecretKeyGetter struct{}

func (skg *testSecretKeyGetter) Get(ak string) (string, error) {
	if ak == testAccessKey {
		return testSecretKey, nil
	}
	return "", errors.New("not found")
}
