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
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	"github.com/storj/minio/pkg/storj/hash"
)

type accessKeyIDKey struct{}

// Standard S3 HTTP response constants
const (
	headerDate          = "Date"
	headerContentType   = "Content-Type"
	headerContentMD5    = "Content-Md5"
	headerExpires       = "Expires"
	headerContentLength = "Content-Length"
	headerAcceptRanges  = "Accept-Ranges"
	headerAuthorization = "Authorization"
	headerAction        = "Action"
	// Signature V4 related contants.
	headerAmzContentSha256 = "X-Amz-Content-Sha256"
	headerAmzDate          = "X-Amz-Date"
	headerAmzAlgorithm     = "X-Amz-Algorithm"
	headerAmzExpires       = "X-Amz-Expires"
	headerAmzSignedHeaders = "X-Amz-SignedHeaders"
	headerAmzSignature     = "X-Amz-Signature"
	headerAmzCredential    = "X-Amz-Credential"
	headerAmzSecurityToken = "X-Amz-Security-Token"
	// Signature v2 related constants
	headerAmzSignatureV2 = "Signature"
	headerAmzAccessKeyID = "AWSAccessKeyId"
	// Response request id.
	headerAmzRequestID                    = "x-amz-request-id"
	headerSSE                             = "X-Amz-Server-Side-Encryption"
	headerSSECKey                         = headerSSE + "-Customer-Key"
	headerSSECopyKey                      = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"
	headerAmzMetaUnencryptedContentLength = "X-Amz-Meta-X-Amz-Unencrypted-Content-Length"
	headerAmzMetaUnencryptedContentMD5    = "X-Amz-Meta-X-Amz-Unencrypted-Content-Md5"
)

// SecretKeyGetter returns a secret key from an access key.
type SecretKeyGetter interface {
	Get(accessKeyID string) (secretKey string, err error)
}

// AWSMiddleware returns a gorilla mux middleware function.
func AWSMiddleware(secretKeyGetter SecretKeyGetter, domains []string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			accessKeyID, err := validateAuth(r, secretKeyGetter, domains)
			if err != ErrNone {
				errCode := errorCodes.ToAPIErr(err)
				vars := mux.Vars(r)
				bucket := vars["bucket"]
				key, err := url.PathUnescape(vars["key"])
				if err != nil {
					key = vars["key"]
				}
				_ = writeErrorResponse(w, errCode, bucket, key, r.URL)
			} else {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessKeyIDKey{}, accessKeyID)))
			}
		})
	}
}

// AccessKeyIDFromRequest retrieves the access key ID from the request context.
func AccessKeyIDFromRequest(r *http.Request) string {
	val, ok := r.Context().Value(accessKeyIDKey{}).(string)
	if !ok {
		return ""
	}
	return val
}

func validateAuth(r *http.Request, secretKeyGetter SecretKeyGetter, domains []string) (accessKeyID string, err APIErrorCode) {
	switch getRequestAuthType(r) {
	case authTypeUnknown, authTypeStreamingSigned:
		return "", ErrSignatureVersionNotSupported
	case authTypePresignedV2, authTypeSignedV2:
		if err = isReqAuthenticatedV2(r, secretKeyGetter, domains); err != ErrNone {
			return "", err
		}
		return getReqAccessKeyV2(r)
	default:
		if err = isReqAuthenticated(r, serviceS3, secretKeyGetter); err != ErrNone {
			return "", err
		}
		return getReqAccessKeyV4(r, serviceS3)
	}
}

// Verify if request has valid AWS Signature Version '2'.
func isReqAuthenticatedV2(r *http.Request, secretKeyGetter SecretKeyGetter, domains []string) (s3Error APIErrorCode) {
	if isRequestSignatureV2(r) {
		return doesSignV2Match(r, secretKeyGetter, domains)
	}
	return doesPresignV2SignatureMatch(r, secretKeyGetter, domains)
}

func reqSignatureV4Verify(r *http.Request, stype serviceType, secretKeyGetter SecretKeyGetter) (s3Error APIErrorCode) {
	sha256sum := getContentSha256Cksum(r, stype)
	switch {
	case isRequestSignatureV4(r):
		return doesSignatureMatch(sha256sum, r, stype, secretKeyGetter)
	case isRequestPresignedSignatureV4(r):
		return doesPresignedSignatureMatch(sha256sum, r, stype, secretKeyGetter)
	default:
		return ErrAccessDenied
	}
}

// Verify if request has valid AWS Signature Version '4'.
func isReqAuthenticated(r *http.Request, stype serviceType, secretKeyGetter SecretKeyGetter) (s3Error APIErrorCode) {
	if errCode := reqSignatureV4Verify(r, stype, secretKeyGetter); errCode != ErrNone {
		return errCode
	}

	var (
		err                       error
		contentMD5, contentSHA256 []byte
	)

	// Extract 'Content-Md5' if present.
	contentMD5, err = checkValidMD5(r.Header)
	if err != nil {
		return ErrInvalidDigest
	}

	// Extract either 'X-Amz-Content-Sha256' header or 'X-Amz-Content-Sha256' query parameter (if V4 presigned)
	// Do not verify 'X-Amz-Content-Sha256' if skipSHA256.
	if skipSHA256 := skipContentSha256Cksum(r); !skipSHA256 && isRequestPresignedSignatureV4(r) {
		if sha256Sum, ok := r.URL.Query()[headerAmzContentSha256]; ok && len(sha256Sum) > 0 {
			contentSHA256, err = hex.DecodeString(sha256Sum[0])
			if err != nil {
				return ErrContentSHA256Mismatch
			}
		}
	} else if _, ok := r.Header[headerAmzContentSha256]; !skipSHA256 && ok {
		contentSHA256, err = hex.DecodeString(r.Header.Get(headerAmzContentSha256))
		if err != nil || len(contentSHA256) == 0 {
			return ErrContentSHA256Mismatch
		}
	}

	// Verify 'Content-Md5' and/or 'X-Amz-Content-Sha256' if present.
	// The verification happens implicit during reading.
	reader, err := hash.NewReader(r.Body, -1, hex.EncodeToString(contentMD5),
		hex.EncodeToString(contentSHA256), -1, true)
	if err != nil {
		return toAPIErrorCode(err)
	}
	r.Body = reader
	return ErrNone
}

// checkValidMD5 - verify if valid md5, returns md5 in bytes.
func checkValidMD5(h http.Header) ([]byte, error) {
	md5B64, ok := h[headerContentMD5]
	if ok {
		if md5B64[0] == "" {
			return nil, fmt.Errorf("Content-Md5 header set to empty value")
		}
		return base64.StdEncoding.Strict().DecodeString(md5B64[0])
	}
	return []byte{}, nil
}

// Authorization type.
type authType int

// List of all supported auth types.
const (
	authTypeUnknown authType = iota
	authTypeAnonymous
	authTypePresigned
	authTypePresignedV2
	authTypePostPolicy
	authTypeStreamingSigned
	authTypeSigned
	authTypeSignedV2
	authTypeJWT
	authTypeSTS
)

// Get request authentication type.
func getRequestAuthType(r *http.Request) authType {
	if isRequestSignatureV2(r) {
		return authTypeSignedV2
	} else if isRequestPresignedSignatureV2(r) {
		return authTypePresignedV2
	} else if isRequestSignStreamingV4(r) {
		return authTypeStreamingSigned
	} else if isRequestSignatureV4(r) {
		return authTypeSigned
	} else if isRequestPresignedSignatureV4(r) {
		return authTypePresigned
	} else if isRequestJWT(r) {
		return authTypeJWT
	} else if isRequestPostPolicySignatureV4(r) {
		return authTypePostPolicy
	} else if _, ok := r.URL.Query()[headerAction]; ok {
		return authTypeSTS
	} else if _, ok := r.Header[headerAuthorization]; !ok {
		return authTypeAnonymous
	}
	return authTypeUnknown
}

const (
	jwtAlgorithm = "Bearer"
)

// Verify if request has JWT.
func isRequestJWT(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(headerAuthorization), jwtAlgorithm)
}

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(headerAuthorization), signV4Algorithm)
}

// Verify if request has AWS Signature Version '2'.
func isRequestSignatureV2(r *http.Request) bool {
	return (!strings.HasPrefix(r.Header.Get(headerAuthorization), signV4Algorithm) &&
		strings.HasPrefix(r.Header.Get(headerAuthorization), signV2Algorithm))
}

// Verify if request has AWS PreSign Version '4'.
func isRequestPresignedSignatureV4(r *http.Request) bool {
	_, ok := r.URL.Query()[headerAmzCredential]
	return ok
}

// Verify request has AWS PreSign Version '2'.
func isRequestPresignedSignatureV2(r *http.Request) bool {
	_, ok := r.URL.Query()[headerAmzAccessKeyID]
	return ok
}

// Verify if request has AWS Post policy Signature Version '4'.
func isRequestPostPolicySignatureV4(r *http.Request) bool {
	return strings.Contains(r.Header.Get(headerContentType), "multipart/form-data") &&
		r.Method == http.MethodPost
}

// Verify if the request has AWS Streaming Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestSignStreamingV4(r *http.Request) bool {
	return r.Header.Get(headerAmzContentSha256) == streamingContentSHA256 &&
		r.Method == http.MethodPut
}
