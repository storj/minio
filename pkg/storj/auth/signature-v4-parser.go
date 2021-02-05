// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

/*
 * MinIO Cloud Storage, (C) 2015 MinIO, Inc.
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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/storj/minio/pkg/auth"
)

// credentialHeader data type represents structured form of Credential
// string from authorization header.
type credentialHeader struct {
	accessKey string
	scope     struct {
		date    time.Time
		region  string
		service string
		request string
	}
}

// Return scope string.
func (c credentialHeader) getScope() string {
	return strings.Join([]string{
		c.scope.date.Format(yyyymmdd),
		c.scope.region,
		c.scope.service,
		c.scope.request,
	}, SlashSeparator)
}

func getReqAccessKeyV4(r *http.Request, stype serviceType) (string, APIErrorCode) {
	ch, s3Err := parseCredentialHeader("Credential="+r.URL.Query().Get(headerAmzCredential), stype)
	if s3Err != ErrNone {
		// Strip off the Algorithm prefix.
		v4Auth := strings.TrimPrefix(r.Header.Get("Authorization"), signV4Algorithm)
		authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
		if len(authFields) != 3 {
			return "", ErrMissingFields
		}
		ch, s3Err = parseCredentialHeader(authFields[0], stype)
		if s3Err != ErrNone {
			return "", s3Err
		}
	}
	return ch.accessKey, ErrNone
}

// parse credentialHeader string into its structured form.
func parseCredentialHeader(credElement string, stype serviceType) (ch credentialHeader, aec APIErrorCode) {
	creds := strings.SplitN(strings.TrimSpace(credElement), "=", 2)
	if len(creds) != 2 {
		return ch, ErrMissingFields
	}
	if creds[0] != "Credential" {
		return ch, ErrMissingCredTag
	}
	credElements := strings.Split(strings.TrimSpace(creds[1]), SlashSeparator)
	if len(credElements) < 5 {
		return ch, ErrCredMalformed
	}
	accessKey := strings.Join(credElements[:len(credElements)-4], SlashSeparator) // The access key may contain one or more `/`
	if !auth.IsAccessKeyValid(accessKey) {
		return ch, ErrInvalidAccessKeyID
	}
	// Save access key id.
	cred := credentialHeader{
		accessKey: accessKey,
	}
	credElements = credElements[len(credElements)-4:]
	var e error
	cred.scope.date, e = time.Parse(yyyymmdd, credElements[0])
	if e != nil {
		return ch, ErrMalformedCredentialDate
	}

	cred.scope.region = credElements[1]
	if credElements[2] != string(stype) {
		if stype == serviceSTS {
			return ch, ErrInvalidServiceSTS
		}
		return ch, ErrInvalidServiceS3
	}
	cred.scope.service = credElements[2]
	if credElements[3] != "aws4_request" {
		return ch, ErrInvalidRequestVersion
	}
	cred.scope.request = credElements[3]
	return cred, ErrNone
}

// Parse signature from signature tag.
func parseSignature(signElement string) (string, APIErrorCode) {
	signFields := strings.Split(strings.TrimSpace(signElement), "=")
	if len(signFields) != 2 {
		return "", ErrMissingFields
	}
	if signFields[0] != "Signature" {
		return "", ErrMissingSignTag
	}
	if signFields[1] == "" {
		return "", ErrMissingFields
	}
	signature := signFields[1]
	return signature, ErrNone
}

// Parse slice of signed headers from signed headers tag.
func parseSignedHeader(signedHdrElement string) ([]string, APIErrorCode) {
	signedHdrFields := strings.Split(strings.TrimSpace(signedHdrElement), "=")
	if len(signedHdrFields) != 2 {
		return nil, ErrMissingFields
	}
	if signedHdrFields[0] != "SignedHeaders" {
		return nil, ErrMissingSignHeadersTag
	}
	if signedHdrFields[1] == "" {
		return nil, ErrMissingFields
	}
	signedHeaders := strings.Split(signedHdrFields[1], ";")
	return signedHeaders, ErrNone
}

// signValues data type represents structured form of AWS Signature V4 header.
type signValues struct {
	Credential    credentialHeader
	SignedHeaders []string
	Signature     string
}

// preSignValues data type represents structued form of AWS Signature V4 query string.
type preSignValues struct {
	signValues
	Date    time.Time
	Expires time.Duration
}

// Parses signature version '4' query string of the following form.
//
//   querystring = X-Amz-Algorithm=algorithm
//   querystring += &X-Amz-Credential= urlencode(accessKey + '/' + credential_scope)
//   querystring += &X-Amz-Date=date
//   querystring += &X-Amz-Expires=timeout interval
//   querystring += &X-Amz-SignedHeaders=signed_headers
//   querystring += &X-Amz-Signature=signature
//
// verifies if any of the necessary query params are missing in the presigned request.
func doesV4PresignParamsExist(query url.Values) APIErrorCode {
	v4PresignQueryParams := []string{headerAmzAlgorithm, headerAmzCredential, headerAmzSignature, headerAmzDate, headerAmzSignedHeaders, headerAmzExpires}
	for _, v4PresignQueryParam := range v4PresignQueryParams {
		if _, ok := query[v4PresignQueryParam]; !ok {
			return ErrInvalidQueryParams
		}
	}
	return ErrNone
}

// Parses all the presigned signature values into separate elements.
func parsePreSignV4(query url.Values, stype serviceType) (psv preSignValues, aec APIErrorCode) {
	// verify whether the required query params exist.
	aec = doesV4PresignParamsExist(query)
	if aec != ErrNone {
		return psv, aec
	}

	// Verify if the query algorithm is supported or not.
	if query.Get(headerAmzAlgorithm) != signV4Algorithm {
		return psv, ErrInvalidQuerySignatureAlgo
	}

	// Initialize signature version '4' structured header.
	preSignV4Values := preSignValues{}

	// Save credential.
	preSignV4Values.Credential, aec = parseCredentialHeader("Credential="+query.Get(headerAmzCredential), stype)
	if aec != ErrNone {
		return psv, aec
	}

	var e error
	// Save date in native time.Time.
	preSignV4Values.Date, e = time.Parse(iso8601Format, query.Get(headerAmzDate))
	if e != nil {
		return psv, ErrMalformedPresignedDate
	}

	// Save expires in native time.Duration.
	preSignV4Values.Expires, e = time.ParseDuration(query.Get(headerAmzExpires) + "s")
	if e != nil {
		return psv, ErrMalformedExpires
	}

	if preSignV4Values.Expires < 0 {
		return psv, ErrNegativeExpires
	}

	// Check if Expiry time is less than 7 days (value in seconds).
	if preSignV4Values.Expires.Seconds() > 604800 {
		return psv, ErrMaximumExpires
	}

	// Save signed headers.
	preSignV4Values.SignedHeaders, aec = parseSignedHeader("SignedHeaders=" + query.Get(headerAmzSignedHeaders))
	if aec != ErrNone {
		return psv, aec
	}

	// Save signature.
	preSignV4Values.Signature, aec = parseSignature("Signature=" + query.Get(headerAmzSignature))
	if aec != ErrNone {
		return psv, aec
	}

	// Return structed form of signature query string.
	return preSignV4Values, ErrNone
}

// Parses signature version '4' header of the following form.
//
//    Authorization: algorithm Credential=accessKeyID/credScope, \
//            SignedHeaders=signedHeaders, Signature=signature
//
func parseSignV4(v4Auth string, stype serviceType) (sv signValues, aec APIErrorCode) {
	// credElement is fetched first to skip replacing the space in access key.
	credElement := strings.TrimPrefix(strings.Split(strings.TrimSpace(v4Auth), ",")[0], signV4Algorithm)
	// Replace all spaced strings, some clients can send spaced
	// parameters and some won't. So we pro-actively remove any spaces
	// to make parsing easier.
	v4Auth = strings.ReplaceAll(v4Auth, " ", "")
	if v4Auth == "" {
		return sv, ErrAuthHeaderEmpty
	}

	// Verify if the header algorithm is supported or not.
	if !strings.HasPrefix(v4Auth, signV4Algorithm) {
		return sv, ErrSignatureVersionNotSupported
	}

	// Strip off the Algorithm prefix.
	v4Auth = strings.TrimPrefix(v4Auth, signV4Algorithm)
	authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
	if len(authFields) != 3 {
		return sv, ErrMissingFields
	}

	// Initialize signature version '4' structured header.
	signV4Values := signValues{}

	var s3Err APIErrorCode
	// Save credentail values.
	signV4Values.Credential, s3Err = parseCredentialHeader(strings.TrimSpace(credElement), stype)
	if s3Err != ErrNone {
		return sv, s3Err
	}

	// Save signed headers.
	signV4Values.SignedHeaders, s3Err = parseSignedHeader(authFields[1])
	if s3Err != ErrNone {
		return sv, s3Err
	}

	// Save signature.
	signV4Values.Signature, s3Err = parseSignature(authFields[2])
	if s3Err != ErrNone {
		return sv, s3Err
	}

	// Return the structure here.
	return signV4Values, ErrNone
}
