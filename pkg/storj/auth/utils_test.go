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
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sha256-simd"
)

// Various signature types we are supporting, currently
// two main signature types.
type signerType int

const (
	signerV2 signerType = iota
	signerV4
)

func newTestSignedRequest(method, urlStr string, contentLength int64, body io.ReadSeeker, accessKey, secretKey string, signer signerType) (*http.Request, error) {
	if signer == signerV2 {
		return newTestSignedRequestV2(method, urlStr, contentLength, body, accessKey, secretKey, nil)
	}
	return newTestSignedRequestV4(method, urlStr, contentLength, body, accessKey, secretKey, nil)
}

// Returns new HTTP request object signed with signature v2.
func newTestSignedRequestV2(method, urlStr string, contentLength int64, body io.ReadSeeker, accessKey, secretKey string, headers map[string]string) (*http.Request, error) {
	req, err := newTestRequest(method, urlStr, contentLength, body)
	if err != nil {
		return nil, err
	}
	req.Header.Del("x-amz-content-sha256")

	// Anonymous request return quickly.
	if accessKey == "" || secretKey == "" {
		return req, nil
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	req, err = SignV2(*req, accessKey, secretKey, false)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// Returns new HTTP request object signed with signature v4.
func newTestSignedRequestV4(method, urlStr string, contentLength int64, body io.ReadSeeker, accessKey, secretKey string, headers map[string]string) (*http.Request, error) {
	req, err := newTestRequest(method, urlStr, contentLength, body)
	if err != nil {
		return nil, err
	}

	// Anonymous request return quickly.
	if accessKey == "" || secretKey == "" {
		return req, nil
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	err = signRequestV4(req, accessKey, secretKey)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// Sign given request using Signature V4.
func signRequestV4(req *http.Request, accessKey, secretKey string) error {
	// Get hashed payload.
	hashedPayload := req.Header.Get("x-amz-content-sha256")
	if hashedPayload == "" {
		return fmt.Errorf("Invalid hashed payload")
	}

	currTime := time.Now().UTC()

	// Set x-amz-date.
	req.Header.Set("x-amz-date", currTime.Format(iso8601Format))

	// Get header map.
	headerMap := make(map[string][]string)
	for k, vv := range req.Header {
		// If request header key is not in ignored headers, then add it.
		if _, ok := ignoredHeaders[http.CanonicalHeaderKey(k)]; !ok {
			headerMap[strings.ToLower(k)] = vv
		}
	}

	// Get header keys.
	headers := []string{"host"}
	for k := range headerMap {
		headers = append(headers, k)
	}
	sort.Strings(headers)

	region := ""

	// Get canonical headers.
	var buf bytes.Buffer
	for _, k := range headers {
		buf.WriteString(k)
		buf.WriteByte(':')
		switch {
		case k == "host":
			buf.WriteString(req.URL.Host)
			fallthrough
		default:
			for idx, v := range headerMap[k] {
				if idx > 0 {
					buf.WriteByte(',')
				}
				buf.WriteString(v)
			}
			buf.WriteByte('\n')
		}
	}
	canonicalHeaders := buf.String()

	// Get signed headers.
	signedHeaders := strings.Join(headers, ";")

	// Get canonical query string.
	req.URL.RawQuery = strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20")

	// Get canonical URI.
	canonicalURI := EncodePath(req.URL.Path)

	// Get canonical request.
	// canonicalRequest =
	//  <HTTPMethod>\n
	//  <CanonicalURI>\n
	//  <CanonicalQueryString>\n
	//  <CanonicalHeaders>\n
	//  <SignedHeaders>\n
	//  <HashedPayload>
	//
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		hashedPayload,
	}, "\n")

	// Get scope.
	scope := strings.Join([]string{
		currTime.Format(yyyymmdd),
		region,
		string(serviceS3),
		"aws4_request",
	}, SlashSeparator)

	stringToSign := "AWS4-HMAC-SHA256" + "\n" + currTime.Format(iso8601Format) + "\n"
	stringToSign = stringToSign + scope + "\n"
	stringToSign += getSHA256Hash([]byte(canonicalRequest))

	date := sumHMAC([]byte("AWS4"+secretKey), []byte(currTime.Format(yyyymmdd)))
	regionHMAC := sumHMAC(date, []byte(region))
	service := sumHMAC(regionHMAC, []byte(serviceS3))
	signingKey := sumHMAC(service, []byte("aws4_request"))

	signature := hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))

	// final Authorization header
	parts := []string{
		"AWS4-HMAC-SHA256" + " Credential=" + accessKey + SlashSeparator + scope,
		"SignedHeaders=" + signedHeaders,
		"Signature=" + signature,
	}
	auth := strings.Join(parts, ", ")
	req.Header.Set("Authorization", auth)

	return nil
}

// Returns new HTTP request object.
func newTestRequest(method, urlStr string, contentLength int64, body io.ReadSeeker) (*http.Request, error) {
	if method == "" {
		method = http.MethodPost
	}

	// Save for subsequent use
	var hashedPayload string
	var md5Base64 string
	switch {
	case body == nil:
		hashedPayload = getSHA256Hash([]byte{})
	default:
		payloadBytes, err := ioutil.ReadAll(body)
		if err != nil {
			return nil, err
		}
		hashedPayload = getSHA256Hash(payloadBytes)
		md5Base64 = getMD5HashBase64(payloadBytes)
	}
	// Seek back to beginning.
	if body != nil {
		_, err := body.Seek(0, 0)
		if err != nil {
			return nil, err
		}
	} else {
		body = bytes.NewReader([]byte(""))
	}
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	if md5Base64 != "" {
		req.Header.Set("Content-Md5", md5Base64)
	}
	req.Header.Set("x-amz-content-sha256", hashedPayload)

	// Add Content-Length
	req.ContentLength = contentLength

	return req, nil
}

// getMD5Sum returns MD5 sum of given data.
func getMD5Sum(data []byte) []byte {
	hash := md5.New()
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

// getMD5HashBase64 returns MD5 hash in base64 encoding of given data.
func getMD5HashBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(getMD5Sum(data))
}

// getSHA256Hash returns SHA-256 hash in hex encoding of given data.
func getSHA256Hash(data []byte) string {
	return hex.EncodeToString(getSHA256Sum(data))
}

// getSHA256Hash returns SHA-256 sum of given data.
func getSHA256Sum(data []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

//
// Excerpts from @lsegal - https://github.com/aws/aws-sdk-js/issues/659#issuecomment-120477258
//
//  User-Agent:
//
//      This is ignored from signing because signing this causes problems with generating pre-signed URLs
//      (that are executed by other agents) or when customers pass requests through proxies, which may
//      modify the user-agent.
//
//  Authorization:
//
//      Is skipped for obvious reasons
//
var ignoredHeaders = map[string]bool{
	"Authorization": true,
	"User-Agent":    true,
}

// return URL For fetching location of the bucket.
func getBucketLocationURL(endPoint, bucketName string) string {
	queryValue := url.Values{}
	queryValue.Set("location", "")
	return makeTestTargetURL(endPoint, bucketName, "", queryValue)
}

// construct URL for http requests for bucket operations.
func makeTestTargetURL(endPoint, bucketName, objectName string, queryValues url.Values) string {
	urlStr := endPoint + SlashSeparator
	if bucketName != "" {
		urlStr = urlStr + bucketName + SlashSeparator
	}
	if objectName != "" {
		urlStr += EncodePath(objectName)
	}
	if len(queryValues) > 0 {
		urlStr = urlStr + "?" + queryValues.Encode()
	}
	return urlStr
}

// preSignV4 presign the request, in accordance with
// http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html.
func preSignV4(req *http.Request, accessKeyID, secretAccessKey string, expires int64) error {
	// Presign is not needed for anonymous credentials.
	if accessKeyID == "" || secretAccessKey == "" {
		return errors.New("Presign cannot be generated without access and secret keys")
	}

	region := ""
	date := time.Now().UTC()
	scope := getScope(date, region)
	credential := fmt.Sprintf("%s/%s", accessKeyID, scope)

	// Set URL query.
	query := req.URL.Query()
	query.Set("X-Amz-Algorithm", signV4Algorithm)
	query.Set("X-Amz-Date", date.Format(iso8601Format))
	query.Set("X-Amz-Expires", strconv.FormatInt(expires, 10))
	query.Set("X-Amz-SignedHeaders", "host")
	query.Set("X-Amz-Credential", credential)
	query.Set("X-Amz-Content-Sha256", unsignedPayload)

	// "host" is the only header required to be signed for Presigned URLs.
	extractedSignedHeaders := make(http.Header)
	extractedSignedHeaders.Set("host", req.Host)

	queryStr := strings.ReplaceAll(query.Encode(), "+", "%20")
	canonicalRequest := getCanonicalRequest(extractedSignedHeaders, unsignedPayload, queryStr, req.URL.Path, req.Method)
	stringToSign := getStringToSign(canonicalRequest, date, scope)
	signingKey := getSigningKey(secretAccessKey, date, region, serviceS3)
	signature := getSignature(signingKey, stringToSign)

	req.URL.RawQuery = query.Encode()

	// Add signature header to RawQuery.
	req.URL.RawQuery += "&X-Amz-Signature=" + url.QueryEscape(signature)

	// Construct the final presigned URL.
	return nil
}

// preSignV2 - presign the request in following style.
// https://${S3_BUCKET}.s3.amazonaws.com/${S3_OBJECT}?AWSAccessKeyId=${S3_ACCESS_KEY}&Expires=${TIMESTAMP}&Signature=${SIGNATURE}.
func preSignV2(req *http.Request, accessKeyID, secretAccessKey string, expires int64) error {
	// Presign is not needed for anonymous credentials.
	if accessKeyID == "" || secretAccessKey == "" {
		return errors.New("Presign cannot be generated without access and secret keys")
	}

	// FIXME: Remove following portion of code after fixing a bug in minio-go preSignV2.

	d := time.Now().UTC()
	// Find epoch expires when the request will expire.
	epochExpires := d.Unix() + expires

	// Add expires header if not present.
	expiresStr := req.Header.Get("Expires")
	if expiresStr == "" {
		expiresStr = strconv.FormatInt(epochExpires, 10)
		req.Header.Set("Expires", expiresStr)
	}

	// url.RawPath will be valid if path has any encoded characters, if not it will
	// be empty - in which case we need to consider url.Path (bug in net/http?)
	encodedResource := req.URL.RawPath
	encodedQuery := req.URL.RawQuery
	if encodedResource == "" {
		splits := strings.SplitN(req.URL.Path, "?", 2)
		encodedResource = splits[0]
		if len(splits) == 2 {
			encodedQuery = splits[1]
		}
	}

	unescapedQueries, err := unescapeQueries(encodedQuery)
	if err != nil {
		return err
	}

	// Get presigned string to sign.
	stringToSign := getStringToSignV2(req.Method, encodedResource, strings.Join(unescapedQueries, "&"), req.Header, expiresStr)
	hm := hmac.New(sha1.New, []byte(secretAccessKey))
	_, _ = hm.Write([]byte(stringToSign))

	// Calculate signature.
	signature := base64.StdEncoding.EncodeToString(hm.Sum(nil))

	query := req.URL.Query()
	// Handle specially for Google Cloud Storage.
	query.Set("AWSAccessKeyId", accessKeyID)
	// Fill in Expires for presigned query.
	query.Set("Expires", strconv.FormatInt(epochExpires, 10))

	// Encode query and save.
	req.URL.RawQuery = query.Encode()

	// Save signature finally.
	req.URL.RawQuery += "&Signature=" + url.QueryEscape(signature)
	return nil
}
