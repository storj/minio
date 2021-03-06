// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

/*
 * MinIO Cloud Storage, (C) 2017 MinIO, Inc.
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

package hash

import "fmt"

// SHA256Mismatch - when content sha256 does not match with what was sent from client.
type SHA256Mismatch struct {
	ExpectedSHA256   string
	CalculatedSHA256 string
}

func (e SHA256Mismatch) Error() string {
	return "Bad sha256: Expected " + e.ExpectedSHA256 + " does not match calculated " + e.CalculatedSHA256
}

// BadDigest - Content-MD5 you specified did not match what we received.
type BadDigest struct {
	ExpectedMD5   string
	CalculatedMD5 string
}

func (e BadDigest) Error() string {
	return "Bad digest: Expected " + e.ExpectedMD5 + " does not match calculated " + e.CalculatedMD5
}

// ErrSizeMismatch error size mismatch
type ErrSizeMismatch struct {
	Want int64
	Got  int64
}

func (e ErrSizeMismatch) Error() string {
	return fmt.Sprintf("Size mismatch: got %d, want %d", e.Got, e.Want)
}
