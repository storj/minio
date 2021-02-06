/*
 * MinIO Cloud Storage, (C) 2016-2019 MinIO, Inc.
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
	"sync"

	humanize "github.com/dustin/go-humanize"
)

const (
	// Block size used for all internal operations version 1.
	blockSizeV1 = 10 * humanize.MiByte

	// Staging buffer read size for all internal operations version 1.
	readSizeV1 = 1 * humanize.MiByte

	// Buckets meta prefix.
	bucketMetaPrefix = "buckets"

	// ETag (hex encoded md5sum) of empty string.
	emptyETag = "d41d8cd98f00b204e9800998ecf8427e"
)

// Global object layer mutex, used for safely updating object layer.
var globalObjLayerMutex sync.RWMutex

// Global object layer, only accessed by globalObjectAPI.
var globalObjectAPI ObjectLayer

// Checks if the object is a directory, this logic uses
// if size == 0 and object ends with SlashSeparator then
// returns true.
func isObjectDir(object string, size int64) bool {
	return HasSuffix(object, SlashSeparator) && size == 0
}
