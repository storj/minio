/*
 * MinIO Cloud Storage, (C) 2020 MinIO, Inc.
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
	"testing"

	"github.com/dustin/go-humanize"
)

func TestIsXLMetaFormatValid(t *testing.T) {
	tests := []struct {
		name    int
		version string
		format  string
		want    bool
	}{
		{1, "123", "fs", false},
		{2, "123", xlMetaFormat, false},
		{3, xlMetaVersion100, "test", false},
		{4, xlMetaVersion101, "hello", false},
		{5, xlMetaVersion100, xlMetaFormat, true},
		{6, xlMetaVersion101, xlMetaFormat, true},
	}
	for _, tt := range tests {
		if got := isXLMetaFormatValid(tt.version, tt.format); got != tt.want {
			t.Errorf("Test %d: Expected %v but received %v", tt.name, got, tt.want)
		}
	}
}

func TestIsXLMetaErasureInfoValid(t *testing.T) {
	tests := []struct {
		name   int
		data   int
		parity int
		want   bool
	}{
		{1, 5, 6, false},
		{2, 5, 5, true},
		{3, 0, 5, false},
		{4, 5, 0, false},
		{5, 5, 0, false},
		{6, 5, 4, true},
	}
	for _, tt := range tests {
		if got := isXLMetaErasureInfoValid(tt.data, tt.parity); got != tt.want {
			t.Errorf("Test %d: Expected %v but received %v", tt.name, got, tt.want)
		}
	}
}

// Test the predicted part size from the part index
func TestGetPartSizeFromIdx(t *testing.T) {
	// Create test cases
	testCases := []struct {
		totalSize    int64
		partSize     int64
		partIndex    int
		expectedSize int64
	}{
		// Total size is zero
		{0, 10, 1, 0},
		// part size 2MiB, total size 4MiB
		{4 * humanize.MiByte, 2 * humanize.MiByte, 1, 2 * humanize.MiByte},
		{4 * humanize.MiByte, 2 * humanize.MiByte, 2, 2 * humanize.MiByte},
		{4 * humanize.MiByte, 2 * humanize.MiByte, 3, 0},
		// part size 2MiB, total size 5MiB
		{5 * humanize.MiByte, 2 * humanize.MiByte, 1, 2 * humanize.MiByte},
		{5 * humanize.MiByte, 2 * humanize.MiByte, 2, 2 * humanize.MiByte},
		{5 * humanize.MiByte, 2 * humanize.MiByte, 3, 1 * humanize.MiByte},
		{5 * humanize.MiByte, 2 * humanize.MiByte, 4, 0},
	}

	for i, testCase := range testCases {
		s, err := calculatePartSizeFromIdx(GlobalContext, testCase.totalSize, testCase.partSize, testCase.partIndex)
		if err != nil {
			t.Errorf("Test %d: Expected to pass but failed. %s", i+1, err)
		}
		if err == nil && s != testCase.expectedSize {
			t.Errorf("Test %d: The calculated part size is incorrect: expected = %d, found = %d\n", i+1, testCase.expectedSize, s)
		}
	}

	testCasesFailure := []struct {
		totalSize int64
		partSize  int64
		partIndex int
		err       error
	}{
		// partSize is 0, returns error.
		{10, 0, 1, errPartSizeZero},
		// partIndex is 0, returns error.
		{10, 1, 0, errPartSizeIndex},
		// Total size is -1, returns error.
		{-2, 10, 1, errInvalidArgument},
	}

	for i, testCaseFailure := range testCasesFailure {
		_, err := calculatePartSizeFromIdx(GlobalContext, testCaseFailure.totalSize, testCaseFailure.partSize, testCaseFailure.partIndex)
		if err == nil {
			t.Errorf("Test %d: Expected to failed but passed. %s", i+1, err)
		}
		if err != nil && err != testCaseFailure.err {
			t.Errorf("Test %d: Expected err %s, but got %s", i+1, testCaseFailure.err, err)
		}
	}
}
