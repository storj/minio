/*
 * MinIO Cloud Storage, (C) 2018 MinIO, Inc.
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

package event

import (
	"encoding/xml"
	"reflect"
	"testing"
)

func TestARNString(t *testing.T) {
	testCases := []struct {
		arn            ARN
		expectedResult string
	}{
		{ARN{}, ""},
		{ARN{AccountID: "my-project", ResourceID: "my-topic"}, "arn:gcp:pubsub::my-project:my-topic"},
		{ARN{Partition: "gcp", Service: "pubsub", AccountID: "my-project", ResourceID: "my-topic"}, "arn:gcp:pubsub::my-project:my-topic"},
		{ARN{Partition: "my-provider", Service: "my-service", AccountID: "my-account", ResourceID: "my-resource"}, "arn:my-provider:my-service::my-account:my-resource"},
	}

	for i, testCase := range testCases {
		result := testCase.arn.String()

		if result != testCase.expectedResult {
			t.Fatalf("test %v: result: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestARNMarshalXML(t *testing.T) {
	testCases := []struct {
		arn          ARN
		expectedData []byte
	}{
		{ARN{}, []byte("<ARN></ARN>")},
		{ARN{AccountID: "my-project", ResourceID: "my-topic"}, []byte("<ARN>arn:gcp:pubsub::my-project:my-topic</ARN>")},
		{ARN{Partition: "gcp", Service: "pubsub", AccountID: "my-project", ResourceID: "my-topic"}, []byte("<ARN>arn:gcp:pubsub::my-project:my-topic</ARN>")},
		{ARN{Partition: "my-provider", Service: "my-service", AccountID: "my-account", ResourceID: "my-resource"}, []byte("<ARN>arn:my-provider:my-service::my-account:my-resource</ARN>")},
	}

	for i, testCase := range testCases {
		data, err := xml.Marshal(testCase.arn)

		if err != nil {
			t.Fatalf("test %v: error: %v", i+1, err)
		}

		if !reflect.DeepEqual(data, testCase.expectedData) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, string(testCase.expectedData), string(data))
		}
	}
}

func TestARNUnmarshalXML(t *testing.T) {
	testCases := []struct {
		data        []byte
		expectedARN *ARN
		expectErr   bool
	}{
		{[]byte("<ARN></ARN>"), nil, true},
		{[]byte("<ARN>arn:gcp:pubsub:::</ARN>"), nil, true},
		{[]byte("<ARN>arn:minio:sqs::1:webhook</ARN>"), nil, true},                    // Old format rejected
		{[]byte("<ARN>arn:aws:sqs::my-project:my-topic</ARN>"), nil, true},            // aws partition not supported
		{[]byte("<ARN>arn:gcp:sqs::my-project:my-topic</ARN>"), nil, true},            // sqs service not supported
		{[]byte("<ARN>arn:gcp:pubsub:us-east1:my-project:my-topic</ARN>"), nil, true}, // region must be empty
		{[]byte("<ARN>arn:gcp:pubsub::my-project:my-topic</ARN>"), &ARN{Partition: "gcp", Service: "pubsub", Region: "", AccountID: "my-project", ResourceID: "my-topic"}, false},
	}

	for i, testCase := range testCases {
		arn := &ARN{}
		err := xml.Unmarshal(testCase.data, &arn)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if *arn != *testCase.expectedARN {
				t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedARN, arn)
			}
		}
	}
}

func TestParseARN(t *testing.T) {
	testCases := []struct {
		s           string
		expectedARN *ARN
		expectErr   bool
	}{
		{"", nil, true},
		{"arn:gcp:pubsub:::", nil, true},
		{"arn:gcp:pubsub::my-project:my-topic:extra", nil, true},
		{"arn:minio:sqs::1:webhook", nil, true},                    // Old format rejected
		{"arn:aws:sqs::my-project:my-topic", nil, true},            // aws partition not supported
		{"arn:gcp:sqs::my-project:my-topic", nil, true},            // sqs service not supported
		{"arn:gcp:pubsub:us-east1:my-project:my-topic", nil, true}, // region must be empty
		{"arn:gcp:pubsub::my-project:my-topic", &ARN{Partition: "gcp", Service: "pubsub", Region: "", AccountID: "my-project", ResourceID: "my-topic"}, false},
	}

	for i, testCase := range testCases {
		arn, err := parseARN(testCase.s)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if *arn != *testCase.expectedARN {
				t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedARN, arn)
			}
		}
	}
}

func TestARNToTargetID(t *testing.T) {
	arn := ARN{
		Partition:  "gcp",
		Service:    "pubsub",
		AccountID:  "my-project",
		ResourceID: "my-topic",
	}

	targetID := arn.ToTargetID()

	if targetID.ID != "my-project" {
		t.Fatalf("expected ID 'my-project', got '%v'", targetID.ID)
	}
	if targetID.Name != "my-topic" {
		t.Fatalf("expected Name 'my-topic', got '%v'", targetID.Name)
	}
}
