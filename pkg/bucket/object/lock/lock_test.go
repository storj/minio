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

package lock

import (
	"encoding/xml"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	xhttp "storj.io/minio/cmd/http"
)

func TestParseMode(t *testing.T) {
	testCases := []struct {
		value        string
		expectedMode RetMode
	}{
		{
			value:        "governance",
			expectedMode: RetGovernance,
		},
		{
			value:        "complIAnce",
			expectedMode: RetCompliance,
		},
		{
			value:        "gce",
			expectedMode: "",
		},
	}

	for _, tc := range testCases {
		if parseRetMode(tc.value) != tc.expectedMode {
			t.Errorf("Expected Mode %s, got %s", tc.expectedMode, parseRetMode(tc.value))
		}
	}
}
func TestParseLegalHoldStatus(t *testing.T) {
	tests := []struct {
		value          string
		expectedStatus LegalHoldStatus
	}{
		{
			value:          "ON",
			expectedStatus: LegalHoldOn,
		},
		{
			value:          "Off",
			expectedStatus: LegalHoldOff,
		},
		{
			value:          "x",
			expectedStatus: "",
		},
	}

	for _, tt := range tests {
		actualStatus := parseLegalHoldStatus(tt.value)
		if actualStatus != tt.expectedStatus {
			t.Errorf("Expected legal hold status %s, got %s", tt.expectedStatus, actualStatus)
		}
	}
}

// TestUnmarshalDefaultRetention checks if default retention
// marshaling and unmarshaling work as expected
func TestUnmarshalDefaultRetention(t *testing.T) {
	days := int32(4)
	years := int32(1)
	zerodays := int32(0)
	invalidDays := int32(maximumRetentionDays + 1)
	tests := []struct {
		value       DefaultRetention
		expectedErr error
		expectErr   bool
	}{
		{
			value:       DefaultRetention{Mode: "retain"},
			expectedErr: ErrMalformedXML,
			expectErr:   true,
		},
		{
			value:       DefaultRetention{Mode: RetGovernance},
			expectedErr: ErrMalformedXML,
			expectErr:   true,
		},
		{
			value:       DefaultRetention{Mode: RetGovernance, Days: &days},
			expectedErr: nil,
			expectErr:   false,
		},
		{
			value:       DefaultRetention{Mode: RetGovernance, Years: &years},
			expectedErr: nil,
			expectErr:   false,
		},
		{
			value:       DefaultRetention{Mode: RetGovernance, Days: &days, Years: &years},
			expectedErr: ErrMalformedXML,
			expectErr:   true,
		},
		{
			value:       DefaultRetention{Mode: RetGovernance, Days: &zerodays},
			expectedErr: ErrInvalidRetentionPeriod,
			expectErr:   true,
		},
		{
			value:       DefaultRetention{Mode: RetGovernance, Days: &invalidDays},
			expectedErr: ErrRetentionPeriodTooLarge,
			expectErr:   true,
		},
	}
	for _, tt := range tests {
		d, err := xml.MarshalIndent(&tt.value, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		var dr DefaultRetention
		err = xml.Unmarshal(d, &dr)
		if tt.expectedErr == nil {
			if err != nil {
				t.Fatalf("error: expected = <nil>, got = %v", err)
			}
		} else if err == nil {
			t.Fatalf("error: expected = %v, got = <nil>", tt.expectedErr)
		} else if tt.expectedErr.Error() != err.Error() {
			t.Fatalf("error: expected = %v, got = %v", tt.expectedErr, err)
		}
	}
}

func TestParseObjectLockConfig(t *testing.T) {
	tests := []struct {
		value       string
		expectedErr error
		expectErr   bool
	}{
		{
			value:       `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>yes</ObjectLockEnabled></ObjectLockConfiguration>`,
			expectedErr: ErrMalformedXML,
			expectErr:   true,
		},
		{
			value:       `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>0</Days></DefaultRetention></Rule></ObjectLockConfiguration>`,
			expectedErr: ErrInvalidRetentionPeriod,
			expectErr:   true,
		},
		{
			value:       `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>36501</Days></DefaultRetention></Rule></ObjectLockConfiguration>`,
			expectedErr: ErrRetentionPeriodTooLarge,
			expectErr:   true,
		},
		{
			value:       `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`,
			expectedErr: nil,
			expectErr:   false,
		},
	}
	for _, tt := range tests {
		_, err := ParseObjectLockConfig(strings.NewReader(tt.value))
		if tt.expectedErr == nil {
			if err != nil {
				t.Fatalf("error: expected = <nil>, got = %v", err)
			}
		} else if err == nil {
			t.Fatalf("error: expected = %v, got = <nil>", tt.expectedErr)
		} else if tt.expectedErr.Error() != err.Error() {
			t.Fatalf("error: expected = %v, got = %v", tt.expectedErr, err)
		}
	}
}

func TestParseObjectRetention(t *testing.T) {
	tests := []struct {
		value       string
		expectedErr error
		expectErr   bool
	}{
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>string</Mode><RetainUntilDate>2020-01-02T15:04:05Z</RetainUntilDate></Retention>`,
			expectedErr: ErrUnknownWORMModeDirective,
			expectErr:   true,
		},
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>COMPLIANCE</Mode><RetainUntilDate>2017-01-02T15:04:05Z</RetainUntilDate></Retention>`,
			expectedErr: ErrPastObjectLockRetainDate,
			expectErr:   true,
		},
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>GOVERNANCE</Mode><RetainUntilDate>2057-01-02T15:04:05Z</RetainUntilDate></Retention>`,
			expectedErr: nil,
			expectErr:   false,
		},
	}
	for _, tt := range tests {
		_, err := ParseObjectRetention(strings.NewReader(tt.value))
		if tt.expectedErr == nil {
			if err != nil {
				t.Fatalf("error: expected = <nil>, got = %v", err)
			}
		} else if err == nil {
			t.Fatalf("error: expected = %v, got = <nil>", tt.expectedErr)
		} else if tt.expectedErr.Error() != err.Error() {
			t.Fatalf("error: expected = %v, got = %v", tt.expectedErr, err)
		}
	}
}

func TestIsObjectLockRequested(t *testing.T) {
	tests := []struct {
		header      http.Header
		expectedVal bool
	}{
		{
			header: http.Header{
				"Authorization":        []string{"AWS4-HMAC-SHA256 <cred_string>"},
				"X-Amz-Content-Sha256": []string{""},
				"Content-Encoding":     []string{""},
			},
			expectedVal: false,
		},
		{
			header: http.Header{
				AmzObjectLockLegalHold: []string{""},
			},
			expectedVal: true,
		},
		{
			header: http.Header{
				AmzObjectLockRetainUntilDate: []string{""},
				AmzObjectLockMode:            []string{""},
			},
			expectedVal: true,
		},
		{
			header: http.Header{
				AmzObjectLockBypassRetGovernance: []string{""},
			},
			expectedVal: false,
		},
	}
	for _, tt := range tests {
		actualVal := IsObjectLockRequested(tt.header)
		if actualVal != tt.expectedVal {
			t.Fatalf("error: expected %v, actual %v", tt.expectedVal, actualVal)
		}
	}
}

func TestIsObjectLockGovernanceBypassSet(t *testing.T) {
	tests := []struct {
		header      http.Header
		expectedVal bool
	}{
		{
			header: http.Header{
				"Authorization":        []string{"AWS4-HMAC-SHA256 <cred_string>"},
				"X-Amz-Content-Sha256": []string{""},
				"Content-Encoding":     []string{""},
			},
			expectedVal: false,
		},
		{
			header: http.Header{
				AmzObjectLockLegalHold: []string{""},
			},
			expectedVal: false,
		},
		{
			header: http.Header{
				AmzObjectLockRetainUntilDate: []string{""},
				AmzObjectLockMode:            []string{""},
			},
			expectedVal: false,
		},
		{
			header: http.Header{
				AmzObjectLockBypassRetGovernance: []string{""},
			},
			expectedVal: false,
		},
		{
			header: http.Header{
				AmzObjectLockBypassRetGovernance: []string{"true"},
			},
			expectedVal: true,
		},
	}
	for _, tt := range tests {
		actualVal := IsObjectLockGovernanceBypassSet(tt.header)
		if actualVal != tt.expectedVal {
			t.Fatalf("error: expected %v, actual %v", tt.expectedVal, actualVal)
		}
	}
}

func TestParseObjectLockRetentionHeaders(t *testing.T) {
	tests := []struct {
		header      http.Header
		expectedErr error
	}{
		{
			header: http.Header{
				"Authorization":        []string{"AWS4-HMAC-SHA256 <cred_string>"},
				"X-Amz-Content-Sha256": []string{""},
				"Content-Encoding":     []string{""},
			},
			expectedErr: ErrObjectLockInvalidHeaders,
		},
		{
			header: http.Header{
				xhttp.AmzObjectLockMode:            []string{"lock"},
				xhttp.AmzObjectLockRetainUntilDate: []string{"2017-01-02"},
			},
			expectedErr: ErrUnknownWORMModeDirective,
		},
		{
			header: http.Header{
				xhttp.AmzObjectLockMode: []string{"governance"},
			},
			expectedErr: ErrObjectLockInvalidHeaders,
		},
		{
			header: http.Header{
				xhttp.AmzObjectLockRetainUntilDate: []string{"2017-01-02"},
				xhttp.AmzObjectLockMode:            []string{"governance"},
			},
			expectedErr: ErrInvalidRetentionDate,
		},
		{
			header: http.Header{
				xhttp.AmzObjectLockRetainUntilDate: []string{"2017-01-02T15:04:05Z"},
				xhttp.AmzObjectLockMode:            []string{"governance"},
			},
			expectedErr: ErrPastObjectLockRetainDate,
		},
		{
			header: http.Header{
				xhttp.AmzObjectLockMode:            []string{"governance"},
				xhttp.AmzObjectLockRetainUntilDate: []string{"2017-01-02T15:04:05Z"},
			},
			expectedErr: ErrPastObjectLockRetainDate,
		},
		{
			header: http.Header{
				xhttp.AmzObjectLockMode:            []string{"governance"},
				xhttp.AmzObjectLockRetainUntilDate: []string{"2087-01-02T15:04:05Z"},
			},
			expectedErr: nil,
		},
	}

	for i, tt := range tests {
		_, _, err := ParseObjectLockRetentionHeaders(tt.header)
		if tt.expectedErr == nil {
			if err != nil {
				t.Fatalf("Case %d error: expected = <nil>, got = %v", i, err)
			}
		} else if err == nil {
			t.Fatalf("Case %d error: expected = %v, got = <nil>", i, tt.expectedErr)
		} else if tt.expectedErr.Error() != err.Error() {
			t.Fatalf("Case %d error: expected = %v, got = %v", i, tt.expectedErr, err)
		}
	}
}

func TestGetObjectRetentionMeta(t *testing.T) {
	tests := []struct {
		metadata map[string]string
		expected ObjectRetention
	}{
		{
			metadata: map[string]string{
				"Authorization":        "AWS4-HMAC-SHA256 <cred_string>",
				"X-Amz-Content-Sha256": "",
				"Content-Encoding":     "",
			},
			expected: ObjectRetention{},
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-mode": "governance",
			},
			expected: ObjectRetention{Mode: RetGovernance},
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-retain-until-date": "2020-02-01",
			},
			expected: ObjectRetention{RetainUntilDate: RetentionDate{time.Date(2020, 2, 1, 12, 0, 0, 0, time.UTC)}},
		},
	}

	for i, tt := range tests {
		o := GetObjectRetentionMeta(tt.metadata)
		if o.Mode != tt.expected.Mode {
			t.Fatalf("Case %d expected %v, got %v", i, tt.expected.Mode, o.Mode)
		}
	}
}

func TestGetObjectLegalHoldMeta(t *testing.T) {
	tests := []struct {
		metadata map[string]string
		expected ObjectLegalHold
	}{
		{
			metadata: map[string]string{
				"x-amz-object-lock-mode": "governance",
			},
			expected: ObjectLegalHold{},
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold": "on",
			},
			expected: ObjectLegalHold{Status: LegalHoldOn},
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold": "off",
			},
			expected: ObjectLegalHold{Status: LegalHoldOff},
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold": "X",
			},
			expected: ObjectLegalHold{Status: ""},
		},
	}

	for i, tt := range tests {
		o := GetObjectLegalHoldMeta(tt.metadata)
		if o.Status != tt.expected.Status {
			t.Fatalf("Case %d expected %v, got %v", i, tt.expected.Status, o.Status)
		}
	}
}

func TestParseObjectLegalHold(t *testing.T) {
	tests := []struct {
		value       string
		expectedErr error
		expectErr   bool
	}{
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>string</Status></LegalHold>`,
			expectedErr: ErrMalformedXML,
			expectErr:   true,
		},
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></LegalHold>`,
			expectedErr: nil,
			expectErr:   false,
		},
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><ObjectLockLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></ObjectLockLegalHold>`,
			expectedErr: nil,
			expectErr:   false,
		},
		// invalid Status key
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><ObjectLockLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><MyStatus>ON</MyStatus></ObjectLockLegalHold>`,
			expectedErr: errors.New("expected element type <Status> but have <MyStatus>"),
			expectErr:   true,
		},
		// invalid XML attr
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><UnknownLegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>ON</Status></UnknownLegalHold>`,
			expectedErr: errors.New("expected element type <LegalHold>/<ObjectLockLegalHold> but have <UnknownLegalHold>"),
			expectErr:   true,
		},
		{
			value:       `<?xml version="1.0" encoding="UTF-8"?><LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>On</Status></LegalHold>`,
			expectedErr: ErrMalformedXML,
			expectErr:   true,
		},
	}
	for i, tt := range tests {
		_, err := ParseObjectLegalHold(strings.NewReader(tt.value))
		if tt.expectedErr == nil {
			if err != nil {
				t.Fatalf("Case %d error: expected = <nil>, got = %v", i, err)
			}
		} else if err == nil {
			t.Fatalf("Case %d error: expected = %v, got = <nil>", i, tt.expectedErr)
		} else if tt.expectedErr.Error() != err.Error() {
			t.Fatalf("Case %d error: expected = %v, got = %v", i, tt.expectedErr, err)
		}
	}
}
func TestFilterObjectLockMetadata(t *testing.T) {
	tests := []struct {
		metadata        map[string]string
		filterRetention bool
		filterLegalHold bool
		expected        map[string]string
	}{
		{
			metadata: map[string]string{
				"Authorization":        "AWS4-HMAC-SHA256 <cred_string>",
				"X-Amz-Content-Sha256": "",
				"Content-Encoding":     "",
			},
			expected: map[string]string{
				"Authorization":        "AWS4-HMAC-SHA256 <cred_string>",
				"X-Amz-Content-Sha256": "",
				"Content-Encoding":     "",
			},
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-mode": "governance",
			},
			expected: map[string]string{
				"x-amz-object-lock-mode": "governance",
			},
			filterRetention: false,
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-mode":              "governance",
				"x-amz-object-lock-retain-until-date": "2020-02-01",
			},
			expected:        map[string]string{},
			filterRetention: true,
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold": "off",
			},
			expected:        map[string]string{},
			filterLegalHold: true,
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold": "on",
			},
			expected:        map[string]string{"x-amz-object-lock-legal-hold": "on"},
			filterLegalHold: false,
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold":        "on",
				"x-amz-object-lock-mode":              "governance",
				"x-amz-object-lock-retain-until-date": "2020-02-01",
			},
			expected:        map[string]string{},
			filterRetention: true,
			filterLegalHold: true,
		},
		{
			metadata: map[string]string{
				"x-amz-object-lock-legal-hold":        "on",
				"x-amz-object-lock-mode":              "governance",
				"x-amz-object-lock-retain-until-date": "2020-02-01",
			},
			expected: map[string]string{"x-amz-object-lock-legal-hold": "on",
				"x-amz-object-lock-mode":              "governance",
				"x-amz-object-lock-retain-until-date": "2020-02-01"},
		},
	}

	for i, tt := range tests {
		o := FilterObjectLockMetadata(tt.metadata, tt.filterRetention, tt.filterLegalHold)
		if !reflect.DeepEqual(o, tt.metadata) {
			t.Fatalf("Case %d expected %v, got %v", i, tt.metadata, o)
		}
	}
}
