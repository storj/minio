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
	"strings"
)

// ARN - Cloud provider resource name representation following standard ARN format:
// arn:partition:service:region:account-id:resource-id
type ARN struct {
	Partition  string // Cloud provider: "gcp" (future: may support more providers)
	Service    string // Service type: "pubsub" (future: may support more services)
	Region     string // Region (usually empty for GCP)
	AccountID  string // Account identifier (GCP project ID)
	ResourceID string // Resource identifier (topic ID)
}

// String - returns string representation.
func (arn ARN) String() string {
	if arn.AccountID == "" && arn.ResourceID == "" && arn.Region == "" {
		return ""
	}

	partition := arn.Partition
	if partition == "" {
		partition = "gcp"
	}

	service := arn.Service
	if service == "" {
		service = "pubsub"
	}

	return "arn:" + partition + ":" + service + ":" + arn.Region + ":" + arn.AccountID + ":" + arn.ResourceID
}

// ToTargetID converts ARN to TargetID for backward compatibility.
func (arn ARN) ToTargetID() TargetID {
	return TargetID{
		ID:   arn.AccountID,
		Name: arn.ResourceID,
	}
}

// MarshalXML - encodes to XML data.
func (arn ARN) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(arn.String(), start)
}

// UnmarshalXML - decodes XML data.
func (arn *ARN) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}

	parsedARN, err := parseARN(s)
	if err != nil {
		return err
	}

	*arn = *parsedARN
	return nil
}

// parseARN - parses string to ARN.
func parseARN(s string) (*ARN, error) {
	// ARN must be in the format of arn:partition:service:region:account-id:resource-id
	if !strings.HasPrefix(s, "arn:") {
		return nil, &ErrInvalidARN{s}
	}

	tokens := strings.Split(s, ":")
	if len(tokens) != 6 {
		return nil, &ErrInvalidARN{s}
	}

	// Partition (cloud provider, only "gcp" supported for now)
	if tokens[1] != "gcp" {
		return nil, &ErrInvalidARN{s}
	}

	// Service (only "pubsub" supported for now)
	if tokens[2] != "pubsub" {
		return nil, &ErrInvalidARN{s}
	}

	// Region must be empty for GCP Pub/Sub
	if tokens[3] != "" {
		return nil, &ErrInvalidARN{s}
	}

	// Account ID (GCP project ID in case of Pub/Sub)
	if tokens[4] == "" {
		return nil, &ErrInvalidARN{s}
	}

	// Resource ID (Topic ID in case of Pub/Sub)
	if tokens[5] == "" {
		return nil, &ErrInvalidARN{s}
	}

	return &ARN{
		Partition:  tokens[1],
		Service:    tokens[2],
		Region:     tokens[3],
		AccountID:  tokens[4],
		ResourceID: tokens[5],
	}, nil
}
