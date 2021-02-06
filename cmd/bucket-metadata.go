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
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"time"

	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/storj/minio/cmd/logger"
	bucketsse "github.com/storj/minio/pkg/bucket/encryption"
	"github.com/storj/minio/pkg/bucket/lifecycle"
	objectlock "github.com/storj/minio/pkg/bucket/object/lock"
	"github.com/storj/minio/pkg/bucket/policy"
	"github.com/storj/minio/pkg/bucket/replication"
	"github.com/storj/minio/pkg/bucket/versioning"
	"github.com/storj/minio/pkg/event"
	"github.com/storj/minio/pkg/madmin"
)

const (
	legacyBucketObjectLockEnabledConfigFile = "object-lock-enabled.json"
	legacyBucketObjectLockEnabledConfig     = `{"x-amz-bucket-object-lock-enabled":true}`

	bucketMetadataFile    = ".metadata.bin"
	bucketMetadataFormat  = 1
	bucketMetadataVersion = 1
)

var (
	enabledBucketObjectLockConfig = []byte(`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
	enabledBucketVersioningConfig = []byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
)

//go:generate msgp -file $GOFILE

// BucketMetadata contains bucket metadata.
// When adding/removing fields, regenerate the marshal code using the go generate above.
// Only changing meaning of fields requires a version bump.
// bucketMetadataFormat refers to the format.
// bucketMetadataVersion can be used to track a rolling upgrade of a field.
type BucketMetadata struct {
	Name                    string
	Created                 time.Time
	LockEnabled             bool // legacy not used anymore.
	PolicyConfigJSON        []byte
	NotificationConfigXML   []byte
	LifecycleConfigXML      []byte
	ObjectLockConfigXML     []byte
	VersioningConfigXML     []byte
	EncryptionConfigXML     []byte
	TaggingConfigXML        []byte
	QuotaConfigJSON         []byte
	ReplicationConfigXML    []byte
	BucketTargetsConfigJSON []byte

	// Unexported fields. Must be updated atomically.
	policyConfig       *policy.Policy
	notificationConfig *event.Config
	lifecycleConfig    *lifecycle.Lifecycle
	objectLockConfig   *objectlock.Config
	versioningConfig   *versioning.Versioning
	sseConfig          *bucketsse.BucketSSEConfig
	taggingConfig      *tags.Tags
	quotaConfig        *madmin.BucketQuota
	replicationConfig  *replication.Config
	bucketTargetConfig *madmin.BucketTargets
}

// newBucketMetadata creates BucketMetadata with the supplied name and Created to Now.
func newBucketMetadata(name string) BucketMetadata {
	return BucketMetadata{
		Name:    name,
		Created: UTCNow(),
		notificationConfig: &event.Config{
			XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
		},
		quotaConfig: &madmin.BucketQuota{},
		versioningConfig: &versioning.Versioning{
			XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
		},
		bucketTargetConfig: &madmin.BucketTargets{},
	}
}

// Load - loads the metadata of bucket by name from ObjectLayer api.
// If an error is returned the returned metadata will be default initialized.
func (b *BucketMetadata) Load(ctx context.Context, api ObjectLayer, name string) error {
	if name == "" {
		logger.LogIf(ctx, errors.New("bucket name cannot be empty"))
		return errors.New("bucket name cannot be empty")
	}

	return nil
}

// loadBucketMetadata loads and migrates to bucket metadata.
func loadBucketMetadata(ctx context.Context, objectAPI ObjectLayer, bucket string) (BucketMetadata, error) {
	b := newBucketMetadata(bucket)
	err := b.Load(ctx, objectAPI, b.Name)
	if err == nil {
		return b, b.convertLegacyConfigs(ctx, objectAPI)
	}

	if !errors.Is(err, errConfigNotFound) {
		return b, err
	}

	// Old bucket without bucket metadata. Hence we migrate existing settings.
	return b, b.convertLegacyConfigs(ctx, objectAPI)
}

// parseAllConfigs will parse all configs and populate the private fields.
// The first error encountered is returned.
func (b *BucketMetadata) parseAllConfigs(ctx context.Context, objectAPI ObjectLayer) (err error) {
	if len(b.PolicyConfigJSON) != 0 {
		b.policyConfig, err = policy.ParseConfig(bytes.NewReader(b.PolicyConfigJSON), b.Name)
		if err != nil {
			return err
		}
	} else {
		b.policyConfig = nil
	}

	if len(b.NotificationConfigXML) != 0 {
		if err = xml.Unmarshal(b.NotificationConfigXML, b.notificationConfig); err != nil {
			return err
		}
	}

	if len(b.LifecycleConfigXML) != 0 {
		b.lifecycleConfig, err = lifecycle.ParseLifecycleConfig(bytes.NewReader(b.LifecycleConfigXML))
		if err != nil {
			return err
		}
	} else {
		b.lifecycleConfig = nil
	}

	if len(b.EncryptionConfigXML) != 0 {
		b.sseConfig, err = bucketsse.ParseBucketSSEConfig(bytes.NewReader(b.EncryptionConfigXML))
		if err != nil {
			return err
		}
	} else {
		b.sseConfig = nil
	}

	if len(b.TaggingConfigXML) != 0 {
		b.taggingConfig, err = tags.ParseBucketXML(bytes.NewReader(b.TaggingConfigXML))
		if err != nil {
			return err
		}
	} else {
		b.taggingConfig = nil
	}

	if bytes.Equal(b.ObjectLockConfigXML, enabledBucketObjectLockConfig) {
		b.VersioningConfigXML = enabledBucketVersioningConfig
	}

	if len(b.ObjectLockConfigXML) != 0 {
		b.objectLockConfig, err = objectlock.ParseObjectLockConfig(bytes.NewReader(b.ObjectLockConfigXML))
		if err != nil {
			return err
		}
	} else {
		b.objectLockConfig = nil
	}

	if len(b.VersioningConfigXML) != 0 {
		b.versioningConfig, err = versioning.ParseConfig(bytes.NewReader(b.VersioningConfigXML))
		if err != nil {
			return err
		}
	}

	if len(b.BucketTargetsConfigJSON) != 0 {
		if err = json.Unmarshal(b.BucketTargetsConfigJSON, b.bucketTargetConfig); err != nil {
			return err
		}
	} else {
		b.bucketTargetConfig = &madmin.BucketTargets{}
	}
	return nil
}

func (b *BucketMetadata) convertLegacyConfigs(ctx context.Context, objectAPI ObjectLayer) error {
	return nil
}

// Save config to supplied ObjectLayer api.
func (b *BucketMetadata) Save(ctx context.Context, api ObjectLayer) error {
	return NotImplemented{}
}
