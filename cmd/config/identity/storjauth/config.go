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

package storjauth

import (
	"github.com/storj/minio/cmd/config"
	"github.com/storj/minio/pkg/env"
)

// Config contains disables user authorization within MinIO, allowing any user to act as owner.
type Config struct {
	Enabled bool `json:"enabled"`
}

//StorjAuthEnabled is the key for the StorjAuthSubSys KVS
const StorjAuthEnabled = "enabled"

//EnvStorjAuthEnabled is the key for sys.Env
const EnvStorjAuthEnabled = "STORJ_AUTH_ENABLED"

// DefaultKVS - default config for LDAP config
var DefaultKVS = config.KVS{
	config.KV{
		Key:   StorjAuthEnabled,
		Value: config.EnableOff,
	},
}

// Enabled returns if jwks is enabled.
func Enabled(kvs config.KVS) bool {
	return kvs.Get(StorjAuthEnabled) == config.Enable
}

// LookupConfig - Initialize new storjauth config.
func LookupConfig(kvs config.KVS) Config {
	return Config{Enabled: env.Get(EnvStorjAuthEnabled, kvs.Get(StorjAuthEnabled)) == config.Enable}
}
