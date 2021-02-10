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
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/storj/minio/cmd/config"
	"github.com/storj/minio/cmd/config/api"
	"github.com/storj/minio/cmd/config/cache"
	"github.com/storj/minio/cmd/config/compress"
	"github.com/storj/minio/cmd/config/crawler"
	"github.com/storj/minio/cmd/config/etcd"
	"github.com/storj/minio/cmd/config/heal"
	xldap "github.com/storj/minio/cmd/config/identity/ldap"
	"github.com/storj/minio/cmd/config/identity/openid"
	"github.com/storj/minio/cmd/config/identity/storjauth"
	"github.com/storj/minio/cmd/config/notify"
	"github.com/storj/minio/cmd/config/storageclass"
	"github.com/storj/minio/cmd/crypto"
	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/cmd/logger/target/http"
	"github.com/storj/minio/pkg/env"
	"github.com/storj/minio/pkg/madmin"
)

func initHelp() {
	var kvs = map[string]config.KVS{
		config.EtcdSubSys:              etcd.DefaultKVS,
		config.CacheSubSys:             cache.DefaultKVS,
		config.CompressionSubSys:       compress.DefaultKVS,
		config.IdentityLDAPSubSys:      xldap.DefaultKVS,
		config.IdentityStorjAuthSubSys: storjauth.DefaultKVS,
		config.IdentityOpenIDSubSys:    openid.DefaultKVS,
		config.RegionSubSys:            config.DefaultRegionKVS,
		config.APISubSys:               api.DefaultKVS,
		config.CredentialsSubSys:       config.DefaultCredentialKVS,
		config.KmsVaultSubSys:          crypto.DefaultVaultKVS,
		config.KmsKesSubSys:            crypto.DefaultKesKVS,
		config.LoggerWebhookSubSys:     logger.DefaultKVS,
		config.AuditWebhookSubSys:      logger.DefaultAuditKVS,
		config.HealSubSys:              heal.DefaultKVS,
		config.CrawlerSubSys:           crawler.DefaultKVS,
	}
	for k, v := range notify.DefaultNotificationKVS {
		kvs[k] = v
	}
	config.RegisterDefaultKVS(kvs)

	// Captures help for each sub-system
	var helpSubSys = config.HelpKVS{
		config.HelpKV{
			Key:         config.RegionSubSys,
			Description: "label the location of the server",
		},
		config.HelpKV{
			Key:         config.CacheSubSys,
			Description: "add caching storage tier",
		},
		config.HelpKV{
			Key:         config.CompressionSubSys,
			Description: "enable server side compression of objects",
		},
		config.HelpKV{
			Key:         config.EtcdSubSys,
			Description: "federate multiple clusters for IAM and Bucket DNS",
		},
		config.HelpKV{
			Key:         config.IdentityOpenIDSubSys,
			Description: "enable OpenID SSO support",
		},
		config.HelpKV{
			Key:         config.IdentityStorjAuthSubSys,
			Description: "disable user authentication support",
		},
		config.HelpKV{
			Key:         config.IdentityLDAPSubSys,
			Description: "enable LDAP SSO support",
		},
		config.HelpKV{
			Key:         config.PolicyOPASubSys,
			Description: "[DEPRECATED] enable external OPA for policy enforcement",
		},
		config.HelpKV{
			Key:         config.KmsVaultSubSys,
			Description: "enable external HashiCorp Vault key management service",
		},
		config.HelpKV{
			Key:         config.KmsKesSubSys,
			Description: "enable external MinIO key encryption service",
		},
		config.HelpKV{
			Key:         config.APISubSys,
			Description: "manage global HTTP API call specific features, such as throttling, authentication types, etc.",
		},
		config.HelpKV{
			Key:         config.HealSubSys,
			Description: "manage object healing frequency and bitrot verification checks",
		},
		config.HelpKV{
			Key:         config.CrawlerSubSys,
			Description: "manage crawling for usage calculation, lifecycle, healing and more",
		},
		config.HelpKV{
			Key:             config.LoggerWebhookSubSys,
			Description:     "send server logs to webhook endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.AuditWebhookSubSys,
			Description:     "send audit logs to webhook endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyWebhookSubSys,
			Description:     "publish bucket notifications to webhook endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyAMQPSubSys,
			Description:     "publish bucket notifications to AMQP endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyKafkaSubSys,
			Description:     "publish bucket notifications to Kafka endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyMQTTSubSys,
			Description:     "publish bucket notifications to MQTT endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyNATSSubSys,
			Description:     "publish bucket notifications to NATS endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyNSQSubSys,
			Description:     "publish bucket notifications to NSQ endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyMySQLSubSys,
			Description:     "publish bucket notifications to MySQL databases",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyPostgresSubSys,
			Description:     "publish bucket notifications to Postgres databases",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyESSubSys,
			Description:     "publish bucket notifications to Elasticsearch endpoints",
			MultipleTargets: true,
		},
		config.HelpKV{
			Key:             config.NotifyRedisSubSys,
			Description:     "publish bucket notifications to Redis datastores",
			MultipleTargets: true,
		},
	}

	var helpMap = map[string]config.HelpKVS{
		"":                             helpSubSys, // Help for all sub-systems.
		config.RegionSubSys:            config.RegionHelp,
		config.APISubSys:               api.Help,
		config.StorageClassSubSys:      storageclass.Help,
		config.EtcdSubSys:              etcd.Help,
		config.CacheSubSys:             cache.Help,
		config.CompressionSubSys:       compress.Help,
		config.HealSubSys:              heal.Help,
		config.CrawlerSubSys:           crawler.Help,
		config.IdentityOpenIDSubSys:    openid.Help,
		config.IdentityStorjAuthSubSys: storjauth.Help,
		config.IdentityLDAPSubSys:      xldap.Help,
		config.KmsVaultSubSys:          crypto.HelpVault,
		config.KmsKesSubSys:            crypto.HelpKes,
		config.LoggerWebhookSubSys:     logger.Help,
		config.AuditWebhookSubSys:      logger.HelpAudit,
		config.NotifyAMQPSubSys:        notify.HelpAMQP,
		config.NotifyKafkaSubSys:       notify.HelpKafka,
		config.NotifyMQTTSubSys:        notify.HelpMQTT,
		config.NotifyNATSSubSys:        notify.HelpNATS,
		config.NotifyNSQSubSys:         notify.HelpNSQ,
		config.NotifyMySQLSubSys:       notify.HelpMySQL,
		config.NotifyPostgresSubSys:    notify.HelpPostgres,
		config.NotifyRedisSubSys:       notify.HelpRedis,
		config.NotifyWebhookSubSys:     notify.HelpWebhook,
		config.NotifyESSubSys:          notify.HelpES,
	}

	config.RegisterHelpSubSys(helpMap)
}

var (
	// globalServerConfig server config.
	globalServerConfig   config.Config
	globalServerConfigMu sync.RWMutex
)

func validateConfig(s config.Config) error {
	// We must have a global lock for this so nobody else modifies env while we do.
	defer env.LockSetEnv()()

	// Disable merging env values with config for validation.
	env.SetEnvOff()

	// Enable env values to validate KMS.
	defer env.SetEnvOn()

	if _, err := config.LookupCreds(s[config.CredentialsSubSys][config.Default]); err != nil {
		return err
	}

	if _, err := config.LookupRegion(s[config.RegionSubSys][config.Default]); err != nil {
		return err
	}

	if _, err := api.LookupConfig(s[config.APISubSys][config.Default]); err != nil {
		return err
	}

	compCfg, err := compress.LookupConfig(s[config.CompressionSubSys][config.Default])
	if err != nil {
		return err
	}
	objAPI := newObjectLayerFn()
	if objAPI != nil {
		if compCfg.Enabled && !objAPI.IsCompressionSupported() {
			return fmt.Errorf("Backend does not support compression")
		}
	}

	if _, err := logger.LookupConfig(s); err != nil {
		return err
	}

	return nil
}

func lookupConfigs(s config.Config) {
	ctx := GlobalContext

	var err error
	if !globalActiveCred.IsValid() {
		// Env doesn't seem to be set, we fallback to lookup creds from the config.
		globalActiveCred, err = config.LookupCreds(s[config.CredentialsSubSys][config.Default])
		if err != nil {
			logger.LogIf(ctx, fmt.Errorf("Invalid credentials configuration: %w", err))
		}
	}

	globalStorjAuthConfig = storjauth.LookupConfig(s[config.IdentityStorjAuthSubSys][config.Enable])

	globalServerRegion, err = config.LookupRegion(s[config.RegionSubSys][config.Default])
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Invalid region configuration: %w", err))
	}

	apiConfig, err := api.LookupConfig(s[config.APISubSys][config.Default])
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Invalid api configuration: %w", err))
	}

	globalAPIConfig.init(apiConfig)

	// Initialize remote instance transport once.
	getRemoteInstanceTransportOnce.Do(func() {
		getRemoteInstanceTransport = newGatewayHTTPTransport(apiConfig.RemoteTransportDeadline)
	})

	// Load logger targets based on user's configuration
	loggerCfg, err := logger.LookupConfig(s)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize logger: %w", err))
	}

	for k, l := range loggerCfg.HTTP {
		if l.Enabled {
			// Enable http logging
			if err = logger.AddTarget(
				http.New(
					http.WithTargetName(k),
					http.WithEndpoint(l.Endpoint),
					http.WithAuthToken(l.AuthToken),
					http.WithLogKind(string(logger.All)),
					http.WithTransport(NewGatewayHTTPTransport()),
				),
			); err != nil {
				logger.LogIf(ctx, fmt.Errorf("Unable to initialize console HTTP target: %w", err))
			}
		}
	}

	for k, l := range loggerCfg.Audit {
		if l.Enabled {
			// Enable http audit logging
			if err = logger.AddAuditTarget(
				http.New(
					http.WithTargetName(k),
					http.WithEndpoint(l.Endpoint),
					http.WithAuthToken(l.AuthToken),
					http.WithLogKind(string(logger.All)),
					http.WithTransport(NewGatewayHTTPTransport()),
				),
			); err != nil {
				logger.LogIf(ctx, fmt.Errorf("Unable to initialize audit HTTP target: %w", err))
			}
		}
	}

	globalConfigTargetList, err = notify.GetNotificationTargets(GlobalContext, s, NewGatewayHTTPTransport(), false)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize notification target(s): %w", err))
	}

	globalEnvTargetList, err = notify.GetNotificationTargets(GlobalContext, newServerConfig(), NewGatewayHTTPTransport(), true)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize notification target(s): %w", err))
	}

	// Apply dynamic config values
	logger.LogIf(ctx, applyDynamicConfig(ctx, s))
}

// applyDynamicConfig will apply dynamic config values.
// Dynamic systems should be in config.SubSystemsDynamic as well.
func applyDynamicConfig(ctx context.Context, s config.Config) error {
	// Read all dynamic configs.
	// API
	apiConfig, err := api.LookupConfig(s[config.APISubSys][config.Default])
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Invalid api configuration: %w", err))
	}

	// Compression
	cmpCfg, err := compress.LookupConfig(s[config.CompressionSubSys][config.Default])
	if err != nil {
		return fmt.Errorf("Unable to setup Compression: %w", err)
	}
	objAPI := newObjectLayerFn()
	if objAPI != nil {
		if cmpCfg.Enabled && !objAPI.IsCompressionSupported() {
			return fmt.Errorf("Backend does not support compression")
		}
	}

	// Apply configurations.
	// We should not fail after this.
	globalAPIConfig.init(apiConfig)

	// Update all dynamic config values in memory.
	globalServerConfigMu.Lock()
	defer globalServerConfigMu.Unlock()
	if globalServerConfig != nil {
		for k := range config.SubSystemsDynamic {
			globalServerConfig[k] = s[k]
		}
	}
	return nil
}

// Help - return sub-system level help
type Help struct {
	SubSys          string         `json:"subSys"`
	Description     string         `json:"description"`
	MultipleTargets bool           `json:"multipleTargets"`
	KeysHelp        config.HelpKVS `json:"keysHelp"`
}

// GetHelp - returns help for sub-sys, a key for a sub-system or all the help.
func GetHelp(subSys, key string, envOnly bool) (Help, error) {
	if len(subSys) == 0 {
		return Help{KeysHelp: config.HelpSubSysMap[subSys]}, nil
	}
	subSystemValue := strings.SplitN(subSys, config.SubSystemSeparator, 2)
	if len(subSystemValue) == 0 {
		return Help{}, config.Errorf("invalid number of arguments %s", subSys)
	}

	subSys = subSystemValue[0]

	subSysHelp, ok := config.HelpSubSysMap[""].Lookup(subSys)
	if !ok {
		return Help{}, config.Errorf("unknown sub-system %s", subSys)
	}

	h, ok := config.HelpSubSysMap[subSys]
	if !ok {
		return Help{}, config.Errorf("unknown sub-system %s", subSys)
	}
	if key != "" {
		value, ok := h.Lookup(key)
		if !ok {
			return Help{}, config.Errorf("unknown key %s for sub-system %s",
				key, subSys)
		}
		h = config.HelpKVS{value}
	}

	envHelp := config.HelpKVS{}
	if envOnly {
		// Only for multiple targets, make sure
		// to list the ENV, for regular k/v EnableKey is
		// implicit, for ENVs we cannot make it implicit.
		if subSysHelp.MultipleTargets {
			envK := config.EnvPrefix + strings.Join([]string{
				strings.ToTitle(subSys), strings.ToTitle(madmin.EnableKey),
			}, config.EnvWordDelimiter)
			envHelp = append(envHelp, config.HelpKV{
				Key:         envK,
				Description: fmt.Sprintf("enable %s target, default is 'off'", subSys),
				Optional:    false,
				Type:        "on|off",
			})
		}
		for _, hkv := range h {
			envK := config.EnvPrefix + strings.Join([]string{
				strings.ToTitle(subSys), strings.ToTitle(hkv.Key),
			}, config.EnvWordDelimiter)
			envHelp = append(envHelp, config.HelpKV{
				Key:         envK,
				Description: hkv.Description,
				Optional:    hkv.Optional,
				Type:        hkv.Type,
			})
		}
		h = envHelp
	}

	return Help{
		SubSys:          subSys,
		Description:     subSysHelp.Description,
		MultipleTargets: subSysHelp.MultipleTargets,
		KeysHelp:        h,
	}, nil
}

func newServerConfig() config.Config {
	return config.New()
}

// newSrvConfig - initialize a new server config, saves env parameters if
// found, otherwise use default parameters
func newSrvConfig(objAPI ObjectLayer) error {
	// Initialize server config.
	srvCfg := newServerConfig()

	// hold the mutex lock before a new config is assigned.
	globalServerConfigMu.Lock()
	globalServerConfig = srvCfg
	globalServerConfigMu.Unlock()

	// Save config into file.
	return saveServerConfig(GlobalContext, objAPI, globalServerConfig)
}

func getValidConfig(objAPI ObjectLayer) (config.Config, error) {
	return readServerConfig(GlobalContext, objAPI)
}

// loadConfig - loads a new config from disk, overrides params
// from env if found and valid
func loadConfig(objAPI ObjectLayer) error {
	srvCfg, err := getValidConfig(objAPI)
	if err != nil {
		return err
	}

	// Override any values from ENVs.
	lookupConfigs(srvCfg)

	// hold the mutex lock before a new config is assigned.
	globalServerConfigMu.Lock()
	globalServerConfig = srvCfg
	globalServerConfigMu.Unlock()

	return nil
}

// getOpenIDValidators - returns ValidatorList which contains
// enabled providers in server config.
// A new authentication provider is added like below
// * Add a new provider in pkg/iam/openid package.
func getOpenIDValidators(cfg openid.Config) *openid.Validators {
	validators := openid.NewValidators()

	if cfg.JWKS.URL != nil {
		validators.Add(openid.NewJWT(cfg))
	}

	return validators
}
