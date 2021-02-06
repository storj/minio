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
	"net/http"
	"sync"
	"time"

	"github.com/storj/minio/cmd/config/api"
)

type apiConfig struct {
	mu sync.RWMutex

	requestsDeadline time.Duration
	requestsPool     chan struct{}
	extendListLife   time.Duration
	corsAllowOrigins []string
}

func (t *apiConfig) init(cfg api.Config) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.corsAllowOrigins = cfg.CorsAllowOrigin

	var apiRequestsMaxPerNode int
	apiRequestsMaxPerNode = cfg.RequestsMax
	if len(globalEndpoints.Hostnames()) > 0 {
		apiRequestsMaxPerNode /= len(globalEndpoints.Hostnames())
	}

	if cap(t.requestsPool) < apiRequestsMaxPerNode {
		// Only replace if needed.
		// Existing requests will use the previous limit,
		// but new requests will use the new limit.
		// There will be a short overlap window,
		// but this shouldn't last long.
		t.requestsPool = make(chan struct{}, apiRequestsMaxPerNode)
	}
	t.requestsDeadline = cfg.RequestsDeadline
	t.extendListLife = cfg.ExtendListLife
}

func (t *apiConfig) getExtendListLife() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.extendListLife
}

func (t *apiConfig) getCorsAllowOrigins() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	corsAllowOrigins := make([]string, len(t.corsAllowOrigins))
	copy(corsAllowOrigins, t.corsAllowOrigins)
	return corsAllowOrigins
}

func (t *apiConfig) getRequestsPool() (chan struct{}, time.Duration) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.requestsPool == nil {
		return nil, time.Duration(0)
	}

	return t.requestsPool, t.requestsDeadline
}

// maxClients throttles the S3 API calls
func maxClients(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pool, deadline := globalAPIConfig.getRequestsPool()
		if pool == nil {
			f.ServeHTTP(w, r)
			return
		}

		deadlineTimer := time.NewTimer(deadline)
		defer deadlineTimer.Stop()

		select {
		case pool <- struct{}{}:
			defer func() { <-pool }()
			f.ServeHTTP(w, r)
		case <-deadlineTimer.C:
			// Send a http timeout message
			writeErrorResponse(r.Context(), w,
				errorCodes.ToAPIErr(ErrOperationMaxedOut),
				r.URL)
			return
		case <-r.Context().Done():
			return
		}
	}
}
