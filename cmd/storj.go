// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package cmd

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/minio/minio/cmd/config/policy/opa"
	xhttp "github.com/minio/minio/cmd/http"
	xnet "github.com/minio/minio/pkg/net"
)

// CriticalErrorHandler exports CriticalErrorHandler
// Used in pkg/server/server.go
func CriticalErrorHandler(handler http.Handler) http.Handler {
	return criticalErrorHandler{handler: handler}
}

// ObjectAPIHandlers exports objectAPIHandlers
// Used in pkg/server/api-router.go
type ObjectAPIHandlers = objectAPIHandlers

// CorsHandler handler for CORS (Cross Origin Resource Sharing)
// Used in pkg/server/server.go
func CorsHandler(handler http.Handler) http.Handler {
	return corsHandler(handler)
}

// RegisterMiddlewares exports RegisterMiddlewares.
// Used in pkg/server/server.go
func RegisterMiddlewares(next http.Handler) http.Handler {
	return registerMiddlewares(next)
}

func RegisterHealthCheckRouter(router *mux.Router) {
	// Add healthcheck router
	registerHealthCheckRouter(router)
}

func RegisterMetricsRouter(router *mux.Router) {
	// Add server metrics router
	registerMetricsRouter(router)
}

func RegisterAPIRouter(router *mux.Router) {
	registerAPIRouter(router)
}

//todo:  set globalAPIConfig.getCorsAllowOrigins() or merge b0adac24cc4ee29413fb49f6f2ef783a95437249

type allowAllOPA struct{}

func (s allowAllOPA) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(strings.NewReader(`{"result":true}`)),
	}, nil
}

// StartMinio is a possible alternative to everything else above
func StartMinio(address, AuthURL, AuthToken string, gatewayLayer ObjectLayer) {
	// wire up domain names for Minio
	handleCommonEnvVars()
	// make Minio not use random ETags
	globalCLIContext.JSON = false
	globalCLIContext.Quiet = true
	globalCLIContext.Anonymous = false
	globalCLIContext.Addr = address
	globalCLIContext.StrictS3Compat = true

	store := NewIAMStorjAuthStore(gatewayLayer, AuthURL, AuthToken)
	setObjectLayer(gatewayLayer)
	iamSys := NewIAMSys()
	iamSys.store = store
	iamSys.usersSysType = "StorjAuthSys"
	globalIAMSys = iamSys

	// force globalIAMSys.IsAllowed() to always return true
	globalPolicyOPA = opa.New(opa.Args{URL: &xnet.URL{Scheme: "http"}, AuthToken: " ", Transport: allowAllOPA{}, CloseRespFn: xhttp.DrainBody})

	globalIsGateway = true
	globalNotificationSys = NewNotificationSys(globalEndpoints)
	globalBucketQuotaSys = NewBucketQuotaSys()
}
