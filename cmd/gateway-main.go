/*
 * MinIO Cloud Storage, (C) 2017-2020 MinIO, Inc.
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
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/minio/cli"
	xhttp "github.com/storj/minio/cmd/http"
	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/certs"
	"github.com/storj/minio/pkg/env"
)

var (
	gatewayCmd = cli.Command{
		Name:            "gateway",
		Usage:           "start object storage gateway",
		Flags:           append(ServerFlags, GlobalFlags...),
		HideHelpCommand: true,
	}
)

// RegisterGatewayCommand registers a new command for gateway.
func RegisterGatewayCommand(cmd cli.Command) error {
	cmd.Flags = append(append(cmd.Flags, ServerFlags...), GlobalFlags...)
	gatewayCmd.Subcommands = append(gatewayCmd.Subcommands, cmd)
	return nil
}

// ParseGatewayEndpoint - Return endpoint.
func ParseGatewayEndpoint(arg string) (endPoint string, secure bool, err error) {
	schemeSpecified := len(strings.Split(arg, "://")) > 1
	if !schemeSpecified {
		// Default connection will be "secure".
		arg = "https://" + arg
	}

	u, err := url.Parse(arg)
	if err != nil {
		return "", false, err
	}

	switch u.Scheme {
	case "http":
		return u.Host, false, nil
	case "https":
		return u.Host, true, nil
	default:
		return "", false, fmt.Errorf("Unrecognized scheme %s", u.Scheme)
	}
}

// ValidateGatewayArguments - Validate gateway arguments.
func ValidateGatewayArguments(serverAddr, endpointAddr string) error {
	if err := CheckLocalServerAddr(serverAddr); err != nil {
		return err
	}

	if endpointAddr != "" {
		// Reject the endpoint if it points to the gateway handler itself.
		sameTarget, err := sameLocalAddrs(endpointAddr, serverAddr)
		if err != nil {
			return err
		}
		if sameTarget {
			return fmt.Errorf("endpoint points to the local gateway")
		}
	}
	return nil
}

// StartGateway - handler for 'minio gateway <name>'.
func StartGateway(ctx *cli.Context, gw Gateway) {
	// This is only to uniquely identify each gateway deployments.
	globalDeploymentID = env.Get("MINIO_GATEWAY_DEPLOYMENT_ID", mustGetUUID())
	logger.SetDeploymentID(globalDeploymentID)

	if gw == nil {
		logger.FatalIf(errUnexpected, "Gateway implementation not initialized")
	}

	// Validate if we have access, secret set through environment.
	globalGatewayName = gw.Name()
	gatewayName := gw.Name()
	if ctx.Args().First() == "help" {
		cli.ShowCommandHelpAndExit(ctx, gatewayName, 1)
	}

	// Initialize globalConsoleSys system
	globalConsoleSys = NewConsoleLogger(GlobalContext)
	logger.AddTarget(globalConsoleSys)

	// Handle common command args.
	handleCommonCmdArgs(ctx)

	// Check and load TLS certificates.
	var err error
	globalPublicCerts, globalTLSCerts, globalIsSSL, err = getTLSConfig()
	logger.FatalIf(err, "Invalid TLS certificate file")

	// Check and load Root CAs.
	globalRootCAs, err = certs.GetRootCAs(globalCertsCADir.Get())
	logger.FatalIf(err, "Failed to read root CAs (%v)", err)

	// Add the global public crts as part of global root CAs
	for _, publicCrt := range globalPublicCerts {
		globalRootCAs.AddCert(publicCrt)
	}

	// Register root CAs for remote ENVs
	env.RegisterGlobalCAs(globalRootCAs)

	// Initialize all help
	initHelp()

	// Get port to listen on from gateway address
	globalMinioHost, globalMinioPort = mustSplitHostPort(globalCLIContext.Addr)

	// On macOS, if a process already listens on LOCALIPADDR:PORT, net.Listen() falls back
	// to IPv6 address ie minio will start listening on IPv6 address whereas another
	// (non-)minio process is listening on IPv4 of given port.
	// To avoid this error situation we check for port availability.
	logger.FatalIf(checkPortAvailability(globalMinioHost, globalMinioPort), "Unable to start the gateway")

	globalMinioEndpoint = func() string {
		host := globalMinioHost
		if host == "" {
			host = sortIPs(localIP4.ToSlice())[0]
		}
		return fmt.Sprintf("%s://%s", getURLScheme(globalIsSSL), net.JoinHostPort(host, globalMinioPort))
	}()

	// Handle gateway specific env
	gatewayHandleEnvVars()

	// Set system resources to maximum.
	setMaxResources()

	// Set when gateway is enabled
	globalIsGateway = true

	// TODO: We need to move this code with globalConfigSys.Init()
	// for now keep it here such that "s3" gateway layer initializes
	// itself properly when KMS is set.

	// Initialize server config.
	srvCfg := newServerConfig()

	// Override any values from ENVs.
	lookupConfigs(srvCfg)

	// hold the mutex lock before a new config is assigned.
	globalServerConfigMu.Lock()
	globalServerConfig = srvCfg
	globalServerConfigMu.Unlock()

	// Initialize router. `SkipClean(true)` stops gorilla/mux from
	// normalizing URL path minio/minio#3256
	// avoid URL path encoding minio/minio#8950
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	// Add API router.
	registerAPIRouter(router)

	// Use all the middlewares
	router.Use(registerMiddlewares)

	var getCert certs.GetCertificateFunc
	if globalTLSCerts != nil {
		getCert = globalTLSCerts.GetCertificate
	}

	httpServer := xhttp.NewServer([]string{globalCLIContext.Addr},
		CriticalErrorHandler{corsHandler(router)}, getCert)
	httpServer.BaseContext = func(listener net.Listener) context.Context {
		return GlobalContext
	}
	go func() {
		globalHTTPServerErrorCh <- httpServer.Start()
	}()

	globalObjLayerMutex.Lock()
	globalHTTPServer = httpServer
	globalObjLayerMutex.Unlock()

	signal.Notify(globalOSSignalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	newObject, err := gw.NewGatewayLayer(globalActiveCred)
	if err != nil {
		globalHTTPServer.Shutdown()
		logger.FatalIf(err, "Unable to initialize gateway backend")
	}

	// Calls all New() for all sub-systems.
	newAllSubsystems()

	// Once endpoints are finalized, initialize the new object api in safe mode.
	globalObjLayerMutex.Lock()
	globalObjectAPI = newObject
	globalObjLayerMutex.Unlock()

	globalIAMSys.InitStore(newObject)

	// Verify if object layer supports
	// - encryption
	// - compression
	verifyObjectLayerFeatures("gateway "+gatewayName, newObject)

	// Prints the formatted startup message once object layer is initialized.
	if !globalCLIContext.Quiet {
		// Print gateway startup message.
		printGatewayStartupMessage(getAPIEndpoints(), gatewayName)
	}

	handleSignals()
}
