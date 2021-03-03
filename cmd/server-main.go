/*
 * MinIO Cloud Storage, (C) 2015-2019 MinIO, Inc.
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
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/minio/cli"
	"github.com/storj/minio/cmd/config"
	xhttp "github.com/storj/minio/cmd/http"
	"github.com/storj/minio/cmd/logger"
	"github.com/storj/minio/pkg/bucket/bandwidth"
	"github.com/storj/minio/pkg/certs"
	"github.com/storj/minio/pkg/env"
)

// ServerFlags - server command specific flags
var ServerFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "address",
		Value: ":" + GlobalMinioDefaultPort,
		Usage: "bind to a specific ADDRESS:PORT, ADDRESS can be an IP or hostname",
	},
}

var serverCmd = cli.Command{
	Name:   "server",
	Usage:  "start object storage server",
	Flags:  append(ServerFlags, GlobalFlags...),
	Action: serverMain,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS] {{end}}DIR1 [DIR2..]
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS] {{end}}DIR{1...64}
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS] {{end}}DIR{1...64} DIR{65...128}

DIR:
  DIR points to a directory on a filesystem. When you want to combine
  multiple drives into a single large system, pass one directory per
  filesystem separated by space. You may also use a '...' convention
  to abbreviate the directory arguments. Remote directories in a
  distributed setup are encoded as HTTP(s) URIs.
{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
EXAMPLES:
  1. Start minio server on "/home/shared" directory.
     {{.Prompt}} {{.HelpName}} /home/shared

  2. Start single node server with 64 local drives "/mnt/data1" to "/mnt/data64".
     {{.Prompt}} {{.HelpName}} /mnt/data{1...64}

  3. Start distributed minio server on an 32 node setup with 32 drives each, run following command on all the nodes
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}minio
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}miniostorage
     {{.Prompt}} {{.HelpName}} http://node{1...32}.example.com/mnt/export{1...32}

  4. Start distributed minio server in an expanded setup, run the following command on all the nodes
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}minio
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}miniostorage
     {{.Prompt}} {{.HelpName}} http://node{1...16}.example.com/mnt/export{1...32} \
            http://node{17...64}.example.com/mnt/export{1...64}
`,
}

func serverCmdArgs(ctx *cli.Context) []string {
	v := env.Get(config.EnvArgs, "")
	if v == "" {
		// Fall back to older ENV MINIO_ENDPOINTS
		v = env.Get(config.EnvEndpoints, "")
	}
	if v == "" {
		if !ctx.Args().Present() || ctx.Args().First() == "help" {
			cli.ShowCommandHelpAndExit(ctx, ctx.Command.Name, 1)
		}
		return ctx.Args()
	}
	return strings.Fields(v)
}

func serverHandleCmdArgs(ctx *cli.Context) {
	// Handle common command args.
	handleCommonCmdArgs(ctx)

	logger.FatalIf(CheckLocalServerAddr(globalCLIContext.Addr), "Unable to validate passed arguments")

	var err error

	// Check and load TLS certificates.
	globalPublicCerts, globalTLSCerts, globalIsSSL, err = getTLSConfig()
	logger.FatalIf(err, "Unable to load the TLS configuration")

	// Check and load Root CAs.
	globalRootCAs, err = certs.GetRootCAs(globalCertsCADir.Get())
	logger.FatalIf(err, "Failed to read root CAs (%v)", err)

	// Add the global public crts as part of global root CAs
	for _, publicCrt := range globalPublicCerts {
		globalRootCAs.AddCert(publicCrt)
	}

	// Register root CAs for remote ENVs
	env.RegisterGlobalCAs(globalRootCAs)

	globalMinioAddr = globalCLIContext.Addr

	globalMinioHost, globalMinioPort = mustSplitHostPort(globalMinioAddr)
	globalEndpoints, _, err = createServerEndpoints(globalCLIContext.Addr, serverCmdArgs(ctx)...)
	logger.FatalIf(err, "Invalid command line arguments")

	// On macOS, if a process already listens on LOCALIPADDR:PORT, net.Listen() falls back
	// to IPv6 address ie minio will start listening on IPv6 address whereas another
	// (non-)minio process is listening on IPv4 of given port.
	// To avoid this error situation we check for port availability.
	logger.FatalIf(checkPortAvailability(globalMinioHost, globalMinioPort), "Unable to start the server")
}

func serverHandleEnvVars() {
	// Handle common environment variables.
	handleCommonEnvVars()
}

var globalHealStateLK sync.RWMutex

func newAllSubsystems() {
	// Create the bucket bandwidth monitor
	globalBucketMonitor = bandwidth.NewMonitor(GlobalServiceDoneCh)

	// Create a new config system.
	globalConfigSys = NewConfigSys()

	// Create new IAM system.
	globalIAMSys = NewIAMSys()

	// Create new policy system.
	globalPolicySys = NewPolicySys()

	// Create new bucket versioning subsystem
	globalBucketVersioningSys = NewBucketVersioningSys()
}

func initServer(ctx context.Context, newObject ObjectLayer) error {
	// Once the config is fully loaded, initialize the new object layer.
	globalObjLayerMutex.Lock()
	globalObjectAPI = newObject
	globalObjLayerMutex.Unlock()

	return nil
}

func initAllSubsystems(ctx context.Context, newObject ObjectLayer) (err error) {
	// Initialize config system.
	if err = globalConfigSys.Init(newObject); err != nil {
		if errors.Is(err, errDiskNotFound) ||
			errors.Is(err, errConfigNotFound) ||
			errors.Is(err, context.DeadlineExceeded) ||
			isErrBucketNotFound(err) {
			return fmt.Errorf("Unable to initialize config system: %w", err)
		}
		// Any other config errors we simply print a message and proceed forward.
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize config, some features may be missing %w", err))
	}

	// Initialize IAM store
	globalIAMSys.InitStore(newObject)

	return nil
}

// serverMain handler called for 'minio server' command.
func serverMain(ctx *cli.Context) {
	signal.Notify(globalOSSignalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	go handleSignals()

	setDefaultProfilerRates()

	// Initialize globalConsoleSys system
	globalConsoleSys = NewConsoleLogger(GlobalContext)
	logger.AddTarget(globalConsoleSys)

	// Handle all server command args.
	serverHandleCmdArgs(ctx)

	// Handle all server environment vars.
	serverHandleEnvVars()

	// Set node name, only set for distributed setup.
	globalConsoleSys.SetNodeName(globalEndpoints)

	// Initialize all help
	initHelp()

	// Initialize all sub-systems
	newAllSubsystems()

	globalMinioEndpoint = func() string {
		host := globalMinioHost
		if host == "" {
			host = sortIPs(localIP4.ToSlice())[0]
		}
		return fmt.Sprintf("%s://%s", getURLScheme(globalIsSSL), net.JoinHostPort(host, globalMinioPort))
	}()

	// Set system resources to maximum.
	setMaxResources()

	// Configure server.
	handler, err := configureServerHandler(globalEndpoints)
	if err != nil {
		logger.Fatal(config.ErrUnexpectedError(err), "Unable to configure one of server's RPC services")
	}

	var getCert certs.GetCertificateFunc
	if globalTLSCerts != nil {
		getCert = globalTLSCerts.GetCertificate
	}

	httpServer := xhttp.NewServer([]string{globalMinioAddr}, CriticalErrorHandler{corsHandler(handler)}, getCert)
	httpServer.BaseContext = func(listener net.Listener) context.Context {
		return GlobalContext
	}
	go func() {
		globalHTTPServerErrorCh <- httpServer.Start()
	}()

	globalObjLayerMutex.Lock()
	globalHTTPServer = httpServer
	globalObjLayerMutex.Unlock()

	logger.SetDeploymentID(globalDeploymentID)

	<-globalOSSignalCh
}
