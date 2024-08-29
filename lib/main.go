package main

import "C"

import (
	"context"
	"math"
	"net/url"
	"os"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/sloghuman"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/codersdk/workspacesdk"
)

type tunnel struct {
	client *codersdk.Client
	conn   *workspacesdk.AgentConn
	logger slog.Logger
}

var tunnelHandles map[int32]tunnel

func init() {
	tunnelHandles = make(map[int32]tunnel)
}

func main() {}

//export coderStartVPN
func coderStartVPN(serverURL, token, workspaceName *C.char, tunFileDescriptor, logFileDescriptor int32) int32 {
	ctx := context.Background()
	logger, err := makeLogger(logFileDescriptor)
	if err != nil {
		return -1
	}
	goServerURL := C.GoString(serverURL)
	logger.Info(ctx, "starting CoderVPN tunnel",
		slog.F("coder_url", goServerURL),
		slog.F("tunnel_file_descriptor", tunFileDescriptor))

	su, err := url.Parse(goServerURL)
	if err != nil {
		logger.Critical(ctx, "failed to parse server URL", slog.Error(err))
		return -1
	}
	client := codersdk.New(su)
	client.SetLogger(logger)
	client.SetSessionToken(C.GoString(token))

	workspace, err := client.WorkspaceByOwnerAndName(ctx, codersdk.Me, C.GoString(workspaceName), codersdk.WorkspaceOptions{})
	if err != nil {
		logger.Error(ctx, "failed to get workspace", slog.Error(err))
		return -1
	}
	agent, err := getWorkspaceAgent(workspace)
	if err != nil {
		logger.Error(ctx, "failed to get agent", slog.Error(err))
		return -1
	}

	dev, err := makeTUN(int(tunFileDescriptor))
	if err != nil {
		logger.Error(ctx, "failed to create tun", slog.Error(err))
		return -1
	}

	opts := &workspacesdk.DialAgentOptions{
		TUNDev:          dev,
		Logger:          logger,
		EnableTelemetry: true,
	}

	conn, err := workspacesdk.New(client).DialAgent(ctx, agent.ID, opts)
	if err != nil {
		dev.Close()
		logger.Error(ctx, "failed to dial agent", slog.Error(err))
		return -1
	}

	go func() {
		conn.AwaitReachable(ctx)
		logger.Info(ctx, "Ready!")
	}()

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		logger.Error(ctx, "out of handles")
		conn.Close()
		return -1
	}
	tunnelHandles[i] = tunnel{
		client: client,
		conn:   conn,
		logger: logger,
	}
	return i
}

//export coderStopVPN
func coderStopVPN(handle int32) int32 {
	ctx := context.Background()
	t, ok := tunnelHandles[handle]
	if !ok {
		return -1
	}
	delete(tunnelHandles, handle)
	err := t.conn.Close()
	if err != nil {
		t.logger.Error(ctx, "failed to close conn", slog.Error(err))
		return -1
	}
	return 0
}

func makeTUN(tunFd int) (tun.Device, error) {
	dupTunFd, err := unix.Dup(tunFd)
	if err != nil {
		return nil, xerrors.Errorf("dup tun fd: %w", err)
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		unix.Close(dupTunFd)
		return nil, xerrors.Errorf("set nonblock: %w", err)
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		unix.Close(dupTunFd)
		return nil, xerrors.Errorf("create TUN from File: %w", err)
	}
	return tun, nil
}

func makeLogger(fd int32) (slog.Logger, error) {
	dupFd, err := unix.Dup(int(fd))
	if err != nil {
		return slog.Logger{}, xerrors.Errorf("dup log fd: %w", err)
	}

	err = unix.SetNonblock(dupFd, true)
	if err != nil {
		unix.Close(dupFd)
		return slog.Logger{}, xerrors.Errorf("set log fd nonblock: %w", err)
	}
	out := os.NewFile(uintptr(dupFd), "PIPE")
	if out == nil {
		unix.Close(dupFd)
		return slog.Logger{}, xerrors.Errorf("create log File: %w", err)
	}
	return slog.Make(sloghuman.Sink(out)).Leveled(slog.LevelDebug), nil
}

func getWorkspaceAgent(workspace codersdk.Workspace) (workspaceAgent codersdk.WorkspaceAgent, err error) {
	resources := workspace.LatestBuild.Resources

	agents := make([]codersdk.WorkspaceAgent, 0)
	for _, resource := range resources {
		agents = append(agents, resource.Agents...)
	}
	if len(agents) == 0 {
		return codersdk.WorkspaceAgent{}, xerrors.Errorf("workspace %q has no agents", workspace.Name)
	}
	return agents[0], nil
}
