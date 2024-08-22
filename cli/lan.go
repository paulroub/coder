package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/sloghuman"
	"github.com/coder/coder/v2/cli/cliui"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/codersdk/workspacesdk"
	"github.com/coder/coder/v2/tailnet"
	"github.com/coder/serpent"
)

func (r *RootCmd) lan() *serpent.Command {
	var (
		disableAutostart  bool
		tunFileDescriptor int64
	)
	client := new(codersdk.Client)
	cmd := &serpent.Command{
		Use:     "lan <workspace>",
		Short:   `Make a workspace available via a LAN-like experience.`,
		Aliases: []string{"bridge"},
		Middleware: serpent.Chain(
			serpent.RequireNArgs(1),
			r.InitClient(client),
		),
		Hidden: true,
		Handler: func(inv *serpent.Invocation) (retErr error) {
			ctx, cancel := context.WithCancel(inv.Context())
			defer cancel()

			workspace, workspaceAgent, err := getWorkspaceAndAgent(ctx, inv, client, !disableAutostart, inv.Args[0])
			if err != nil {
				return err
			}
			if workspace.LatestBuild.Transition != codersdk.WorkspaceTransitionStart {
				return xerrors.New("workspace must be in start transition to port-forward")
			}
			if workspace.LatestBuild.Job.CompletedAt == nil {
				err = cliui.WorkspaceBuild(ctx, inv.Stderr, client, workspace.LatestBuild.ID)
				if err != nil {
					return err
				}
			}
			err = writeHosts([]hostEntry{
				{
					ip:       tailnet.IPFromUUID(workspaceAgent.ID),
					hostname: workspace.Name + ".coderlan",
				},
			})
			if err != nil {
				return xerrors.Errorf("failed to write /etc/hosts: %w", err)
			}

			err = cliui.Agent(ctx, inv.Stderr, workspaceAgent.ID, cliui.AgentOptions{
				Fetch: client.WorkspaceAgent,
				Wait:  false,
			})
			if err != nil {
				return xerrors.Errorf("await agent: %w", err)
			}

			tunDev, err := makeTUN(int(tunFileDescriptor))
			if err != nil {
				return xerrors.Errorf("make TUN: %w", err)
			}
			opts := &workspacesdk.DialAgentOptions{
				TUNDev: tunDev,
			}

			logger := inv.Logger
			opts.Logger = logger.AppendSinks(sloghuman.Sink(inv.Stderr)).Leveled(slog.LevelDebug)

			if r.disableDirect {
				_, _ = fmt.Fprintln(inv.Stderr, "Direct connections disabled.")
				opts.BlockEndpoints = true
			}
			if !r.disableNetworkTelemetry {
				opts.EnableTelemetry = true
			}
			conn, err := workspacesdk.New(client).DialAgent(ctx, workspaceAgent.ID, opts)
			if err != nil {
				return err
			}
			defer conn.Close()

			stopUpdating := client.UpdateWorkspaceUsageWithBodyContext(ctx, workspace.ID, codersdk.PostWorkspaceUsageRequest{
				AgentID: workspaceAgent.ID,
				// TODO: lies
				AppName: codersdk.UsageAppNameSSH,
			})

			// Wait for the context to be canceled or for a signal
			var closeErr error
			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()

				sigs := make(chan os.Signal, 1)
				signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

				select {
				case <-ctx.Done():
					logger.Debug(ctx, "command context expired waiting for signal", slog.Error(ctx.Err()))
					closeErr = ctx.Err()
				case sig := <-sigs:
					logger.Debug(ctx, "received signal", slog.F("signal", sig))
					_, _ = fmt.Fprintln(inv.Stderr, "\nReceived signal, closing all listeners and active connections")
				}

				cancel()
				stopUpdating()
			}()

			conn.AwaitReachable(ctx)
			logger.Debug(ctx, "read to accept connections to forward")
			_, _ = fmt.Fprintln(inv.Stderr, "Ready!")
			wg.Wait()
			return closeErr
		},
	}

	cmd.Options = serpent.OptionSet{
		sshDisableAutostartOption(serpent.BoolOf(&disableAutostart)),
		serpent.Option{
			Flag:          "tunFileDescriptor",
			FlagShorthand: "t",
			Description:   "File descriptor of the TUN device.",
			Value:         serpent.Int64Of(&tunFileDescriptor),
		},
	}

	return cmd
}

type hostEntry struct {
	ip       netip.Addr
	hostname string
}

const coderHostsBegin = "# BEGIN CODER LAN CONFIG"

func writeHosts(hosts []hostEntry) error {
	hostFile, err := os.OpenFile("/etc/hosts", os.O_RDWR, 0)
	if err != nil {
		return xerrors.Errorf("open /etc/hosts: %w", err)
	}
	defer hostFile.Close()
	s := bufio.NewScanner(hostFile)
	newHosts := &strings.Builder{}
	for s.Scan() {
		if s.Text() == coderHostsBegin {
			break
		}
		_, _ = newHosts.Write(s.Bytes())
		_, _ = newHosts.WriteString("\n")
	}
	_, _ = newHosts.WriteString(coderHostsBegin)
	_, _ = newHosts.WriteString("\n")
	for _, host := range hosts {
		_, _ = fmt.Fprintf(newHosts, "%s %s\n", host.ip.String(), host.hostname)
	}

	// clear existing
	_, err = hostFile.Seek(0, 0)
	if err != nil {
		return xerrors.Errorf("seek: %w", err)
	}
	err = hostFile.Truncate(0)
	if err != nil {
		return xerrors.Errorf("truncate: %w", err)
	}
	_, err = hostFile.WriteString(newHosts.String())
	if err != nil {
		return xerrors.Errorf("write hosts: %w", err)
	}
	return nil
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
