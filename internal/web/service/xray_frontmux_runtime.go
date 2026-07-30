package service

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/frontmux"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/xray"
)

const (
	frontMuxBackendReadyTimeout = 5 * time.Second
	frontMuxBackendProbePeriod  = 50 * time.Millisecond
)

// startXrayRuntime starts the private Xray listeners first, waits until every
// frontmux backend is accepting TCP, and only then publishes public shared-port
// listeners. A failure tears down everything started by this attempt.
func startXrayRuntime(cfg *xray.Config) (*xray.Process, error) {
	process := xray.NewProcess(cfg)
	if err := process.Start(); err != nil {
		return process, err
	}
	if err := waitForFrontMuxBackends(cfg.SharedPortPlan, frontMuxBackendReadyTimeout); err != nil {
		stopErr := process.Stop()
		return process, errors.Join(err, stopErr)
	}
	if err := frontMuxManager.Start(cfg.SharedPortPlan); err != nil {
		stopErr := process.Stop()
		return process, errors.Join(fmt.Errorf("start shared-port frontmux: %w", err), stopErr)
	}
	return process, nil
}

// stopXrayRuntime releases public listeners before stopping Xray. This ordering
// guarantees that no new client is accepted after its private backend starts
// shutting down. Existing proxied connections are closed by Manager.Stop.
func stopXrayRuntime(process *xray.Process) error {
	frontMuxErr := frontMuxManager.Stop()
	var processErr error
	if process != nil && process.IsRunning() {
		processErr = process.Stop()
	}
	return errors.Join(frontMuxErr, processErr)
}

// recoverPreviousXrayRuntime restores the last known-good public topology after
// a failed stop. When the old Xray process is still alive, only the FrontMux
// listeners need to be republished; starting a second Xray process would create
// avoidable bind conflicts. When the process has exited, rebuild the complete
// previous runtime.
func recoverPreviousXrayRuntime(process *xray.Process, cfg *xray.Config) (*xray.Process, error) {
	if cfg == nil {
		return process, errors.New("previous Xray configuration is unavailable")
	}
	if process != nil && process.IsRunning() {
		if err := frontMuxManager.Start(cfg.SharedPortPlan); err != nil {
			return process, fmt.Errorf("restore previous shared-port listeners: %w", err)
		}
		return process, nil
	}
	return restoreXrayRuntime(cfg)
}

func restoreXrayRuntime(cfg *xray.Config) (*xray.Process, error) {
	if cfg == nil {
		return nil, errors.New("previous Xray configuration is unavailable")
	}
	process, err := startXrayRuntime(cfg)
	if err != nil {
		return process, fmt.Errorf("restore previous Xray/shared-port runtime: %w", err)
	}
	return process, nil
}

func waitForFrontMuxBackends(plan frontmux.Plan, timeout time.Duration) error {
	if plan.Empty() {
		return nil
	}
	backends := make(map[string]struct{})
	for _, group := range plan.Groups {
		for _, route := range group.Routes {
			backends[route.Backend] = struct{}{}
		}
	}
	pending := make([]string, 0, len(backends))
	for backend := range backends {
		pending = append(pending, backend)
	}
	sort.Strings(pending)

	deadline := time.Now().Add(timeout)
	for len(pending) > 0 {
		next := pending[:0]
		for _, backend := range pending {
			conn, err := net.DialTimeout("tcp", backend, 250*time.Millisecond)
			if err != nil {
				next = append(next, backend)
				continue
			}
			// Every shared backend requires PROXY protocol. Send a syntactically
			// valid UNKNOWN probe before closing so readiness checks do not create
			// malformed-header noise in the Xray log.
			_, _ = conn.Write([]byte("PROXY UNKNOWN\r\n"))
			_ = conn.Close()
		}
		pending = append([]string(nil), next...)
		if len(pending) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("shared-port backends did not become ready within %s: %v", timeout, pending)
		}
		time.Sleep(frontMuxBackendProbePeriod)
	}
	return nil
}

// StopSharedPortFrontMuxAfterXrayCrash is called by the web crash hook. It
// stops public listeners promptly so clients are never accepted into a dead
// backend topology. The normal restart job will publish them again only after
// the replacement Xray listeners are ready.
func StopSharedPortFrontMuxAfterXrayCrash() {
	if err := frontMuxManager.Stop(); err != nil {
		logger.Warning("stop shared-port frontmux after Xray crash: ", err)
	}
}
