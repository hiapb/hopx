package node

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"hopx/internal/certificate"
	"hopx/internal/relay"
	"hopx/internal/wire"
)

var ErrRestart = errors.New("node upgrade staged")

type Settings struct {
	ReverseAddress, ReverseListen                                                  string
	ReverseOnly                                                                    bool
	UDPSmartBind                                                                   bool
	Panel, Directory, Enrollment, Name, Region, Address, IPv4, IPv6                string
	RelayListen, RelayAddress, RelayTransport, Bind, Interface, Version, PublicKey string
	Executable                                                                     string
	MaxListeners, MaxConnections                                                   int
	Period                                                                         time.Duration
}

type localState struct {
	wire.Identity
	Registration wire.Registration
	RelayKey     string
	ReverseKey   string
}

func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".hopx-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func toFile(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomicFile(path, b, 0600)
}

func fromFile(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}

type controlError struct {
	status int
	text   string
}

func (e controlError) Error() string { return fmt.Sprintf("panel returned %d: %s", e.status, e.text) }

func api(ctx context.Context, client *http.Client, panel, path, key string, id int64, input, output any) error {
	raw, e := json.Marshal(input)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(panel, "/")+path, bytes.NewReader(raw))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	if id != 0 {
		req.Header.Set("X-Node-ID", strconv.FormatInt(id, 10))
	}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return controlError{status: resp.StatusCode, text: strings.TrimSpace(string(b))}
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(output)
}

func loadIdentity(settings Settings) (localState, error) {
	var state localState
	name := filepath.Join(settings.Directory, "identity.json")
	if err := fromFile(name, &state); err == nil {
		return state, nil
	} else if !os.IsNotExist(err) {
		return state, err
	}
	if settings.Enrollment == "" {
		return state, errors.New("registration token required")
	}
	state.Registration = wire.Registration{Name: settings.Name, Region: settings.Region, Address: settings.Address, IPv4: settings.IPv4, IPv6: settings.IPv6, RelayAddress: settings.RelayAddress, RelayTransport: settings.RelayTransport}
	if state.Registration.IPv4 == "" || state.Registration.IPv6 == "" {
		addresses, _ := net.InterfaceAddrs()
		for _, address := range addresses {
			var ip net.IP
			if candidate, ok := address.(*net.IPNet); ok {
				ip = candidate.IP
			}
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			if ip.To4() != nil && state.Registration.IPv4 == "" {
				state.Registration.IPv4 = ip.String()
			}
			if ip.To4() == nil && state.Registration.IPv6 == "" {
				state.Registration.IPv6 = ip.String()
			}
		}
	}
	if settings.RelayAddress != "" {
		var err error
		state.Registration.RelayCert, state.RelayKey, err = certificate.SelfSigned(settings.RelayAddress)
		if err != nil {
			return state, err
		}
		state.Registration.RelayToken = rand.Text() + rand.Text()
	}
	if settings.ReverseAddress != "" {
		var err error
		state.Registration.ReverseAddress = settings.ReverseAddress
		state.Registration.ReverseCertificate, state.ReverseKey, err = certificate.SelfSigned(settings.ReverseAddress)
		if err != nil {
			return state, err
		}
		state.Registration.ReverseToken = rand.Text() + rand.Text()
	}
	if settings.ReverseOnly {
		state.Registration.ReverseID = rand.Text()
		state.Registration.RelayToken = rand.Text() + rand.Text()
	}
	return state, nil
}

func Run(ctx context.Context, settings Settings) error {
	base, e := url.Parse(settings.Panel)
	if e != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" || base.User != nil {
		return errors.New("invalid panel URL")
	}
	if settings.MaxConnections < 1 || settings.MaxListeners < 1 || settings.Period <= 0 {
		return errors.New("node limits and sync period must be positive")
	}
	if e = os.MkdirAll(settings.Directory, 0700); e != nil {
		return e
	}
	startupPath := filepath.Join(settings.Directory, "startup.status")
	_ = os.Remove(startupPath)
	startupStatus := ""
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if _, err := os.Stat(filepath.Join(settings.Directory, "revoked")); err == nil {
		return nil
	}
	state, e := loadIdentity(settings)
	if e != nil {
		return e
	}
	maxListeners, maxConnections := fileDescriptorBudget(settings.MaxListeners, settings.MaxConnections, state.Registration.RelayAddress != "" || state.Registration.ReverseID != "")
	maxConnections = memorySessionLimit(maxConnections)
	if maxListeners < 1 || maxConnections < 1 {
		return errors.New("file descriptor limit too low")
	}
	engine := NewEngine(settings.Bind, maxListeners, maxConnections)
	engine.proxy.binary, _ = exec.LookPath("haproxy")
	engine.proxy.stateDir = settings.Directory
	if settings.UDPSmartBind {
		engine.udpBind, e = interfaceUDPAddresses()
		if e != nil {
			return e
		}
	}
	dataContext, stopData := context.WithCancel(ctx)
	defer stopData()
	defer engine.Close()
	var relayBind string
	var relayListener net.Listener
	initialRelayMode := state.Registration.RelayTransport
	if initialRelayMode == "" {
		initialRelayMode = "tls"
	}
	activeRelayMode := initialRelayMode
	listenRelay := func(bind, mode string) (net.Listener, error) {
		return relay.ListenWithSlots(dataContext, bind, state.Registration.RelayCert, state.RelayKey, state.Registration.RelayToken, mode, engine.slots, engine.meterTarget)
	}
	if state.Registration.RelayAddress != "" {
		if settings.RelayListen == "" {
			return errors.New("relay listener required")
		}
		relayListener, e = listenRelay(settings.RelayListen, activeRelayMode)
		if e != nil {
			return e
		}
		relayBind = relayListener.Addr().String()
		defer func() {
			if relayListener != nil {
				relayListener.Close()
			}
		}()
	}
	if state.Registration.ReverseAddress != "" {
		engine.reverse = relay.NewReverseHub(true)
		bind := settings.ReverseListen
		if bind == "" {
			_, port, _ := net.SplitHostPort(state.Registration.ReverseAddress)
			bind = net.JoinHostPort("", port)
		}
		ln, err := engine.reverse.Listen(dataContext, bind, state.Registration.ReverseCertificate, state.ReverseKey, state.Registration.ReverseToken)
		if err != nil {
			return err
		}
		defer ln.Close()
	}
	var reverseClient *relay.ReverseClient
	if state.Registration.ReverseID != "" {
		reverseClient, e = relay.NewReverseClientWithSlots(dataContext, state.Registration.ReverseID, state.Registration.RelayToken, engine.slots, engine.meterTarget)
		if e != nil {
			return e
		}
	}
	if state.ID == 0 {
		if e = api(ctx, client, settings.Panel, "/api/node/register", settings.Enrollment, 0, state.Registration, &state.Identity); e != nil {
			return e
		}
		if e = toFile(filepath.Join(settings.Directory, "identity.json"), state); e != nil {
			return e
		}
	}
	verifyUpgrade, e := pendingUpgrade(settings)
	if e != nil {
		return e
	}
	cached := filepath.Join(settings.Directory, "active-routes.json")
	legacyCached := filepath.Join(settings.Directory, "active.json")
	startupCache := cached
	currentInfo, currentErr := os.Stat(cached)
	legacyInfo, legacyErr := os.Stat(legacyCached)
	if legacyErr == nil && (os.IsNotExist(currentErr) || (currentErr == nil && legacyInfo.ModTime().After(currentInfo.ModTime()))) {
		startupCache = legacyCached
	}
	var config wire.Config
	if e = fromFile(startupCache, &config); e == nil {
		if e = wire.DecodeRoutes(config.Rules, config.RouteSets, config.HopTable); e != nil {
			return fmt.Errorf("load last applied routes: %w", e)
		}
		config.RouteSets = nil
		config.HopTable = nil
		for i := range config.Rules {
			forward := &config.Rules[i]
			if forward.HAProxy {
				forward.Protocol = (wire.DeviceGroup{}).RuleNetwork(forward.Rule)
			}
		}
		startup := config
		if slices.ContainsFunc(config.Rules, meteredProxy) {
			startup.Rules = slices.DeleteFunc(slices.Clone(config.Rules), meteredProxy)
			startup.Revision = "waiting-for-traffic-sync"
		}
		if e = engine.Apply(dataContext, startup, nil); e != nil {
			if verifyUpgrade {
				return fmt.Errorf("load last applied config: %w", e)
			}
			slog.Warn("load last applied config", "error", e)
			_ = atomicFile(filepath.Join(settings.Directory, "apply.error"), []byte(e.Error()), 0600)
			config = wire.Config{}
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	upgradeDeadline := time.Now().Add(40 * time.Second)
	upgradeHealthy := 0
	upgradeRevision := ""
	managedUpgrade := settings.PublicKey != "" && settings.Executable != ""
	spool := filepath.Join(settings.Directory, "reports")
	if e = os.MkdirAll(spool, 0700); e != nil {
		return e
	}
	quotaPath := filepath.Join(settings.Directory, "quota-closing.json")
	defer func() {
		stopData()
		engine.Close()
		done := make(chan struct{})
		go func() {
			engine.workers.Wait()
			engine.exitMu.Lock()
			engine.exitMu.Unlock()
			engine.exitWorkers.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		claims := engine.quota.claims(true)
		safe := []wire.QuotaClaim{}
		for _, claim := range claims {
			if claim.ID != "" && claim.Close {
				safe = append(safe, claim)
			}
		}
		if err := toFile(quotaPath, safe); err != nil {
			slog.Warn("quota closing state", "error", err)
		}
		if _, err := prepareReport(engine, spool); err != nil {
			slog.Warn("final traffic spool", "error", err)
		}
	}()
	if err := fromFile(quotaPath, &engine.quota.retired); err != nil && !os.IsNotExist(err) {
		return err
	}
	generation := rand.Text()
	var gauge sampler
	gauge.network.iface = settings.Interface
	var candidateVersion string
	var retryAfter time.Time
	attempts := 0
	forceSnapshot := false
	var diagnostic *wire.DiagnosticResult
	diagnostics := make(chan *wire.DiagnosticResult, 1)
	var pendingDiagnostic string
	var nativeListener net.Listener
	var stopNative context.CancelFunc
	var nativeErr, relayModeErr string
	var relayModeRetry time.Time
	var stopBandwidth context.CancelFunc
	key := hmac.New(sha256.New, []byte(state.RelayKey))
	_, _ = key.Write([]byte("hopx DTLS relay key v1"))
	nativeKey := hex.EncodeToString(key.Sum(nil))
	defer func() {
		if stopBandwidth != nil {
			stopBandwidth()
		}
		if stopNative != nil {
			stopNative()
			nativeListener.Close()
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		delay := settings.Period
		engine.mux.SweepIdle()
		report, reportErr := prepareReport(engine, spool)
		if reportErr != nil {
			slog.Warn("traffic spool", "error", reportErr)
		}
		revision, listeners, connections := engine.Status()
		metrics := gauge.sample(settings.Directory)
		metrics.Listeners, metrics.Connections = listeners, int64(connections)
		metrics.ListenerLimit, metrics.ConnectionLimit = maxListeners, maxConnections
		metrics.BindAddresses = len(engine.bind)
		metrics.UDPBindAddresses = len(engine.udpBind)
		metrics.TCPConnections, metrics.UDPSessions = engine.activeTCP.Load(), engine.activeUDP.Load()
		metrics.UDPDrop = engine.udpDropped.Load()
		heartbeat := wire.Heartbeat{Version: settings.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Revision: revision, Metrics: metrics, Report: report, AcceptTLSPolicy: true, AcceptRouteSets: true, AcceptSharedTLS: true, AcceptIngress: true, AcceptRuleProbe: true, AcceptRelayTransports: true, AcceptUDPProxy: true, AcceptWebsocketMux: true, AcceptAlternateRelayAddress: true, AcceptPing: true}
		if nativeListener != nil {
			heartbeat.NativeUDPKey = nativeKey
		}
		heartbeat.NativeUDPError = nativeErr
		if relayBind != "" {
			heartbeat.ActiveRelayMode, heartbeat.RelayModeError = activeRelayMode, relayModeErr
		}
		heartbeat.AcceptExitMeter = true
		heartbeat.AcceptScopedReverse = true
		heartbeat.AcceptPublicTargets = true
		heartbeat.AcceptDelta = !forceSnapshot
		heartbeat.AcceptRouteProbe = true
		heartbeat.AcceptLinkProbe = true
		heartbeat.AcceptFET = true
		heartbeat.AcceptHopTable = true
		heartbeat.UpgradePending = verifyUpgrade
		heartbeat.ManagedUpgrade = &managedUpgrade
		heartbeat.Diagnostic = diagnostic
		heartbeat.QuotaGeneration, heartbeat.QuotaClaims = generation, engine.quota.claims(false)
		heartbeat.ApplyError = localMessage(settings.Directory, "apply.error")
		heartbeat.UpdateError = localMessage(settings.Directory, "update.error")
		heartbeat.AcceptHAProxy = engine.proxy.available()
		heartbeat.AcceptHAProxyHandoff = true
		heartbeat.AcceptPortCheck = true
		metrics.TCPConnections += int64(engine.proxy.connections)
		heartbeat.Metrics = metrics
		var reply wire.Sync
		if e = api(ctx, client, settings.Panel, "/api/node/sync", state.Token, state.ID, heartbeat, &reply); e != nil {
			if stopBandwidth != nil {
				stopBandwidth()
				stopBandwidth = nil
			}
			var control controlError
			if errors.As(e, &control) && control.status == http.StatusUnauthorized {
				_ = atomicFile(filepath.Join(settings.Directory, "revoked"), []byte("registration revoked\n"), 0600)
				_ = os.Remove(cached)
				_ = os.Remove(legacyCached)
				slog.Warn("node registration revoked")
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("panel sync", "error", e)
			delay = max(delay, 10*time.Second)
		} else {
			if reply.LiveBandwidth && stopBandwidth == nil {
				var bandwidthContext context.Context
				bandwidthContext, stopBandwidth = context.WithCancel(ctx)
				go reportBandwidth(bandwidthContext, client, settings.Panel, settings.Interface, state.Identity)
			} else if !reply.LiveBandwidth && stopBandwidth != nil {
				stopBandwidth()
				stopBandwidth = nil
			}
			if len(reply.MeterKey) == 32 && reply.MeterGroup > 0 {
				current := engine.meter.Load()
				if current == nil || current.group != reply.MeterGroup || !slices.Equal(current.key, reply.MeterKey) {
					engine.meter.Store(&meterVerifier{key: reply.MeterKey, group: reply.MeterGroup})
				}
			} else {
				engine.meter.Store(nil)
			}
			desiredMode := reply.RelayMode
			if desiredMode == "" {
				desiredMode = initialRelayMode
			}
			if relayBind != "" && wire.ValidRelayMode(desiredMode) {
				if desiredMode == activeRelayMode && relayListener != nil {
					relayModeRetry, relayModeErr = time.Time{}, ""
				} else if time.Now().After(relayModeRetry) {
					if relayListener != nil {
						_ = relayListener.Close()
					}
					listener, err := listenRelay(relayBind, desiredMode)
					if err == nil {
						relayListener, activeRelayMode = listener, desiredMode
						relayModeRetry, relayModeErr, delay = time.Time{}, "", time.Second
					} else {
						relayModeRetry = time.Now().Add(30 * time.Second)
						relayModeErr = err.Error()
						relayListener, err = listenRelay(relayBind, activeRelayMode)
						if err != nil {
							slog.Error("restore relay listener", "error", err)
						}
						slog.Warn("relay transport switch", "mode", desiredMode, "error", relayModeErr)
					}
				}
			}
			if reply.EnableNativeUDP && relayBind != "" && nativeListener == nil {
				nativeCtx, cancel := context.WithCancel(dataContext)
				listener, err := relay.ListenNativeUDP(nativeCtx, relayBind, nativeKey, engine.slots, engine.meterTarget)
				if err != nil {
					cancel()
					nativeErr = err.Error()
					slog.Warn("native UDP listener", "error", err)
				} else {
					nativeListener, stopNative, nativeErr = listener, cancel, ""
					delay = time.Second
				}
			} else if !reply.EnableNativeUDP {
				if nativeListener != nil {
					stopNative()
					nativeListener.Close()
					nativeListener, stopNative = nil, nil
				}
				nativeErr = ""
			}
			if report != nil && reply.Ack == report.ID {
				_ = os.Remove(filepath.Join(spool, report.ID+".json"))
			}
			if reportErr == nil && (report == nil || reply.Ack == report.ID) {
				engine.authorizeProxyTraffic(settings.Period)
			}
			engine.quota.apply(reply.QuotaGrants, reply.ClosedGrants)
			if reverseClient != nil {
				reverseClient.Update(reply.Reverse)
			}
			diagnostic = nil
			if reply.Diagnostic != nil && pendingDiagnostic == "" {
				task := *reply.Diagnostic
				pendingDiagnostic = task.ID
				go func() {
					if task.PingHost != "" {
						diagnostics <- pingHost(dataContext, task)
					} else {
						diagnostics <- engine.checkConnectivity(dataContext, task)
					}
				}()
			}
			var next *wire.Config
			snapshotOK := true
			if reply.Delta != nil {
				merged, err := mergeDelta(config, *reply.Delta)
				if err != nil {
					forceSnapshot = true
					snapshotOK = false
					slog.Warn("config delta rejected", "error", err)
				} else {
					next = &merged
				}
			}
			if reply.Config != nil {
				if e = wire.DecodeRoutes(reply.Config.Rules, reply.Config.RouteSets, reply.Config.HopTable); e != nil {
					forceSnapshot = true
					snapshotOK = false
					slog.Warn("config snapshot rejected", "error", e)
				} else {
					reply.Config.RouteSets = nil
					reply.Config.HopTable = nil
					next = reply.Config
				}
			}
			if next != nil {
				e = engine.apply(dataContext, *next, func() error {
					packed := *next
					packed.Rules, packed.RouteSets = wire.PackRoutes(next.Rules)
					// Keep managed sockets closed if an older node reads the cache during rollback.
					if slices.ContainsFunc(packed.Rules, func(f wire.Forward) bool { return f.HAProxy }) {
						packed.Rules = slices.Clone(packed.Rules)
						for i := range packed.Rules {
							rule := &packed.Rules[i]
							if rule.HAProxy {
								rule.Protocol = "haproxy-tcp"
								if next.Rules[i].Protocol == "both" {
									rule.Protocol = "haproxy-both"
								}
							}
						}
					}
					return toFile(cached, &packed)
				}, func() error {
					for _, path := range []string{cached, legacyCached} {
						if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
							return err
						}
					}
					return nil
				})
				if e != nil {
					snapshotOK = false
					slog.Warn("config application", "error", e)
					_ = atomicFile(filepath.Join(settings.Directory, "apply.error"), []byte(e.Error()), 0600)
				} else {
					config = *next
					forceSnapshot = false
					_ = os.Remove(filepath.Join(settings.Directory, "apply.error"))
				}
			}
			status := "pending"
			if !snapshotOK {
				status = "failed"
			} else if config.Revision != "" {
				_, appliedListeners, _ := engine.Status()
				status = "applied " + strconv.Itoa(appliedListeners)
			}
			if status != startupStatus {
				if err := atomicFile(startupPath, []byte(status+"\n"), 0600); err == nil {
					startupStatus = status
				}
			}
			if verifyUpgrade {
				ready := snapshotOK && !forceSnapshot && config.Revision != "" && heartbeat.Revision == config.Revision &&
					heartbeat.ApplyError == "" && relayModeErr == "" && nativeErr == ""
				if !ready || upgradeRevision != config.Revision {
					upgradeHealthy = 0
					upgradeRevision = config.Revision
				}
				if ready {
					upgradeHealthy++
					if upgradeHealthy >= 2 {
						if err := engine.checkUpgradeRoutes(dataContext, config); err != nil {
							_ = atomicFile(filepath.Join(settings.Directory, "update.check"), []byte(err.Error()), 0600)
							return err
						}
						if e := confirmUpgrade(settings); e != nil {
							return e
						}
						verifyUpgrade = false
					}
					delay = time.Second
				}
			}
			if !verifyUpgrade && reply.Release != nil && settings.PublicKey != "" && settings.Executable != "" {
				if candidateVersion != reply.Release.Version {
					candidateVersion = reply.Release.Version
					retryAfter = time.Time{}
					attempts = 0
				}
				if time.Now().After(retryAfter) {
					if e = stageUpgrade(ctx, client, settings, *reply.Release); e != nil {
						if ctx.Err() != nil {
							return nil
						}
						slog.Error("node upgrade", "error", e)
						attempts++
						if attempts >= 3 {
							_ = atomicFile(filepath.Join(settings.Directory, "update.error"), []byte(reply.Release.Version+": "+e.Error()), 0600)
						}
						retryAfter = time.Now().Add(time.Duration(attempts) * 10 * time.Second)
					} else {
						return ErrRestart
					}
				}
			}
		}
		if verifyUpgrade && time.Now().After(upgradeDeadline) {
			return errors.New("candidate did not confirm a configuration with the panel")
		}
		timer := time.NewTimer(delay)
		var wake <-chan struct{}
		if delay == settings.Period {
			wake = engine.quota.wake
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		case diagnostic = <-diagnostics:
			timer.Stop()
			pendingDiagnostic = ""
		case <-wake:
			timer.Stop()
			short := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ctx.Done():
				short.Stop()
				return nil
			case <-short.C:
			}
		}
	}
}

func localMessage(dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return strings.TrimSpace(string(b[:min(len(b), 512)]))
}

func prepareReport(engine *Engine, spool string) (*wire.Report, error) {
	files, e := os.ReadDir(spool)
	if e != nil {
		return nil, e
	}
	const spoolLimit = 2048
	if len(files) < spoolLimit {
		traffic := engine.Traffic()
		now := time.Now()
		var first *wire.Report
		for i := range spoolLimit - len(files) {
			if len(traffic) == 0 {
				break
			}
			batch := traffic[:min(len(traffic), wire.MaxReportEntries)]
			stamp := now.Add(time.Duration(i))
			report := wire.Report{ID: fmt.Sprintf("%020d-%s", stamp.UnixNano(), rand.Text()), CollectedAt: now.Unix(), Traffic: batch}
			if e = toFile(filepath.Join(spool, report.ID+".json"), report); e != nil {
				engine.restore(traffic)
				if first == nil {
					return nil, e
				}
				slog.Warn("traffic spool", "error", e)
				return first, nil
			}
			if first == nil {
				first = &report
			}
			traffic = traffic[len(batch):]
		}
		if len(traffic) != 0 {
			engine.restore(traffic)
		}
		if len(files) == 0 {
			return first, nil
		}
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		var report wire.Report
		if e = fromFile(filepath.Join(spool, f.Name()), &report); e != nil {
			return nil, e
		}
		if report.ID+".json" != f.Name() {
			return nil, errors.New("invalid traffic batch filename")
		}
		return &report, nil
	}
	return nil, nil
}

func mergeDelta(previous wire.Config, delta wire.ConfigDelta) (wire.Config, error) {
	if delta.Base != previous.Revision || delta.Revision == "" {
		return wire.Config{}, errors.New("base revision mismatch")
	}
	if err := wire.DecodeRoutes(delta.Rules, delta.RouteSets, delta.HopTable); err != nil {
		return wire.Config{}, err
	}
	byID := make(map[int64]wire.Forward, len(previous.Rules)+len(delta.Rules))
	for _, r := range previous.Rules {
		byID[r.ID] = r
	}
	for _, id := range delta.Remove {
		delete(byID, id)
	}
	for _, r := range delta.Rules {
		byID[r.ID] = r
	}
	result := wire.Config{Revision: delta.Revision, Rules: make([]wire.Forward, 0, len(byID))}
	for _, r := range byID {
		result.Rules = append(result.Rules, r)
	}
	slices.SortFunc(result.Rules, func(a, b wire.Forward) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return result, nil
}

func (e *Engine) checkConnectivity(ctx context.Context, task wire.DiagnosticTask) *wire.DiagnosticResult {
	if task.PortCheck != nil {
		return e.checkPort(ctx, task)
	}
	if task.Revision != "" {
		return e.checkRuleRoutes(ctx, task)
	}
	started := time.Now()
	check, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result := &wire.DiagnosticResult{ID: task.ID}
	var c net.Conn
	var err error
	if task.RuleID != 0 {
		e.mu.Lock()
		rr := e.activeRules[task.RuleID]
		e.mu.Unlock()
		if rr == nil || rr.rule.Protocol == "udp" || rr.rule.TLSShared {
			return result
		}
		select {
		case e.slots <- struct{}{}:
			defer func() { <-e.slots }()
		default:
			return result
		}
		if rr.rule.HAProxy {
			probe := checkRoute(check, []*relay.Session{{}}, rr.rule.Targets, false)
			result.Connected, result.LatencyMS = probe.Status == "connected", probe.LatencyMS
			return result
		}
		c, result.Backup, err = rr.dial(check, "tcp", "")
	} else {
		c, err = (&net.Dialer{}).DialContext(check, "tcp", task.Address)
	}
	if err == nil {
		_ = c.Close()
	}
	result.Connected, result.LatencyMS = err == nil, time.Since(started).Milliseconds()
	return result
}

func (e *Engine) checkRuleRoutes(ctx context.Context, task wire.DiagnosticTask) *wire.DiagnosticResult {
	result := &wire.DiagnosticResult{ID: task.ID}
	e.mu.Lock()
	active, revision := e.activeRules[task.RuleID], e.applied
	e.mu.Unlock()
	if revision != task.Revision {
		result.RuleStatus = "syncing"
		return result
	}
	if active == nil || (active.rule.Expires > 0 && active.rule.Expires <= time.Now().Unix()) {
		result.RuleStatus = "inactive"
		return result
	}
	result.RuleStatus = "running"
	for _, pair := range []struct {
		network string
		at      int64
	}{{"tcp", active.lastTCPRoute.Load()}, {"udp", active.lastUDPRoute.Load()}} {
		if pair.at != 0 {
			result.RecentRoutes = append(result.RecentRoutes, wire.RecentRoute{
				Network: pair.network, At: max(pair.at, -pair.at), Backup: pair.at < 0,
			})
		}
	}
	if active.rule.TLSShared || (task.ProbeSamples == 0 && active.rule.Protocol == "udp") {
		return result
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		result.RuleStatus = "busy"
		return result
	}
	if task.ProbeSamples > 0 {
		result.Links = probeRuleLinks(ctx, active, task)
		return result
	}
	if active.rule.HAProxy {
		result.PrimaryRoute = checkRoute(ctx, []*relay.Session{{}}, active.rule.Targets, false)
		return result
	}
	result.PrimaryRoute = checkRoute(ctx, active.primary, active.rule.Targets, active.rule.PublicTargets)
	if len(active.rule.BackupPath) > 0 {
		result.BackupRoute = checkRoute(ctx, active.backup, active.rule.Targets, active.rule.PublicBackupTargets)
	}
	return result
}

func probeRuleLinks(ctx context.Context, active *ruleRuntime, task wire.DiagnosticTask) []wire.LinkProbe {
	if len(active.rule.Targets) == 0 {
		return nil
	}
	type lane struct {
		wire.LinkProbe
		paths []*relay.Session
	}
	var lanes []lane
	for _, network := range []string{"tcp", "udp"} {
		if active.rule.Protocol != network && active.rule.Protocol != "both" {
			continue
		}
		paths := active.primary
		if network == "tcp" && active.rule.HAProxy {
			paths = []*relay.Session{{}}
		}
		measuresTarget := network == "tcp" || active.rule.UDPProbe
		lanes = append(lanes, lane{LinkProbe: wire.LinkProbe{Network: network, Lane: "primary", MeasuresTarget: measuresTarget}, paths: paths})
		if len(active.rule.BackupPath) > 0 && !(network == "tcp" && active.rule.HAProxy) {
			lanes = append(lanes, lane{LinkProbe: wire.LinkProbe{Network: network, Lane: "backup", MeasuresTarget: measuresTarget}, paths: active.backup})
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	samples := min(task.ProbeSamples, 3)
	targets := active.rule.Targets
	var checks sync.WaitGroup
	for i := range lanes {
		lane := &lanes[i]
		if len(lane.paths) == 0 {
			continue
		}
		checks.Go(func() {
			for attempt := 0; attempt < samples && ctx.Err() == nil; attempt++ {
				offset := uint64(max(0, task.ProbeOffset)) + uint64(attempt)
				perTry, done := context.WithTimeout(ctx, 1100*time.Millisecond)
				path := lane.paths[offset%uint64(len(lane.paths))]
				target := targets[offset%uint64(len(targets))]
				address := target
				publicOnly := (lane.Lane == "primary" && active.rule.PublicTargets) || (lane.Lane == "backup" && active.rule.PublicBackupTargets)
				if publicOnly {
					var err error
					address, _, err = resolvePublicTarget(perTry, target)
					if err != nil {
						if errors.Is(err, errPrivateDestination) {
							lane.Traces = append(lane.Traces, wire.RouteTrace{Target: target,
								Steps: []wire.ProbeStep{{Phase: "target_policy", Status: "failed"}}})
						}
						done()
						continue
					}
				}
				trace := path.Probe(perTry, lane.Network, address, active.rule.UDPProbe)
				trace.Target = target
				lane.Traces = append(lane.Traces, trace)
				done()
			}
		})
	}
	checks.Wait()
	results := make([]wire.LinkProbe, len(lanes))
	for i, lane := range lanes {
		results[i] = lane.LinkProbe
	}
	return results
}

func checkRoute(ctx context.Context, paths []*relay.Session, targets []string, publicOnly bool) *wire.RouteDiagnostic {
	result := &wire.RouteDiagnostic{Status: "unavailable"}
	if len(paths) == 0 || len(targets) == 0 {
		return result
	}
	started := time.Now()
	check, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	result.Status = "unreachable"
	for i := 0; i < min(4, max(len(paths), len(targets))) && check.Err() == nil; i++ {
		target := targets[i%len(targets)]
		address := target
		if publicOnly {
			var err error
			address, _, err = resolvePublicTarget(check, target)
			if err != nil {
				continue
			}
		}
		trace, err := paths[i%len(paths)].ProbeTCP(check, address)
		trace.Target = target
		if trace.Hops > 0 && (err == nil || result.Trace == nil || result.Trace.Reached < trace.Reached) {
			result.Trace = &trace
		}
		if err == nil {
			result.Status = "connected"
			break
		}
	}
	result.LatencyMS = time.Since(started).Milliseconds()
	return result
}
