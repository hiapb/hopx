package node

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"hopx/internal/wire"
)

type proxyRule struct {
	wire.Forward
	stats *counter
}

type proxyProcess struct {
	socket    string
	command   *exec.Cmd
	done      chan struct{}
	exitError error
	counters  map[int64]*counter
	last      map[int64][2]int64
	frontends map[int64]proxyFrontend
	log       proxyTrafficLog
}

// Runtime stats account for live sessions. Close logs cover bytes sent after
// the last stats sample, including a draining process's final session.
type proxyTrafficLog struct {
	mu      sync.Mutex
	closed  map[int64][2]int64
	pending []byte
}

func (l *proxyTrafficLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = append(l.pending, data...)
	for {
		line, rest, ok := bytes.Cut(l.pending, []byte("\n"))
		if !ok {
			if len(l.pending) > 4096 {
				l.pending = l.pending[:0]
			}
			return len(data), nil
		}
		l.pending = rest
		fields := bytes.Fields(line)
		if len(fields) != 3 || !bytes.HasPrefix(fields[0], []byte("hopx_")) {
			continue
		}
		id, idErr := strconv.ParseInt(string(fields[0][5:]), 10, 64)
		in, inErr := strconv.ParseInt(string(fields[1]), 10, 64)
		out, outErr := strconv.ParseInt(string(fields[2]), 10, 64)
		if idErr == nil && inErr == nil && outErr == nil {
			total := l.closed[id]
			l.closed[id] = [2]int64{total[0] + in, total[1] + out}
		}
	}
}

func (p *proxyProcess) addTraffic(id int64, in, out int64) {
	stats := p.counters[id]
	if stats == nil {
		return
	}
	old := p.last[id]
	stats.in.Add(max(0, in-old[0]))
	stats.out.Add(max(0, out-old[1]))
	p.last[id] = [2]int64{max(old[0], in), max(old[1], out)}
}

func (p *proxyProcess) flushTraffic() {
	if p == nil {
		return
	}
	p.log.mu.Lock()
	defer p.log.mu.Unlock()
	for id, closed := range p.log.closed {
		p.addTraffic(id, closed[0], closed[1])
	}
}

type proxyFrontend struct {
	expires int64
	targets int
	metered bool
}

type proxyStartupLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (log *proxyStartupLog) Write(p []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	keep := min(len(p), max(0, 4096-log.b.Len()))
	_, _ = log.b.Write(p[:keep])
	return len(p), nil
}

func (log *proxyStartupLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return strings.TrimSpace(log.b.String())
}

type proxyEngine struct {
	binary                 string
	stateDir               string
	config                 string
	active, draining       *proxyProcess
	listeners, connections int
	reserved               int
	expiry                 *time.Timer
	reportUntil            time.Time
}

func meteredProxy(rule wire.Forward) bool { return rule.HAProxy && rule.QuotaManaged }

func (p *proxyEngine) available() bool { return bundledHAProxy != "" || p.binary != "" }

func (p *proxyEngine) executable() (path string, cleanup func(), err error) {
	if bundledHAProxy == "" {
		if p.binary == "" {
			return "", nil, errors.New("HAProxy runtime unavailable")
		}
		return p.binary, func() {}, nil
	}
	reader, err := gzip.NewReader(strings.NewReader(bundledHAProxy))
	if err != nil {
		return "", nil, err
	}
	defer reader.Close()
	file, err := os.CreateTemp(p.stateDir, ".hopx-haproxy-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.Remove(file.Name()) }
	_, copyErr := io.Copy(file, reader)
	err = errors.Join(copyErr, file.Chmod(0700), file.Close())
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return file.Name(), cleanup, nil
}

func (e *Engine) authorizeProxyTraffic(period time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proxy.reportUntil = time.Now().Add(max(30*time.Second, 3*period))
}

func (p *proxyProcess) running() bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *proxyProcess) stop() {
	if p.running() {
		_ = p.command.Process.Kill()
		<-p.done
	}
}

func (p *proxyProcess) drain() {
	_ = p.command.Process.Signal(syscall.SIGUSR1)
}

func (p *proxyProcess) stopFrontends(shouldStop func(int64, proxyFrontend) bool) {
	if !p.running() {
		return
	}
	var commands strings.Builder
	for id, frontend := range p.frontends {
		if !shouldStop(id, frontend) {
			continue
		}
		if commands.Len() >= 4000 {
			if !p.runCommands(commands.String()) {
				p.stop()
				return
			}
			commands.Reset()
		}
		for i := 1; i <= frontend.targets; i++ {
			fmt.Fprintf(&commands, "shutdown sessions server hopx_%d/target_%d;", id, i)
		}
		fmt.Fprintf(&commands, "shutdown frontend hopx_%d;", id)
		delete(p.frontends, id)
	}
	if commands.Len() != 0 && !p.runCommands(commands.String()) {
		p.stop()
	}
}

func (p *proxyProcess) runCommands(commands string) bool {
	conn, err := net.DialTimeout("unix", p.socket, 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = io.WriteString(conn, commands+"\n"); err != nil {
		return false
	}
	result, err := io.ReadAll(io.LimitReader(conn, 4096))
	return err == nil && len(bytes.TrimSpace(result)) == 0
}

// One timer per node covers the active and draining HAProxy processes.
func (e *Engine) scheduleProxyExpiry() {
	if e.proxy.expiry != nil {
		e.proxy.expiry.Stop()
		e.proxy.expiry = nil
	}
	var earliest time.Time
	reportUntil := e.proxy.reportUntil
	if reportUntil.IsZero() {
		reportUntil = time.Now()
	}
	for _, process := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
		if !process.running() {
			continue
		}
		for _, frontend := range process.frontends {
			if frontend.expires > 0 {
				deadline := time.Unix(frontend.expires, 0)
				if earliest.IsZero() || deadline.Before(earliest) {
					earliest = deadline
				}
			}
			if frontend.metered && (earliest.IsZero() || reportUntil.Before(earliest)) {
				earliest = reportUntil
			}
		}
	}
	if !earliest.IsZero() {
		e.proxy.expiry = time.AfterFunc(time.Until(earliest), func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			now := time.Now()
			for _, process := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
				stopped := make(map[int64]bool)
				process.stopFrontends(func(id int64, frontend proxyFrontend) bool {
					staleMeter := frontend.metered && !now.Before(e.proxy.reportUntil)
					if staleMeter || frontend.expires > 0 && frontend.expires <= now.Unix() {
						stopped[id] = true
						if staleMeter && process == e.proxy.active {
							e.applied = ""
						}
						return true
					}
					return false
				})
				if process != nil && process == e.proxy.active && len(stopped) != 0 {
					for key, listener := range e.listeners {
						if key.network == "tcp" && stopped[listener.route.Load().rule.ID] {
							listener.close()
							delete(e.listeners, key)
						}
					}
					e.proxy.listeners = len(process.frontends) * len(e.bind)
					if len(process.frontends) == 0 && process.running() {
						process.drain()
					}
				}
			}
			e.scheduleProxyExpiry()
		})
	}
}

func (p *proxyProcess) sample() (int, error) {
	conn, err := net.DialTimeout("unix", p.socket, 250*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "show stat\n"); err != nil {
		return 0, err
	}
	reader := csv.NewReader(conn)
	header, err := reader.Read()
	if err != nil {
		return 0, err
	}
	fields := make(map[string]int, len(header))
	for i, name := range header {
		fields[strings.TrimPrefix(name, "# ")] = i
	}
	for _, name := range []string{"pxname", "svname", "bin", "bout", "scur"} {
		if _, ok := fields[name]; !ok {
			return 0, fmt.Errorf("HAProxy stats missing %s", name)
		}
	}
	connections := 0
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return connections, nil
		}
		if err != nil {
			return 0, err
		}
		name := row[fields["pxname"]]
		if row[fields["svname"]] != "FRONTEND" || !strings.HasPrefix(name, "hopx_") {
			continue
		}
		id, _ := strconv.ParseInt(strings.TrimPrefix(name, "hopx_"), 10, 64)
		stats := p.counters[id]
		if stats == nil {
			continue
		}
		in, _ := strconv.ParseInt(row[fields["bin"]], 10, 64)
		out, _ := strconv.ParseInt(row[fields["bout"]], 10, 64)
		active, _ := strconv.Atoi(row[fields["scur"]])
		p.addTraffic(id, in, out)
		connections += active
	}
}

func (p *proxyProcess) checkReady(ctx context.Context) error {
	const probeTimeout = 250 * time.Millisecond
	dialer := net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "unix", p.socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(probeTimeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, "show info\n"); err != nil {
		return err
	}
	info := bufio.NewScanner(io.LimitReader(conn, 16<<10))
	ready := false
	for info.Scan() {
		if pid, ok := strings.CutPrefix(info.Text(), "Pid:"); ok {
			if strings.TrimSpace(pid) != strconv.Itoa(p.command.Process.Pid) {
				return errors.New("unexpected HAProxy process on management socket")
			}
			ready = true
		}
	}
	if err := info.Err(); err != nil {
		return err
	}
	if ready {
		return nil
	}
	return errors.New("HAProxy management socket returned no process ID")
}

const proxySyncDNS = " init-addr last,libc,none"

func safeProxyAddress(address string, bind bool) bool {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if bind || host == "" || len(host) > 253 {
		return false
	}
	for _, c := range strings.ToLower(host) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return false
		}
	}
	return !strings.HasPrefix(host, "-")
}

func proxyConfig(rules []proxyRule, hosts []string, maxConnections int) (string, error) {
	if len(rules) == 0 {
		return "", nil
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	var config strings.Builder
	fmt.Fprintf(&config, "    nbthread 1\n    maxconn %d\n    log stdout format raw local0\n\nresolvers hopx_dns\n    parse-resolv-conf\n\ndefaults\n    mode tcp\n    log global\n    log-format \"%%f %%U %%B\"\n    timeout connect 5s\n    timeout client 5m\n    timeout server 5m\n    option redispatch\n    retries 2\n", maxConnections)
	fd := 3
	for _, rule := range rules {
		fmt.Fprintf(&config, "\nlisten hopx_%d\n", rule.ID)
		if rule.HAProxyRatio > 0 {
			fmt.Fprintf(&config, "    # traffic quota epoch %d\n", rule.QuotaEpoch)
		}
		if rule.Expires > 0 {
			fmt.Fprintf(&config, "    tcp-request connection reject if { date ge %d }\n", rule.Expires)
		}
		for _, host := range hosts {
			bind := net.JoinHostPort(host, strconv.Itoa(rule.Port))
			if host != "" && !safeProxyAddress(bind, true) {
				return "", fmt.Errorf("HAProxy requires an IP bind address: %s", host)
			}
			fmt.Fprintf(&config, "    # %s\n    bind fd@%d\n", bind, fd)
			fd++
		}
		balance := "roundrobin"
		switch rule.Strategy {
		case "random":
			balance = "random"
		case "first":
			balance = "first"
		case "ip-hash":
			balance = "source"
		case "least-connections":
			balance = "leastconn"
		}
		fmt.Fprintf(&config, "    balance %s\n", balance)
		for i, target := range rule.Targets {
			if !safeProxyAddress(target, false) {
				return "", fmt.Errorf("invalid HAProxy target for rule %d", rule.ID)
			}
			host, _, _ := net.SplitHostPort(target)
			resolve := ""
			if net.ParseIP(host) == nil {
				resolve = " resolvers hopx_dns resolve-opts allow-dup-ip" + proxySyncDNS
			}
			fmt.Fprintf(&config, "    server target_%d %s%s\n", i+1, target, resolve)
		}
	}
	return config.String(), nil
}

func (e *Engine) stageProxy(ctx context.Context, rules []proxyRule, pending map[listenerKey]*listener, save func() error) (*proxyProcess, string, error) {
	config, err := proxyConfig(rules, e.bind, max(1, cap(e.slots)/4))
	if err != nil {
		return nil, config, err
	}
	if e.proxy.active.running() && config == e.proxy.config && len(e.proxy.active.frontends) == len(rules) {
		return e.proxy.active, config, save()
	}
	if e.proxy.draining.running() && (config != "" || e.proxy.active.running()) {
		return nil, "", errors.New("previous HAProxy process is draining connections")
	}
	if config == "" {
		return nil, "", save()
	}
	if err := e.reserveProxySessions(); err != nil {
		return nil, "", err
	}
	binary, cleanup, err := e.proxy.executable()
	if err != nil {
		return nil, "", err
	}
	defer cleanup()
	files := make([]*os.File, 0, len(rules)*len(e.bind))
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for _, rule := range rules {
		for _, host := range e.bind {
			key := listenerKey{host: host, network: "tcp", port: rule.Port}
			l := pending[key]
			if l == nil {
				l = e.listeners[key]
			}
			file, err := l.tcp.(*net.TCPListener).File()
			if err != nil {
				return nil, "", err
			}
			files = append(files, file)
		}
	}
	// A retry after a startup timeout uses the same persisted snapshot.
	persist := sync.OnceValue(save)
	process, err := startProxy(ctx, binary, config, files, rules, persist)
	if errors.Is(err, errProxyStartupTimeout) && ctx.Err() == nil && strings.Contains(config, proxySyncDNS) {
		// Keep libc resolution for ordinary startups (including hosts-file
		// overrides). If it stalls, leave DNS to HAProxy's runtime resolver.
		fallback := strings.ReplaceAll(config, proxySyncDNS, " init-addr none")
		process, err = startProxy(ctx, binary, fallback, files, rules, persist)
	}
	return process, config, err
}

var errProxyStartupTimeout = errors.New("HAProxy startup timed out")

func startProxy(ctx context.Context, binary, config string, files []*os.File, rules []proxyRule, save func() error) (*proxyProcess, error) {
	dir, err := os.MkdirTemp("/tmp", "hopx-ha-")
	if err != nil {
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			_ = os.RemoveAll(dir)
		}
	}()
	path := filepath.Join(dir, "haproxy.cfg")
	socket := filepath.Join(dir, "admin.sock")
	content := "global\n    stats socket " + socket + " mode 600 level admin\n" + config
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return nil, err
	}
	// Validate the generated configuration and persist it before any new
	// worker starts accepting traffic on the shared sockets.
	checkCtx, cancelCheck := context.WithTimeout(ctx, 3*time.Second)
	check := exec.CommandContext(checkCtx, binary, "-c", "-f", path)
	check.ExtraFiles = files
	check.WaitDelay = time.Second
	var checkLog proxyStartupLog
	check.Stderr = &checkLog
	checkErr := check.Run()
	checkContextErr := checkCtx.Err()
	cancelCheck()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if checkErr != nil {
		if errors.Is(checkContextErr, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w during configuration check: %s", errProxyStartupTimeout, checkLog.String())
		}
		return nil, fmt.Errorf("HAProxy configuration rejected: %w: %s", checkErr, checkLog.String())
	}
	if err := save(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, binary, "-db", "-f", path)
	command.ExtraFiles = files
	var stderr proxyStartupLog
	command.Stderr = &stderr
	p := &proxyProcess{socket: socket, command: command, done: make(chan struct{}), counters: make(map[int64]*counter),
		last: make(map[int64][2]int64), frontends: make(map[int64]proxyFrontend, len(rules)),
		log: proxyTrafficLog{closed: make(map[int64][2]int64, len(rules))}}
	command.Stdout = &p.log
	for _, rule := range rules {
		p.counters[rule.ID] = rule.stats
		p.frontends[rule.ID] = proxyFrontend{expires: rule.Expires, targets: len(rule.Targets), metered: meteredProxy(rule.Forward)}
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start HAProxy: %w", err)
	}
	started = true
	go func() {
		p.exitError = command.Wait()
		_ = os.RemoveAll(dir)
		close(p.done)
	}()
	startCtx, cancelStart := context.WithTimeout(ctx, 5*time.Second)
	defer cancelStart()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	var lastProbe error
	for {
		select {
		case <-p.done:
			return nil, fmt.Errorf("HAProxy exited before becoming ready (%v): %s", p.exitError, stderr.String())
		case <-startCtx.Done():
			p.stop()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("%w waiting for management socket (%v): %s", errProxyStartupTimeout, lastProbe, stderr.String())
		case <-tick.C:
			lastProbe = p.checkReady(startCtx)
			if lastProbe == nil && p.running() {
				return p, nil
			}
		}
	}
}

func (e *Engine) commitProxy(next *proxyProcess, config string, rules []proxyRule, candidates map[int64]*ruleRuntime) {
	if next != e.proxy.active {
		for _, old := range []*proxyProcess{e.proxy.active, e.proxy.draining} {
			old.stopFrontends(func(id int64, _ proxyFrontend) bool {
				previous, candidate := e.activeRules[id], candidates[id]
				return candidate == nil || (previous != nil && previous.lifetime != candidate.lifetime)
			})
		}
		if current := e.proxy.active; current.running() {
			_, _ = current.sample()
			current.drain()
			e.proxy.draining.flushTraffic()
			e.proxy.draining = current
		} else {
			current.flushTraffic()
		}
		e.proxy.active = next
	}
	if next != nil {
		for _, rule := range rules {
			next.counters[rule.ID] = rule.stats
			next.frontends[rule.ID] = proxyFrontend{expires: rule.Expires, targets: len(rule.Targets), metered: meteredProxy(rule.Forward)}
		}
	}
	e.proxy.config = config
	e.proxy.listeners = len(rules) * len(e.bind)
	e.releaseIdleProxySessions()
	e.scheduleProxyExpiry()
}

func (e *Engine) reserveProxySessions() error {
	want := 2 * max(1, cap(e.slots)/4)
	previous := e.proxy.reserved
	for e.proxy.reserved < want {
		select {
		case e.slots <- struct{}{}:
			e.proxy.reserved++
		default:
			e.releaseProxySessions(previous)
			return errors.New("not enough free session capacity to activate HAProxy")
		}
	}
	return nil
}

func (e *Engine) releaseProxySessions(keep int) {
	for e.proxy.reserved > keep {
		<-e.slots
		e.proxy.reserved--
	}
}

func (e *Engine) releaseIdleProxySessions() {
	active, draining := e.proxy.active.running(), e.proxy.draining.running()
	if active && draining {
		return
	}
	keep := 0
	if active || draining {
		keep = max(1, cap(e.slots)/4)
	}
	e.releaseProxySessions(keep)
}
