package node

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"hopx/internal/wire"
)

func startBandwidthReporting(parent context.Context, client *http.Client, panel, iface string, identity wire.Identity) context.CancelFunc {
	ctx, cancel := context.WithCancel(parent)
	go reportBandwidth(ctx, client, panel, iface, identity)
	return cancel
}

func reportBandwidth(ctx context.Context, client *http.Client, panel, iface string, identity wire.Identity) {
	sampler := networkSampler{iface: iface}
	sampler.sample()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			metrics := sampler.sample()
			if metrics.HasTotals {
				request, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
				_ = api(request, client, panel, "/api/node/bandwidth", identity.Token, identity.ID, metrics, nil)
				cancel()
			}
		}
	}
}

type sampler struct {
	cpuTotal, cpuIdle uint64
	network           networkSampler
	proc              procReader
}

type networkSampler struct {
	iface      string
	defaultNIC string
	refreshAt  time.Time
	last       time.Time
	rx, tx     int64
	proc       procReader
}

func number(v string) uint64 { n, _ := strconv.ParseUint(v, 10, 64); return n }

type procReader struct {
	buffer [4096]byte
}

func (r *procReader) lines(path string, done func([]string) bool) {
	file, e := os.Open(path)
	if e != nil {
		return
	}
	defer file.Close()
	scan := bufio.NewScanner(file)
	scan.Buffer(r.buffer[:], bufio.MaxScanTokenSize)
	var fieldsBuffer [32]string
	for scan.Scan() {
		fields := fieldsBuffer[:0]
		for field := range strings.FieldsSeq(scan.Text()) {
			fields = append(fields, field)
		}
		if len(fields) > 0 && done(fields) {
			return
		}
	}
}

func (s *sampler) sample(dir string) wire.Metrics {
	var m wire.Metrics
	if descriptors, err := os.Open("/proc/self/fd"); err == nil {
		names, _ := descriptors.Readdirnames(-1)
		_ = descriptors.Close()
		m.FileDescriptors = max(0, len(names)-1)
		var limit unix.Rlimit
		if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) == nil {
			m.FileLimit = limit.Cur
		}
	}
	s.proc.lines("/proc/stat", func(f []string) bool {
		if f[0] != "cpu" || len(f) < 6 {
			return false
		}
		var total uint64
		for _, v := range f[1:min(len(f), 9)] {
			total += number(v)
		}
		idle := number(f[4]) + number(f[5])
		if s.cpuTotal > 0 && total > s.cpuTotal && idle >= s.cpuIdle {
			m.CPU = clamp(100 * (1 - float64(idle-s.cpuIdle)/float64(total-s.cpuTotal)))
		}
		s.cpuTotal, s.cpuIdle = total, idle
		return true
	})
	var mem, free uint64
	var hasAvailable bool
	s.proc.lines("/proc/meminfo", func(f []string) bool {
		if len(f) < 2 {
			return false
		}
		switch f[0] {
		case "MemTotal:":
			mem = number(f[1])
		case "MemAvailable:":
			free = number(f[1])
			hasAvailable = true
		}
		return mem > 0 && hasAvailable
	})
	if mem > 0 && free <= mem {
		m.RAM = 100 * float64(mem-free) / float64(mem)
	}
	s.proc.lines("/proc/self/status", func(f []string) bool {
		if len(f) > 1 && f[0] == "VmRSS:" {
			m.RSS = int64(number(f[1]) * 1024)
			return true
		}
		return false
	})
	raw, _ := os.ReadFile("/proc/uptime")
	if values := strings.Fields(string(raw)); len(values) > 0 {
		seconds, _ := strconv.ParseFloat(values[0], 64)
		m.Uptime = int64(seconds)
	}
	m.Bandwidth = s.network.sample()
	m.Disk = diskUsage(dir)
	return m
}

func (s *networkSampler) sample() wire.Bandwidth {
	now := time.Now()
	if s.iface == "" && !now.Before(s.refreshAt) {
		var nic string
		s.proc.lines("/proc/net/route", func(f []string) bool {
			if len(f) > 1 && f[1] == "00000000" && f[0] != "lo" {
				nic = f[0]
				return true
			}
			return false
		})
		if nic == "" {
			s.proc.lines("/proc/net/ipv6_route", func(f []string) bool {
				if len(f) >= 10 && f[0] == "00000000000000000000000000000000" && f[1] == "00" && f[9] != "lo" {
					nic = f[9]
					return true
				}
				return false
			})
		}
		if s.defaultNIC != nic {
			s.last = time.Time{}
			s.defaultNIC = nic
		}
		s.refreshAt = now.Add(30 * time.Second)
	}
	var sample wire.Bandwidth
	s.proc.lines("/proc/net/dev", func(f []string) bool {
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			return false
		}
		nic := strings.TrimSuffix(f[0], ":")
		if nic == "lo" {
			return false
		}
		if s.iface != "" {
			selected := false
			for name := range strings.SplitSeq(s.iface, ",") {
				if strings.TrimSpace(name) == nic {
					selected = true
					break
				}
			}
			if !selected {
				return false
			}
		} else if s.defaultNIC != "" && nic != s.defaultNIC {
			return false
		}
		rx, rxErr := strconv.ParseInt(f[1], 10, 64)
		tx, txErr := strconv.ParseInt(f[9], 10, 64)
		if rxErr == nil && txErr == nil && rx >= 0 && tx >= 0 {
			sample.HasTotals = true
			sample.InBytes += rx
			sample.OutBytes += tx
		}
		return s.iface == "" && s.defaultNIC != ""
	})
	if !sample.HasTotals {
		s.last = time.Time{}
		return sample
	}
	if !s.last.IsZero() && now.After(s.last) {
		seconds := now.Sub(s.last).Seconds()
		sample.InMbps = float64(max(0, sample.InBytes-s.rx)) * 8 / 1e6 / seconds
		sample.OutMbps = float64(max(0, sample.OutBytes-s.tx)) * 8 / 1e6 / seconds
	}
	s.last, s.rx, s.tx = now, sample.InBytes, sample.OutBytes
	return sample
}

func clamp(v float64) float64 { return min(100, max(0, v)) }
