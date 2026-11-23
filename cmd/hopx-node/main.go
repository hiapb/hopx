package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"hopx/internal/node"
)

var version = "dev"

func main() {
	var settings node.Settings
	settings.Version = version
	hostname, _ := os.Hostname()
	flag.StringVar(&settings.Panel, "panel", os.Getenv("HOPX_PANEL"), "panel base URL")
	flag.StringVar(&settings.Directory, "state", env("HOPX_STATE", "data/node"), "node state directory")
	flag.StringVar(&settings.Enrollment, "token", os.Getenv("HOPX_TOKEN"), "device group enrollment token")
	flag.StringVar(&settings.Name, "name", env("HOPX_NAME", hostname), "node name")
	flag.StringVar(&settings.Region, "region", os.Getenv("HOPX_REGION"), "region")
	flag.StringVar(&settings.Address, "address", os.Getenv("HOPX_ADDRESS"), "advertised address")
	flag.StringVar(&settings.IPv4, "ipv4", os.Getenv("HOPX_IPV4"), "public IPv4")
	flag.StringVar(&settings.IPv6, "ipv6", os.Getenv("HOPX_IPV6"), "public IPv6")
	flag.StringVar(&settings.RelayListen, "relay-listen", os.Getenv("HOPX_RELAY_LISTEN"), "relay bind address")
	flag.StringVar(&settings.ReverseAddress, "reverse-address", os.Getenv("HOPX_REVERSE_ADDRESS"), "ingress address for reverse egress registration")
	flag.StringVar(&settings.ReverseListen, "reverse-listen", os.Getenv("HOPX_REVERSE_LISTEN"), "reverse registration bind")
	reverseOnly, _ := strconv.ParseBool(os.Getenv("HOPX_REVERSE_ONLY"))
	flag.BoolVar(&settings.ReverseOnly, "reverse-only", reverseOnly, "connect to ingress without a public egress listener")
	flag.StringVar(&settings.RelayAddress, "relay-address", os.Getenv("HOPX_RELAY_ADDRESS"), "relay advertised address")
	flag.StringVar(&settings.RelayTransport, "relay-transport", env("HOPX_RELAY_TRANSPORT", "tls"), "relay transport: tls, tls-mux, ws, wss, wss-mux, http, or https")
	flag.StringVar(&settings.Bind, "bind", os.Getenv("HOPX_BIND"), "forward listeners bind address")
	udpSmartBind, _ := strconv.ParseBool(os.Getenv("HOPX_UDP_SMART_BIND"))
	flag.BoolVar(&settings.UDPSmartBind, "udp-smart-bind", udpSmartBind, "bind UDP listeners per local interface address")
	flag.StringVar(&settings.Interface, "interface", os.Getenv("HOPX_INTERFACE"), "network interface to monitor")
	flag.StringVar(&settings.PublicKey, "release-key", os.Getenv("HOPX_RELEASE_KEY"), "trusted release public key")
	flag.StringVar(&settings.Executable, "update-binary", os.Getenv("HOPX_UPDATE_BINARY"), "managed node executable")
	flag.IntVar(&settings.MaxListeners, "max-listeners", 1024, "maximum forwarding listeners")
	flag.IntVar(&settings.MaxConnections, "max-connections", 2048, "maximum forwarding sessions")
	flag.DurationVar(&settings.Period, "sync", 5*time.Second, "control-plane sync interval")
	show := flag.Bool("version", false, "print version")
	flag.Parse()
	if *show {
		os.Stdout.WriteString(version + "\n")
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := node.Run(ctx, settings); err != nil {
		if errors.Is(err, node.ErrRestart) {
			os.Exit(75)
		}
		log.Fatal(err)
	}
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
