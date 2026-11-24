package wire

import "time"

type RelayRouting struct {
	AllowPrivateTargets bool    `json:"allowPrivateTargets,omitempty"`
	StatusVisibility    string  `json:"statusVisibility,omitempty"`
	IngressMode         string  `json:"ingressMode,omitempty"`
	ApplyRelayMode      bool    `json:"applyRelayMode,omitempty"`
	NativeUDP           bool    `json:"nativeUDP,omitempty"`
	IPv6Groups          []int64 `json:"ipv6Groups,omitempty"`
	AddressMode         string  `json:"addressMode,omitempty"`
	StaticAddress       string  `json:"staticAddress,omitempty"`
	MaxFailures         int     `json:"maxFailures,omitempty"`
	RecoverySeconds     int     `json:"recoverySeconds,omitempty"`
}

type DeviceGroup struct {
	Routing        RelayRouting   `json:"routing"`
	ConnectHost    string         `json:"connectHost,omitempty"`
	FallbackGroup  int64          `json:"fallbackGroup,omitempty"`
	RelayMode      string         `json:"relayMode,omitempty"`
	DefaultNetwork string         `json:"defaultNetwork,omitempty"`
	Folder         string         `json:"folder,omitempty"`
	Note           string         `json:"note,omitempty"`
	ShowOrder      int            `json:"showOrder,omitempty"`
	HideStatus     bool           `json:"hideStatus,omitempty"`
	Ingress        *IngressFilter `json:"ingress,omitempty"`
	TLSIngress     int            `json:"tlsIngress,omitempty"`
	ReverseGroups  []int64        `json:"reverseGroups,omitempty"`
	PortRanges     string         `json:"portRanges,omitempty"`
	Chain          []int64        `json:"chain,omitempty"`
	UserGroups     []int64        `json:"userGroups,omitempty"`
	Owner          int64          `json:"owner"`
	AllowedFrom    []int64        `json:"allowedFrom"`
	AllowedTo      []int64        `json:"allowedTo"`
	ID             int64          `json:"id"`
	Name           string         `json:"name"`
	Kind           string         `json:"kind"`
	FirstPort      int            `json:"firstPort"`
	LastPort       int            `json:"lastPort"`
	Ratio          int64          `json:"ratio"`
	UserGroup      int64          `json:"userGroup"`
	OfflineSeconds int            `json:"offlineSeconds"`
}

func ValidRelayMode(mode string) bool {
	switch mode {
	case "", "tls", "tls-mux", "ws", "wss", "wss-mux", "http", "https":
		return true
	default:
		return false
	}
}

type IngressFilter struct {
	SiteOutboundOnly bool     `json:"siteOutboundOnly,omitempty"`
	BlockPersonal    bool     `json:"blockPersonal,omitempty"`
	DisableUDP       bool     `json:"disableUDP,omitempty"`
	RejectEmptySNI   bool     `json:"rejectEmptySNI,omitempty"`
	AllowedHosts     []string `json:"allowedHosts,omitempty"`
	BlockedHosts     []string `json:"blockedHosts,omitempty"`
	BlockedPaths     []string `json:"blockedPaths,omitempty"`
	BlockedTypes     []string `json:"blockedTypes,omitempty"`
}

func (f *IngressFilter) InspectsTCP() bool {
	return f != nil && (f.RejectEmptySNI || len(f.AllowedHosts)+len(f.BlockedHosts)+len(f.BlockedPaths)+len(f.BlockedTypes) != 0)
}

func (f *IngressFilter) BlocksUDP() bool {
	return f != nil && (f.DisableUDP || len(f.AllowedHosts) != 0)
}

type Hop struct {
	NativeUDPMeter bool   `json:"nativeUDPMeter,omitempty"`
	GroupID        int64  `json:"groupId,omitempty"`
	NativeUDPKey   string `json:"nativeUDPKey,omitempty"`
	AdvertisedAddr string `json:"advertisedAddr,omitempty"`
	ReverseID      string `json:"reverseId,omitempty"`
	Transport      string `json:"transport,omitempty"`
	Addr           string `json:"addr"`
	Cert           string `json:"cert"`
	Token          string `json:"token"`
}

type Rule struct {
	ProbeInterval   int      `json:"probeInterval,omitempty"`
	UDPProbe        bool     `json:"udpProbe,omitempty"`
	TLSShared       bool     `json:"tlsShared,omitempty"`
	TLSSharedPort   int      `json:"tlsSharedPort,omitempty"`
	TLSAllowedNames []string `json:"tlsAllowedNames,omitempty"`
	TLSAllowedUsers []int64  `json:"tlsAllowedUsers,omitempty"`
	TLSOrigin       int      `json:"tlsOrigin,omitempty"`
	ResponseFilters []int    `json:"responseFilters,omitempty"`
	TLSServerNames  []string `json:"tlsServerNames,omitempty"`
	TLSALPN         []string `json:"tlsALPN,omitempty"`
	TLSRequireEmpty bool     `json:"tlsRequireEmpty,omitempty"`
	ID              int64    `json:"id"`
	Owner           int64    `json:"owner"`
	Name            string   `json:"name"`
	Label           string   `json:"label"`
	Entry           int64    `json:"entry"`
	Port            int      `json:"port"`
	Protocol        string   `json:"protocol"`
	Targets         []string `json:"targets"`
	Path            []int64  `json:"path"`
	BackupPath      []int64  `json:"backupPath"`
	Strategy        string   `json:"strategy"`
	Enabled         bool     `json:"enabled"`
	RateMbps        int      `json:"rateMbps"`
	MaxIPs          int      `json:"maxIPs"`
	MaxConns        int      `json:"maxConns"`
	ProxyIn         bool     `json:"proxyIn"`
	ProxyInVersion  int      `json:"proxyInVersion,omitempty"`
	ProxyOutVersion int      `json:"proxyOutVersion,omitempty"`
	ProxyOut        bool     `json:"proxyOut"`
	TLSCert         string   `json:"tlsCert,omitempty"`
	TLSKey          string   `json:"tlsKey,omitempty"`
	TLSGenerateFor  string   `json:"tlsGenerateFor,omitempty"`

	RouteRepair  *RuleRouteRepair `json:"routeRepair,omitempty"`
	ConfirmRoute bool             `json:"confirmRoute,omitempty"`
}

type RuleRouteRepair struct {
	Entry      bool `json:"entry,omitempty"`
	Path       bool `json:"path,omitempty"`
	BackupPath bool `json:"backupPath,omitempty"`
}

func (r Rule) HasTLSPolicy() bool {
	return len(r.TLSServerNames) > 0 || len(r.TLSALPN) > 0 || r.TLSRequireEmpty || r.TLSOrigin != 0 || len(r.ResponseFilters) > 0
}

func (r Rule) UsesSharedTLS() bool {
	return r.TLSShared || r.TLSSharedPort != 0
}

func (r Rule) UsesHAProxy() bool {
	return r.Protocol == "haproxy-tcp" || r.Protocol == "haproxy-both"
}

func (g DeviceGroup) AllowsIngressPath(r Rule) bool {
	switch g.Routing.IngressMode {
	case "direct":
		return len(r.Path) == 0 && len(r.BackupPath) == 0
	case "relay", "personal":
		return len(r.Path) != 0 || r.TLSShared
	default:
		return true
	}
}

func (g DeviceGroup) AllowsIngress(r Rule) bool {
	switch g.TLSIngress {
	case 1:
		return r.TLSCert != "" || r.TLSSharedPort != 0
	case 2:
		return r.UsesSharedTLS()
	default:
		return true
	}
}

func (g DeviceGroup) RuleNetwork(r Rule) string {
	switch r.Protocol {
	case "haproxy-tcp":
		return "tcp"
	case "haproxy-both":
		return "both"
	}
	if r.Protocol != "inherit" {
		return r.Protocol
	}
	if r.ProxyIn || (r.ProxyOut && r.ProxyOutVersion != 2) || r.TLSCert != "" || r.UsesSharedTLS() {
		return "tcp"
	}
	if g.DefaultNetwork != "" {
		return g.DefaultNetwork
	}
	return "tcp"
}

type Forward struct {
	PublicTargets       bool           `json:"publicTargets,omitempty"`
	PublicBackupTargets bool           `json:"publicBackupTargets,omitempty"`
	ExitMeter           string         `json:"exitMeter,omitempty"`
	BackupExitMeter     string         `json:"backupExitMeter,omitempty"`
	EntryRatio          int64          `json:"entryRatio,omitempty"`
	HAProxy             bool           `json:"haProxy,omitempty"`
	HAProxyRatio        int64          `json:"haProxyRatio,omitempty"`
	MaxFailures         int            `json:"maxFailures,omitempty"`
	RecoverySeconds     int            `json:"recoverySeconds,omitempty"`
	Ingress             *IngressFilter `json:"ingress,omitempty"`
	RoutesRef           int            `json:"routesRef,omitempty"`
	BackupRef           int            `json:"backupRef,omitempty"`
	BackupRatio         *int64         `json:"backupRatio,omitempty"`
	QuotaManaged        bool           `json:"quotaManaged,omitempty"`
	QuotaEpoch          int64          `json:"quotaEpoch,omitempty"`
	Expires             int64          `json:"expires,omitempty"`
	UserRate            int            `json:"userRate,omitempty"`
	UserIPs             int            `json:"userIPs,omitempty"`
	UserConnections     int            `json:"userConnections,omitempty"`
	Rule
	Ratio  int64   `json:"ratio"`
	Routes [][]Hop `json:"routes,omitempty"`
	Backup [][]Hop `json:"backup,omitempty"`
}

type Config struct {
	Revision  string    `json:"revision"`
	Rules     []Forward `json:"rules"`
	RouteSets [][][]Hop `json:"routeSets,omitempty"`
	HopTable  *HopTable `json:"hopTable,omitempty"`
}

type ConfigDelta struct {
	Base      string    `json:"base"`
	Revision  string    `json:"revision"`
	Rules     []Forward `json:"rules,omitempty"`
	Remove    []int64   `json:"remove,omitempty"`
	RouteSets [][][]Hop `json:"routeSets,omitempty"`
	HopTable  *HopTable `json:"hopTable,omitempty"`
}

type Traffic struct {
	ExitMeter    string `json:"exitMeter,omitempty"`
	QuotaManaged bool   `json:"quotaManaged,omitempty"`
	QuotaEpoch   *int64 `json:"quotaEpoch,omitempty"`
	RuleID       int64  `json:"ruleId"`
	In           int64  `json:"in"`
	Out          int64  `json:"out"`
	Ratio        int64  `json:"ratio"`
}

const MaxReportEntries = 8192

type Report struct {
	ID          string    `json:"id"`
	CollectedAt int64     `json:"collectedAt,omitempty"`
	Traffic     []Traffic `json:"traffic"`
}

type Metrics struct {
	FileDescriptors  int     `json:"fileDescriptors,omitempty"`
	FileLimit        uint64  `json:"fileLimit,omitempty"`
	BindAddresses    int     `json:"bindAddresses,omitempty"`
	UDPBindAddresses int     `json:"udpBindAddresses,omitempty"`
	UDPDrop          int64   `json:"udpDrop"`
	ListenerLimit    int     `json:"listenerLimit"`
	ConnectionLimit  int     `json:"connectionLimit"`
	TCPConnections   int64   `json:"tcpConnections"`
	UDPSessions      int64   `json:"udpSessions"`
	CPU              float64 `json:"cpu"`
	RAM              float64 `json:"ram"`
	Disk             float64 `json:"disk"`
	InMbps           float64 `json:"inMbps"`
	OutMbps          float64 `json:"outMbps"`
	Uptime           int64   `json:"uptime"`
	Connections      int64   `json:"connections"`
	Listeners        int     `json:"listeners"`
	RSS              int64   `json:"rss"`
}

type Heartbeat struct {
	AcceptPublicTargets         bool              `json:"acceptPublicTargets,omitempty"`
	AcceptScopedReverse         bool              `json:"acceptScopedReverse,omitempty"`
	AcceptExitMeter             bool              `json:"acceptExitMeter,omitempty"`
	ManagedUpgrade              *bool             `json:"managedUpgrade,omitempty"`
	AcceptPortCheck             bool              `json:"acceptPortCheck,omitempty"`
	AcceptHAProxy               bool              `json:"acceptHAProxy,omitempty"`
	AcceptPing                  bool              `json:"acceptPing,omitempty"`
	ActiveRelayMode             string            `json:"activeRelayMode,omitempty"`
	RelayModeError              string            `json:"relayModeError,omitempty"`
	NativeUDPKey                string            `json:"nativeUDPKey,omitempty"`
	NativeUDPError              string            `json:"nativeUDPError,omitempty"`
	AcceptAlternateRelayAddress bool              `json:"acceptAlternateRelayAddress,omitempty"`
	AcceptWebsocketMux          bool              `json:"acceptWebsocketMux,omitempty"`
	AcceptUDPProxy              bool              `json:"acceptUdpProxy,omitempty"`
	AcceptRelayTransports       bool              `json:"acceptRelayTransports,omitempty"`
	AcceptHopTable              bool              `json:"acceptHopTable,omitempty"`
	UpgradePending              bool              `json:"upgradePending,omitempty"`
	AcceptRuleProbe             bool              `json:"acceptRuleProbe,omitempty"`
	AcceptRouteProbe            bool              `json:"acceptRouteProbe,omitempty"`
	AcceptLinkProbe             bool              `json:"acceptLinkProbe,omitempty"`
	AcceptIngress               bool              `json:"acceptIngress,omitempty"`
	AcceptFET                   bool              `json:"acceptFET,omitempty"`
	AcceptSharedTLS             bool              `json:"acceptSharedTls,omitempty"`
	AcceptRouteSets             bool              `json:"acceptRouteSets,omitempty"`
	AcceptTLSPolicy             bool              `json:"acceptTlsPolicy,omitempty"`
	Diagnostic                  *DiagnosticResult `json:"diagnostic,omitempty"`
	AcceptDelta                 bool              `json:"acceptDelta,omitempty"`
	QuotaClaims                 []QuotaClaim      `json:"quotaClaims,omitempty"`
	QuotaGeneration             string            `json:"quotaGeneration,omitempty"`
	Version                     string            `json:"version"`
	OS                          string            `json:"os"`
	Arch                        string            `json:"arch"`
	Revision                    string            `json:"revision"`
	ApplyError                  string            `json:"applyError"`
	UpdateError                 string            `json:"updateError"`
	Metrics                     Metrics           `json:"metrics"`
	Report                      *Report           `json:"report,omitempty"`
}

type Registration struct {
	ReverseAddress     string `json:"reverseAddress,omitempty"`
	ReverseCertificate string `json:"reverseCertificate,omitempty"`
	ReverseToken       string `json:"reverseToken,omitempty"`
	ReverseID          string `json:"reverseId,omitempty"`
	RelayTransport     string `json:"relayTransport,omitempty"`
	Name               string `json:"name"`
	Region             string `json:"region"`
	Address            string `json:"address"`
	IPv4               string `json:"ipv4"`
	IPv6               string `json:"ipv6"`
	RelayAddress       string `json:"relayAddress"`
	RelayCert          string `json:"relayCert"`
	RelayToken         string `json:"relayToken"`
}

type Identity struct {
	ID    int64  `json:"id"`
	Token string `json:"token"`
}

type Release struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

type Sync struct {
	MeterKey        []byte            `json:"meterKey,omitempty"`
	MeterGroup      int64             `json:"meterGroup,omitempty"`
	RelayMode       string            `json:"relayMode,omitempty"`
	EnableNativeUDP bool              `json:"enableNativeUDP,omitempty"`
	Reverse         []ReverseEndpoint `json:"reverse,omitempty"`
	Diagnostic      *DiagnosticTask   `json:"diagnostic,omitempty"`
	Delta           *ConfigDelta      `json:"delta,omitempty"`
	QuotaGrants     []QuotaGrant      `json:"quotaGrants,omitempty"`
	ClosedGrants    []string          `json:"closedGrants,omitempty"`
	Config          *Config           `json:"config,omitempty"`
	Release         *Release          `json:"release,omitempty"`
	Ack             string            `json:"ack,omitempty"`
}

type Device struct {
	CountryCode         string `json:"countryCode,omitempty"`
	AcceptScopedReverse bool   `json:"-"`
	AcceptExitMeter     bool   `json:"-"`
	AcceptPortCheck     bool   `json:"-"`
	AcceptHAProxy       bool   `json:"acceptHAProxy,omitempty"`
	AcceptPing          bool   `json:"acceptPing,omitempty"`
	ActiveRelayMode     string `json:"-"`
	RelayModeError      string `json:"relayModeError,omitempty"`
	NativeUDPKey        string `json:"-"`
	NativeUDP           bool   `json:"nativeUDP,omitempty"`
	NativeUDPError      string `json:"nativeUDPError,omitempty"`
	AcceptRuleProbe     bool   `json:"-"`
	AcceptRouteProbe    bool   `json:"-"`
	AcceptLinkProbe     bool   `json:"-"`
	TargetVersion       string `json:"targetVersion,omitempty"`
	OS                  string `json:"os,omitempty"`
	Arch                string `json:"arch,omitempty"`
	ID                  int64  `json:"id"`
	GroupID             int64  `json:"groupId"`
	Registration
	Version     string    `json:"version"`
	Revision    string    `json:"revision"`
	ApplyError  string    `json:"applyError"`
	UpdateError string    `json:"updateError"`
	LastSeen    time.Time `json:"lastSeen"`
	Online      bool      `json:"online"`
	Revoked     bool      `json:"revoked,omitempty"`
	Metrics     Metrics   `json:"metrics"`
}

type QuotaClaim struct {
	ExitMeter string `json:"exitMeter,omitempty"`
	Requested int64  `json:"requested,omitempty"`
	Owner     int64  `json:"owner"`
	Epoch     int64  `json:"epoch"`
	ID        string `json:"id,omitempty"`
	Spent     int64  `json:"spent,omitempty"`
	Close     bool   `json:"close,omitempty"`
	Want      bool   `json:"want,omitempty"`
}

type QuotaGrant struct {
	Owner     int64  `json:"owner"`
	Epoch     int64  `json:"epoch"`
	ID        string `json:"id"`
	Allocated int64  `json:"allocated"`
	Expires   int64  `json:"expires"`
}

type DiagnosticTask struct {
	PortCheck    *PortCheck `json:"portCheck,omitempty"`
	ProbeSamples int        `json:"probeSamples,omitempty"`
	ProbeOffset  int64      `json:"probeOffset,omitempty"`
	PingHost     string     `json:"pingHost,omitempty"`
	PublicOnly   bool       `json:"publicOnly,omitempty"`
	ID           string     `json:"id"`
	Address      string     `json:"address,omitempty"`
	RuleID       int64      `json:"ruleId,omitempty"`
	Revision     string     `json:"revision,omitempty"`
}

type DiagnosticResult struct {
	RecentRoutes []RecentRoute    `json:"recentRoutes,omitempty"`
	Bindings     []PortBinding    `json:"bindings,omitempty"`
	Links        []LinkProbe      `json:"links,omitempty"`
	Address      string           `json:"address,omitempty"`
	Error        string           `json:"error,omitempty"`
	ID           string           `json:"id"`
	Connected    bool             `json:"connected"`
	LatencyMS    int64            `json:"latencyMs"`
	Backup       bool             `json:"backup,omitempty"`
	RuleStatus   string           `json:"ruleStatus,omitempty"`
	PrimaryRoute *RouteDiagnostic `json:"primaryRoute,omitempty"`
	BackupRoute  *RouteDiagnostic `json:"backupRoute,omitempty"`
}

type RecentRoute struct {
	Network string `json:"network"`
	At      int64  `json:"at"`
	Backup  bool   `json:"backup"`
}

type PortCheck struct {
	Port    int    `json:"port"`
	Network string `json:"network"`
	HAProxy bool   `json:"haProxy,omitempty"`
}

type PortBinding struct {
	Network string `json:"network"`
	Address string `json:"address"`
	Status  string `json:"status"`
}

type RouteDiagnostic struct {
	Status    string      `json:"status"`
	LatencyMS int64       `json:"latencyMs"`
	Trace     *RouteTrace `json:"trace,omitempty"`
}

type RouteTrace struct {
	Reached int         `json:"reached"`
	Hops    int         `json:"hops"`
	Steps   []ProbeStep `json:"steps,omitempty"`
	Target  string      `json:"target,omitempty"`
}

type LinkProbe struct {
	Network        string       `json:"network"`
	Lane           string       `json:"lane"`
	MeasuresTarget bool         `json:"measuresTarget"`
	Traces         []RouteTrace `json:"traces"`
}

type ProbeStep struct {
	GroupID   int64  `json:"groupId,omitempty"`
	Transport string `json:"transport,omitempty"`
	Status    string `json:"status"`
	Phase     string `json:"phase,omitempty"`
	LatencyMS int64  `json:"latencyMs"`
}

type ReverseEndpoint struct {
	Address     string `json:"address"`
	Certificate string `json:"certificate"`
	Token       string `json:"token"`
}
