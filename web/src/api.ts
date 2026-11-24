import { useCallback, useEffect, useRef, useState } from "react";

export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method,
    signal,
    headers:
      body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    const message = typeof error?.error === "string" && error.error.trim();
    throw new Error(message || `HTTP ${response.status}`);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

export type DataReload = (options?: { throwOnError?: boolean }) => Promise<void>;

export function useData<T>(path: string | null, initial: T) {
  const [value, set] = useState(initial);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  const request = useRef<AbortController | undefined>(undefined);
  const reload = useCallback<DataReload>(async ({ throwOnError } = {}) => {
    request.current?.abort();
    if (path === null) {
      request.current = undefined;
      setBusy(false);
      setError("");
      return;
    }
    const current = new AbortController();
    request.current = current;
    setBusy(true);
    setError("");
    try {
      const data = await api<T>(path, "GET", undefined, current.signal);
      if (request.current === current && !current.signal.aborted) set(data);
      else if (throwOnError) throw new DOMException("Refresh cancelled", "AbortError");
    } catch (e) {
      if (!current.signal.aborted && request.current === current) {
        setError((e as Error).message);
      }
      if (throwOnError) throw e;
    } finally {
      if (request.current === current) setBusy(false);
    }
  }, [path]);
  useEffect(() => {
    void reload();
    return () => {
      request.current?.abort();
      request.current = undefined;
    };
  }, [reload]);
  return { value, error, busy, reload, set };
}

export type User = {
  affiliateBalance: number;
  allowDevice: boolean;
  id: number;
  name: string;
  admin: boolean;
  banned: boolean;
  group: number;
  quota: number;
  unlimitedTraffic: boolean;
  used: number;
  balance: number;
  expires: number;
  maxRules: number;
  planId: number;
  invite: string;
  autoRenew: boolean;
  note: string;
  serviceBlock?: string;
  service?: {
    group: string; plan: string; renewPrice: number; rateMbps: number; maxIPs: number; maxConnections: number;
    inviteRegistrationEnabled: boolean; referralRate: number; referralFirstOnly: boolean;
  };
};

export function hasPlan(user: Pick<User, "planId" | "serviceBlock">) {
  return user.planId > 0 && user.serviceBlock !== "请先订购套餐";
}

export function ruleLimitLabel(user: Pick<User, "maxRules" | "planId" | "serviceBlock">) {
  if (!hasPlan(user)) return "0";
  return user.maxRules === 0 ? "不限制" : String(user.maxRules);
}

export function planExpiryLabel(user: Pick<User, "expires" | "planId" | "serviceBlock">) {
  if (!hasPlan(user)) return "—";
  return user.expires >= 253402300799 ? "不限期" : date(user.expires);
}

export type Group = {
  onlineDevices?: number;
  routing?: { ingressMode?: string; statusVisibility?: string };
  ingress?: {
    blockPersonal?: boolean; siteOutboundOnly?: boolean; disableUDP?: boolean; rejectEmptySNI?: boolean;
    allowedHosts?: string[]; blockedHosts?: string[]; blockedPaths?: string[]; blockedTypes?: string[];
  };
  connectHost?: string;
  fallbackGroup?: number;
  relayMode?: string;
  defaultNetwork?: string;
  folder?: string;
  note?: string;
  showOrder?: number;
  hideStatus?: boolean;
  tlsIngress?: number;
  reverseGroups?: number[];
  portRanges?: string;
  chain?: number[];
  id: number;
  name: string;
  kind: string;
  owner: number;
  allowedFrom?: number[];
  allowedTo?: number[];
  firstPort: number;
  lastPort: number;
  ratio: number;
  userGroup: number;
  userGroups?: number[];
  offlineSeconds: number;
};
export type NodeBandwidth = {
  inMbps: number;
  outMbps: number;
  inBytes?: number;
  outBytes?: number;
  hasTotals?: boolean;
};

export type Node = {
  countryCode?: string;
  acceptHAProxy?: boolean;
  relayTransport?: string;
  nativeUDP?: boolean;
  acceptPing?: boolean;
  nativeUDPError?: string;
  relayModeError?: string;
  id: number;
  groupId: number;
  name: string;
  region: string;
  address: string;
  ipv4: string;
  ipv6: string;
  lastSeen: string;
  revoked?: boolean;
  version: string;
  targetVersion?: string;
  os?: string;
  arch?: string;
  revision: string;
  online: boolean;
  applyError: string;
  updateError: string;
  metrics: NodeBandwidth & {
    cpu: number;
    ram: number;
    disk: number;
    uptime: number;
    listeners: number;
    connections: number;
    tcpConnections?: number;
    udpSessions?: number;
    udpDrop?: number;
    listenerLimit?: number;
    connectionLimit?: number;
    fileDescriptors?: number;
    fileLimit?: number;
    rss: number;
  };
};
export type Rule = {
  ownerName?: string;
  serviceBlock?: string;
  runtime?: string;
  reportedAt?: number;
  routeRepair?: { entry?: boolean; path?: boolean; backupPath?: boolean };
  confirmRoute?: boolean;
  id: number;
  owner: number;
  name: string;
  label: string;
  entry: number;
  port: number;
  protocol: string;
  effectiveNetwork?: string;
  udpProbe?: boolean;
  probeInterval?: number;
  targets: string[] | null;
  path: number[] | null;
  backupPath: number[] | null;
  strategy: string;
  rateMbps: number;
  maxIPs: number;
  maxConns: number;
  enabled: boolean;
  proxyIn: boolean;
  proxyOut: boolean;
 proxyInVersion?:number;
 proxyOutVersion?:number;
  tlsCert: string;
  tlsKey: string;
  tlsGenerateFor?: string;
  tlsServerNames?: string[];
  tlsALPN?: string[];
  tlsRequireEmpty?: boolean;
  tlsShared?: boolean;
  tlsSharedPort?: number;
  tlsAllowedNames?: string[];
  tlsAllowedUsers?: number[];
  tlsOrigin?: number;
  responseFilters?: number[];
  in: number;
  out: number;
};
export type Plan = {
 kind:string;
  id: number;
  name: string;
  description: string;
  price: number;
  duration: number;
  quota: number;
  unlimitedTraffic: boolean;
  rules: number;
  groupId: number;
  enabled: boolean;
  rateMbps: number;
  maxIPs: number;
  maxConnections: number;
};
export type Order = {
  id: number;
  userId: number;
  amount: number;
  credit: number;
  kind: string;
  status: string;
  reference: string;
  description: string;
  created: number;
};
export type HomeLink = { title: string; url: string };

export type RegistrationVerification = "off" | "arithmetic" | "turnstile";

export type Site = {
  lookingGlass?: string;
  showAdminNodeIPs?: boolean;
  showShop?: string;
  showOrders?: string;
  showNodeStatus?: string;
  invitesEnabled?: string;
  version?: string;
  ruleProbeInterval?: string;
  name: string;
  announcement: string;
  homeLinks?: HomeLink[];
  registration: string;
  registrationPasswordBytes?: { min: number; max: number };
  registrationChallenge?: string;
  registrationVerification?: RegistrationVerification;
  registrationTurnstileSiteKey?: string;
  personalTunnels?: string;
};

export function bytes(n = 0): string {
  if (n < 1024) return `${n} B`;
  const size = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** size).toFixed(2)} ${["B", "KiB", "MiB", "GiB", "TiB"][size]}`;
}
export const currency = (n = 0) => "¥" + (n / 100).toFixed(2);
export const date = (n = 0) =>
  n > 0 ? new Date(n * 1000).toLocaleString("zh-CN", { hour12: false }) : "—";
