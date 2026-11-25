import { memo, useEffect, useMemo, useRef, useState } from "react";
import { Alert, App, Button, Drawer, Grid, Input, Modal, Select, Space, Spin, Table } from "antd";
import type { TableColumnsType } from "antd";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ChevronRight,
  Copy,
  Layers3,
  Server,
  Search,
  Stethoscope,
  Trash2,
} from "lucide-react";
import { api, bytes, date, useData } from "./api";
import type { Group, Node, NodeBandwidth, User } from "./api";
import { useConfirmAction } from "./confirm-action";
import DismissibleTooltip from "./dismissible-tooltip";
import IconAction from "./icon-action";
import { NodeFlag, nodeDisplayName, nodeRegion } from "./node-location";

const speed = (mbps: number) =>
  mbps >= 1000 ? (mbps / 1000).toFixed(2) + " Gbps" :
    mbps >= 1 ? mbps.toFixed(2) + " Mbps" : (mbps * 1000).toFixed(1) + " Kbps";
const uptime = (sec: number) => {
  const days = Math.floor(sec / 86400);
  return days > 0
    ? days + " 天"
    : new Date(Math.max(sec, 0) * 1000).toISOString().slice(11, 19);
};
const resources = [["cpu", "CPU"], ["ram", "内存"], ["disk", "磁盘"]] as const;
const trafficDirections = [
  { label: "上行", rate: "outMbps", total: "outBytes", cumulative: "累计上传", Icon: ArrowUp },
  { label: "下行", rate: "inMbps", total: "inBytes", cumulative: "累计下载", Icon: ArrowDown },
] as const;
type TrafficDirection = (typeof trafficDirections)[number];

function ResourceMeter({ node, metric, label, narrow }: {
  node: Node;
  metric: (typeof resources)[number][0];
  label: string;
  narrow: boolean;
}) {
  const { metrics } = node;
  const percent = Math.max(0, Math.min(100, Math.round(metrics[metric] || 0)));
  const level = !node.online ? "offline" :
    percent >= 90 ? "critical" :
    percent >= 80 ? "high" :
    percent >= 60 ? "elevated" : "normal";
  if (!node.online) return <span className="probe-meter" data-level={level}>
    <span aria-hidden="true" className="probe-track" />
    —
  </span>;

  const cpu = metric === "cpu" ? metrics.cpuDetails : undefined;
  const capacity = metric === "ram" ? metrics.memoryBytes : metric === "disk" ? metrics.diskBytes : undefined;
  return <DismissibleTooltip clickToOpen={narrow} title={<div className="probe-resource-tooltip">
    <strong>{label} · {percent}%</strong>
    {cpu?.model && <div>{cpu.model}</div>}
    {!!cpu?.logicalCPUs && <div>逻辑核心 {cpu.logicalCPUs}</div>}
    {cpu?.loadAverage && <div>平均负载 {cpu.loadAverage}</div>}
    {!!cpu?.processes && <div>进程数 {cpu.processes}</div>}
    {!!capacity?.total && <div>已用 / 总量 {bytes(capacity.used)} / {bytes(capacity.total)}</div>}
  </div>}>
    <button type="button" className="probe-meter" data-level={level} aria-label={`${label}占用 ${percent}%`}>
      <span aria-hidden="true" className="probe-track">
        <i style={{ width: percent + "%" }} />
      </span>
      {percent}%
    </button>
  </DismissibleTooltip>;
}

function ResourceUsage({ node, narrow }: { node: Node; narrow: boolean }) {
  return <dl className="probe-resources">
    {resources.map(([key, label]) => <div key={key}>
      <dt>{label}</dt><dd><ResourceMeter node={node} metric={key} label={label} narrow={narrow} /></dd>
    </div>)}
  </dl>;
}

function TrafficValue({ bandwidth, direction, online = true, node, narrow }: {
  bandwidth: NodeBandwidth;
  direction: TrafficDirection;
  online?: boolean;
  node?: Node;
  narrow: boolean;
}) {
  const rate = online ? speed(bandwidth[direction.rate]) : "—";
  const [rateValue, unit] = rate.split(" ");
  const total = bandwidth.hasTotals ? bytes(bandwidth[direction.total]) : "—";
  return <DismissibleTooltip clickToOpen={narrow} title={<div>
    <div>{direction.cumulative} {total}</div>
    {node && <div>连接数 · TCP {node.metrics.tcpConnections ?? 0} / UDP {node.metrics.udpSessions ?? 0}</div>}
  </div>}>
    <button type="button" className="button-link probe-rate" aria-label={`${direction.label} ${rate}，${direction.cumulative} ${total}`}>
      {rateValue}{unit && <> <span className="probe-rate-unit">{unit}</span></>}
    </button>
  </DismissibleTooltip>;
}

function TrafficRates({ bandwidth, online = true }: { bandwidth: NodeBandwidth; online?: boolean }) {
  return <dl className="node-speeds">
    {trafficDirections.map(({ label, rate, total, Icon }) => <div key={label}>
      <dt><Icon size={13} aria-hidden="true" />{label}</dt>
      <dd>
        <strong>{online ? speed(bandwidth[rate]) : "—"}</strong>
        <span>累计 {bandwidth.hasTotals ? bytes(bandwidth[total]) : "—"}</span>
      </dd>
    </div>)}
  </dl>;
}

function NodeStatus({ online }: { online: boolean }) {
  return <span className={online ? "probe-status online" : "probe-status offline"}>
    <i aria-hidden="true" className={online ? "status-dot online" : "status-dot"} />{online ? "在线" : "离线"}
  </span>;
}

function sumBandwidth(nodes: Node[]) {
  const bandwidth = { inMbps: 0, outMbps: 0, inBytes: 0, outBytes: 0, hasTotals: false };
  for (const node of nodes) {
    if (node.online) {
      bandwidth.inMbps += node.metrics.inMbps;
      bandwidth.outMbps += node.metrics.outMbps;
    }
    if (node.metrics.hasTotals) {
      bandwidth.hasTotals = true;
      bandwidth.inBytes += node.metrics.inBytes ?? 0;
      bandwidth.outBytes += node.metrics.outBytes ?? 0;
    }
  }
  return bandwidth;
}

type Event = { items: Node[]; removed: number[] };
type BandwidthEvent = { id: number; bandwidth: NodeBandwidth };
type Sample = {
  timestamp: number;
  cpu: number;
  ram: number;
  disk: number;
  in: number;
  out: number;
};
type Diagnostic = { status: string; detail: string; age: number };
type NodeRollout = { version: string; node?: number; name?: string; phase: string; reason?: string };

type ConnectivityRule = { id: number; name: string; port: number };
type ConnectivityResult = { connected: boolean; latencyMs: number; backup?: boolean };

const ConnectivityTest = memo(function ConnectivityTest({ nodeID }: { nodeID: number }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [ruleOptions, setRuleOptions] = useState<{ query: string; items?: ConnectivityRule[]; error?: string }>();
  const [selected, setSelected] = useState<{ value: number; label: string }>();
  const [result, setResult] = useState<ConnectivityResult>();
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const testRequest = useRef<AbortController | undefined>(undefined);
  const path = "/nodes/" + nodeID + "/connectivity";
  const query = search.trim();
  const currentOptions = ruleOptions?.query === query ? ruleOptions : undefined;
  const loadingRules = open && !currentOptions;

  useEffect(() => {
    if (!open) return;
    const request = new AbortController();
    const timer = window.setTimeout(async () => {
      try {
        const items = await api<ConnectivityRule[]>(path + "/rules?q=" + encodeURIComponent(query), "GET", undefined, request.signal);
        if (!request.signal.aborted) setRuleOptions({ query, items });
      } catch (e) {
        if (!request.signal.aborted) setRuleOptions({ query, error: (e as Error).message });
      }
    }, query ? 250 : 0);
    return () => {
      window.clearTimeout(timer);
      request.abort();
    };
  }, [open, path, query]);

  useEffect(() => () => testRequest.current?.abort(), []);

  async function testRule() {
    if (!selected || testRequest.current) return;
    const request = new AbortController();
    testRequest.current = request;
    setPending(true);
    setError("");
    setResult(undefined);
    try {
      const response = await api<ConnectivityResult>(path, "POST", { ruleId: selected.value }, request.signal);
      if (!request.signal.aborted) setResult(response);
    } catch (e) {
      if (!request.signal.aborted) setError((e as Error).message);
    } finally {
      testRequest.current = undefined;
      if (!request.signal.aborted) setPending(false);
    }
  }

  return <div className="probe-history">
    <h3>转发链路诊断</h3>
    <Space.Compact block>
      <Select aria-label="搜索转发规则" placeholder="搜索规则名称或监听端口" style={{ flex: 1, minWidth: 0 }}
        showSearch allowClear labelInValue filterOption={false} value={selected} disabled={pending}
        searchValue={search} onSearch={setSearch}
        onOpenChange={visible => {
          setOpen(visible);
          if (!visible) {
            setSearch("");
            setRuleOptions(undefined);
          }
        }}
        onChange={value => {
          setSelected(value);
          setResult(undefined);
          setError("");
        }}
        loading={loadingRules}
        options={currentOptions?.items?.map(rule => ({
          value: rule.id,
          label: (rule.name || "未命名规则") + " · 端口 " + rule.port,
        })) ?? []}
        notFoundContent={loadingRules ? <Spin size="small" /> : currentOptions?.error ||
          (query ? "未找到匹配的规则" : "此节点暂无可诊断的 TCP 规则")} />
      <Button onClick={() => void testRule()} disabled={!selected} loading={pending}>测试 TCP 链路</Button>
    </Space.Compact>
    {(error || result) && <Alert style={{ marginTop: 12 }}
      type={error ? "error" : result?.connected ? "success" : "warning"}
      message={error || (result?.connected
        ? (result.backup ? "备用链路已接通" : "链路已接通") + " · " + result.latencyMs + " ms"
        : "目标连接失败")} />}
  </div>;
});

export default function Nodes({ user, lookingGlass, showExitIP }: { user: User; lookingGlass: boolean; showExitIP: boolean }) {
  const screens = Grid.useBreakpoint();
  const narrow = !screens.lg;
  const mobile = screens.md === false;
  const { message } = App.useApp();
  const confirmAction = useConfirmAction();
  const [rollout, setRollout] = useState<NodeRollout>();
  const [resumingRollout, setResumingRollout] = useState(false);
  useEffect(() => {
    if (!user.admin) return;
    const request = new AbortController();
    let timer: number;
    async function refreshRollout() {
      try {
        if (!document.hidden) {
          const result = await api<NodeRollout>("/admin/node-rollout", "GET", undefined, request.signal);
          if (!request.signal.aborted) {
            setRollout(current => current?.version === result.version && current.node === result.node &&
              current.name === result.name && current.phase === result.phase && current.reason === result.reason ? current : result);
          }
        }
      } catch {
        // The next refresh can recover from a transient panel restart.
      } finally {
        if (!request.signal.aborted) timer = window.setTimeout(refreshRollout, 5000);
      }
    }
    void refreshRollout();
    return () => { request.abort(); window.clearTimeout(timer); };
  }, [user.admin]);

  async function resumeRollout() {
    setResumingRollout(true);
    try {
      setRollout(await api<NodeRollout>("/admin/node-rollout/resume", "POST"));
      message.success("已继续发布");
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setResumingRollout(false);
    }
  }
  const [nodes, setNodes] = useState<Record<number, Node>>({});
  const [connected, setConnected] = useState(false);
  const [received, setReceived] = useState(false);
  const [nodeError, setNodeError] = useState("");
  const [group, setGroup] = useState<number>();
  const [search, setSearch] = useState("");
  const [online, setOnline] = useState("all");
  const [detail, setDetail] = useState<number>();
  const [history, setHistory] = useState<Sample[]>([]);
  const [diagnostic, setDiagnostic] = useState<Diagnostic>();
  const [diagBusy, setDiagBusy] = useState(false);
  const [diagError, setDiagError] = useState("");
  const [pingNodeID, setPingNodeID] = useState<number>();
  const [pingHost, setPingHost] = useState("");
  const [pingPending, setPingPending] = useState(false);
  const [pingResult, setPingResult] = useState<{ id: number; text: string; ok: boolean }>();
  const pingNode = pingNodeID === undefined ? undefined : nodes[pingNodeID];
  const canPing = Boolean(lookingGlass && pingNode?.online && pingNode.acceptPing);
  const pingRequest = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => pingRequest.current?.abort(), []);

  function closePing() {
    pingRequest.current?.abort();
    pingRequest.current = undefined;
    setPingNodeID(undefined);
    setPingPending(false);
  }

  async function ping() {
    if (!pingNode || !canPing || !pingHost.trim() || pingRequest.current) return;
    const nodeID = pingNode.id;
    const request = new AbortController();
    pingRequest.current = request;
    setPingResult(undefined);
    setPingPending(true);
    try {
      const result = await api<{ connected: boolean; latencyMs: number; address?: string; error?: string }>(
        "/nodes/" + nodeID + "/ping", "POST", { host: pingHost.trim() }, request.signal,
      );
      const label = result.connected ? "Ping 成功 · " + result.latencyMs + " ms" : result.error || "未收到 Ping 响应";
      if (!request.signal.aborted) setPingResult({ id: nodeID, ok: result.connected, text: label + (result.address ? " · " + result.address : "") });
    } catch (error) {
      if (!request.signal.aborted) setPingResult({ id: nodeID, ok: false, text: (error as Error).message });
    } finally {
      if (pingRequest.current === request) {
        pingRequest.current = undefined;
        setPingPending(false);
      }
    }
  }
  const groups = useData<Group[]>("/groups?online=1", []);
  useEffect(() => {
    const request = new AbortController();
    setHistory([]);
    if (detail !== undefined)
      void api<Sample[]>("/nodes/" + detail + "/history", "GET", undefined, request.signal)
        .then((samples) => {
          if (!request.signal.aborted) setHistory(samples);
        })
        .catch(() => undefined);
    return () => request.abort();
  }, [detail]);
  async function diagnose(id: number) {
    setDetail(id);
    setDiagnostic(undefined);
    setDiagError("");
    setDiagBusy(true);
    try {
      setDiagnostic(
        await api<Diagnostic>("/nodes/" + id + "/diagnose", "POST"),
      );
    } catch (e) {
      setDiagError((e as Error).message);
    } finally {
      setDiagBusy(false);
    }
  }
  useEffect(() => {
    let stream: EventSource | undefined;
    let alive = true;
    let hasSnapshot = false;
    function updateStream() {
      if (document.hidden) {
        stream?.close();
        stream = undefined;
        setConnected(false);
        return;
      }
      if (stream) return;
      const source = new EventSource("/api/nodes/events");
      stream = source;
      let reset = true;
      source.onopen = () => {
        reset = true;
        setConnected(true);
      };
      source.onerror = () => {
        reset = true;
        setConnected(false);
      };
      source.onmessage = (event) => {
        const { items, removed } = JSON.parse(event.data) as Event;
        hasSnapshot = true;
        setReceived(true);
        setNodeError("");
        const replace = reset;
        reset = false;
        if (!replace && items.length + removed.length === 0) return;
        setNodes((current) => {
          const next = replace ? {} : { ...current };
          for (const node of items) next[node.id] = node;
          for (const id of removed) delete next[id];
          return next;
        });
      };
      source.addEventListener("bandwidth", (event: MessageEvent<string>) => {
        if (reset) return;
        const changes = JSON.parse(event.data) as BandwidthEvent[];
        setNodes((current) => {
          const next = { ...current };
          for (const { id, bandwidth } of changes) {
            const node = current[id];
            if (node?.online) {
              const { inMbps, outMbps, inBytes, outBytes, hasTotals } = bandwidth;
              next[id] = { ...node, metrics: { ...node.metrics, inMbps, outMbps, inBytes, outBytes, hasTotals } };
            }
          }
          return next;
        });
      });
    }
    updateStream();
    document.addEventListener("visibilitychange", updateStream);
    void api<Node[]>("/nodes")
      .then((items) => {
        if (!alive || hasSnapshot) return;
        setNodes(Object.fromEntries(items.map((n) => [n.id, n])));
        setReceived(true);
      })
      .catch((error: Error) => {
        if (alive && !hasSnapshot) setNodeError(error.message);
      });
    return () => {
      alive = false;
      stream?.close();
      document.removeEventListener("visibilitychange", updateStream);
    };
  }, []);
  const visibleGroups = useMemo(() => groups.value.filter(g => g.onlineDevices !== undefined), [groups.value]);
  const byGroup = useMemo(() => {
    const grouped = new Map<number, Node[]>();
    for (const node of Object.values(nodes)) {
      const members = grouped.get(node.groupId);
      if (members) members.push(node);
      else grouped.set(node.groupId, [node]);
    }
    return grouped;
  }, [nodes]);
  const loading = groups.busy || (!received && !nodeError);
  const visibleNodes = visibleGroups.flatMap(g => byGroup.get(g.id) ?? []);
  const onlineNodes = visibleNodes.filter(node => node.online);
  const searchTerm = search.trim().toLowerCase();
  const filtered = group !== undefined || Boolean(searchTerm) || online !== "all";
  const shown = visibleGroups.filter(g => group === undefined || g.id === group).flatMap(group => {
    const all = byGroup.get(group.id) ?? [];
    const matches = online === "all" && !searchTerm ? all : all.filter(node =>
      (online === "all" || node.online === (online === "online")) &&
      (!searchTerm || [node.name, nodeDisplayName(node), nodeRegion(node), node.countryCode, node.region, node.ipv4, node.ipv6, node.address]
        .some(value => value?.toLowerCase().includes(searchTerm))));
    return matches.length || ((user.admin || group.owner === user.id) && !searchTerm && online === "all")
      ? [{ group, all, matches }]
      : [];
  });
  const active = detail === undefined ? undefined : nodes[detail];
  const rolloutNode = rollout?.node === undefined ? undefined : nodes[rollout.node];
  const rolloutName = rolloutNode ? nodeDisplayName(rolloutNode) : rollout?.node && nodeDisplayName({
    id: rollout.node,
    name: rollout.name ?? "",
  });
  const rolloutReason = rollout?.reason?.trim();
  let rolloutFailure = rolloutReason;
  if (rolloutReason?.startsWith(`${rollout?.version}:`)) {
    if (/HAProxy startup timed out/i.test(rolloutReason)) rolloutFailure = "HAProxy 启动超时";
    else if (/HAProxy (configuration rejected|exited before becoming ready)|start HAProxy:/i.test(rolloutReason)) rolloutFailure = "HAProxy 启动失败";
    else if (/\bGet\s.*(?:deadline exceeded|timeout)/i.test(rolloutReason)) rolloutFailure = "下载更新包超时";
    else rolloutFailure = "节点升级失败";
  }
  const historyPeak = history.reduce((peak, point) => Math.max(peak, point.in, point.out), 0);
  const bandwidth = sumBandwidth(visibleNodes);
  const summary = [
    { label: "在线节点", value: onlineNodes.length, total: visibleNodes.length, icon: Server },
    { label: "离线节点", value: visibleNodes.length - onlineNodes.length, icon: Activity },
    { label: "实时上行", value: speed(bandwidth.outMbps), cumulative: bandwidth.hasTotals ? bytes(bandwidth.outBytes) : "—", icon: ArrowUp },
    { label: "实时下行", value: speed(bandwidth.inMbps), cumulative: bandwidth.hasTotals ? bytes(bandwidth.inBytes) : "—", icon: ArrowDown },
  ];

  function showDetails(id: number) {
    setDiagnostic(undefined);
    setDiagError("");
    setDetail(id);
  }

  function renderAddresses(node: Node) {
    const addresses = [node.ipv4, node.ipv6].filter(Boolean);
    if (!addresses.length) return node.address ? <span className="mono">{node.address}</span> : null;
    return <div className="probe-addresses">
      {addresses.map(ip => <button key={ip} type="button" className="button-link mono" aria-label={"复制地址 " + ip}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(ip);
            message.success("地址已复制");
          } catch {
            message.error("复制失败，请手动复制地址");
          }
        }}>
        {ip}<Copy size={12} aria-hidden="true" />
      </button>)}
    </div>;
  }

  function hideOfflineNode(node: Node) {
    confirmAction({
      title: "从状态列表移除 " + nodeDisplayName(node) + "？",
      content: "节点的接入记录会保留。恢复心跳后，它会自动回到列表。",
      okText: "移除",
      onOk: async () => {
        try {
          await api("/admin/nodes/" + node.id + "/hide-status", "POST");
          setNodes(current => {
            if (current[node.id]?.online) return current;
            const next = { ...current };
            delete next[node.id];
            return next;
          });
          setDetail(current => current === node.id ? undefined : current);
          message.success("已从状态列表移除");
          return true;
        } catch (error) {
          message.error((error as Error).message);
          return false;
        }
      },
    });
  }

  function renderActions(node: Node) {
    const canRemove = user.admin && !node.online;
    return <div className="probe-actions">
      {node.online && (user.admin || lookingGlass) && <Button
        type="link" size="small" className="probe-ping-action"
        onClick={() => {
          setPingHost("");
          setPingResult(undefined);
          setPingNodeID(node.id);
        }}>Ping</Button>}
      {canRemove
        ? <IconAction danger label="从状态列表移除" icon={<Trash2 size={16} />} onClick={() => hideOfflineNode(node)} />
        : <IconAction label="诊断" icon={<Stethoscope size={16} />} onClick={() => void diagnose(node.id)} />}
      <IconAction label="详情" icon={<ChevronRight size={17} />} onClick={() => showDetails(node.id)} />
    </div>;
  }

  const addressColumn: TableColumnsType<Node>[number] = {
    title: "出口 IP",
    key: "address",
    width: mobile ? 148 : screens.xl ? "18%" : "15%",
    shouldCellUpdate: (node, previous) =>
      node.address !== previous.address || node.ipv4 !== previous.ipv4 || node.ipv6 !== previous.ipv6,
    render: (_, node) => renderAddresses(node) || "—",
  };
  const columns: TableColumnsType<Node> = [
    {
      title: narrow ? "节点" : "节点 / 地区",
      key: "name",
      width: mobile ? 120 : undefined,
      render: (_, node) => {
        const name = nodeDisplayName(node);
        return <div className="probe-node">
          <button type="button" className="button-link data-title node-name" title={name} onClick={() => showDetails(node.id)}>
            <NodeFlag node={node} /><span>{name}</span>
          </button>
          {narrow && <NodeStatus online={node.online} />}
        </div>;
      },
    },
    ...(!narrow && showExitIP ? [addressColumn] : []),
    ...(!narrow ? [
      {
        title: "状态",
        key: "status",
        width: 56,
        render: (_: unknown, node: Node) => <NodeStatus online={node.online} />,
      },
    ] : []),
    ...trafficDirections.map(direction => ({
      title: direction.label,
      key: `${direction.rate}-${narrow ? "mobile" : "desktop"}`,
      width: mobile ? 84 : narrow ? "25%" : screens.xl ? 105 : 90,
      className: "probe-rate-cell",
      align: "right" as const,
      shouldCellUpdate: (node: Node, previous: Node) =>
        node.online !== previous.online || node.metrics[direction.rate] !== previous.metrics[direction.rate] ||
        node.metrics[direction.total] !== previous.metrics[direction.total] ||
        node.metrics.hasTotals !== previous.metrics.hasTotals ||
        node.metrics.tcpConnections !== previous.metrics.tcpConnections ||
        node.metrics.udpSessions !== previous.metrics.udpSessions,
      render: (_: unknown, node: Node) => <TrafficValue bandwidth={node.metrics} direction={direction} online={node.online} node={node} narrow={narrow} />,
    })),
    ...(narrow && showExitIP ? [addressColumn] : []),
    ...(!narrow || mobile ? [
      ...resources.map(([metric, label]) => ({
        title: label,
        key: `${metric}-${narrow ? "mobile" : "desktop"}`,
        width: mobile ? 68 : screens.xl ? "8%" : "6%",
        shouldCellUpdate: (node: Node, previous: Node) => {
          if (node.online !== previous.online || node.metrics[metric] !== previous.metrics[metric]) return true;
          if (metric === "cpu") {
            const current = node.metrics.cpuDetails;
            const old = previous.metrics.cpuDetails;
            return current?.model !== old?.model || current?.logicalCPUs !== old?.logicalCPUs ||
              current?.loadAverage !== old?.loadAverage || current?.processes !== old?.processes;
          }
          const field = metric === "ram" ? "memoryBytes" : "diskBytes";
          return node.metrics[field]?.used !== previous.metrics[field]?.used ||
            node.metrics[field]?.total !== previous.metrics[field]?.total;
        },
        render: (_: unknown, node: Node) => <ResourceMeter node={node} metric={metric} label={label} narrow={narrow} />,
      })),
      {
        title: "运行时长",
        key: "uptime",
        width: 68,
        render: (_: unknown, node: Node) => node.online ? uptime(node.metrics.uptime) : "—",
      },
    ] : []),
    {
      title: "操作",
      key: "action",
      align: "right",
      width: user.admin || lookingGlass ? 112 : narrow ? 72 : 76,
      render: (_, node) => renderActions(node),
    },
  ];

  return (
    <section className="panel-table probe-page">
      <header className="page-head">
        <h1>节点状态</h1>
        <span className="connection-state" role="status">
          <i aria-hidden="true" className={"status-dot " + (connected ? "online" : "")} />
          {connected ? "实时连接" : received ? "正在重连" : "正在连接"}
        </span>
      </header>
      {(groups.error || nodeError) && <Alert showIcon type="error" message={groups.error || nodeError} className="alert-gap" />}
      {user.admin && rollout?.version && ["updating", "checking", "paused"].includes(rollout.phase) &&
        <Alert showIcon className="alert-gap probe-rollout" type={rollout.phase === "paused" ? "warning" : "info"}
          message={<div className="probe-rollout-message">
            <strong>{rollout.phase === "paused" ? "节点发布已暂停" : rollout.phase === "checking" ? "正在检查节点状态" : "正在逐台升级"}</strong>
            <span>{[rolloutName, rollout.version].filter(Boolean).join(" · ")}</span>
            {rollout.phase === "paused" && rolloutFailure && (
              rolloutFailure === rolloutReason ? <span>{rolloutFailure}</span> :
                <details className="probe-rollout-error">
                  <summary>{rolloutFailure}</summary>
                  <p>{rolloutReason}</p>
                </details>
            )}
          </div>}
          action={rollout.phase === "paused" && <Button size="small" loading={resumingRollout} onClick={() => void resumeRollout()}>跳过此节点</Button>} />}
      <dl className="probe-overview">
        {summary.map(({ label, value, total, cumulative, icon: Icon }) => {
          const [amount, unit] = String(loading || (!received && nodeError) ? "—" : value).split(" ");
          return <div key={label}>
            <dt><Icon size={14} aria-hidden="true" />{label}</dt>
            <dd>
              <span className="probe-overview-value">
                {amount}{unit && <> <small>{unit}</small></>}
                {!loading && received && total !== undefined && <small> / {total}</small>}
              </span>
              {cumulative !== undefined && !loading && received && <span className="probe-overview-total">网卡累计 {cumulative}</span>}
            </dd>
          </div>;
        })}
      </dl>
      <div className="probe-filters">
        <Input
          aria-label="搜索节点"
          placeholder={narrow ? "搜索" : "搜索节点"}
          prefix={<Search size={15} />}
          allowClear
          value={search}
          onChange={event => setSearch(event.target.value)}
        />
        <Select
          aria-label="设备组"
          value={group}
          allowClear
          placeholder={narrow ? "设备组" : "全部设备组"}
          options={visibleGroups.map(g => ({ value: g.id, label: g.folder ? g.folder + " / " + g.name : g.name }))}
          onChange={setGroup}
        />
        <Select
          aria-label="节点在线状态"
          value={online}
          onChange={setOnline}
          options={[
            { value: "all", label: "全部状态" },
            { value: "online", label: "在线" },
            { value: "offline", label: "离线" },
          ]}
        />
        {filtered && <Button type="text" onClick={() => {
          setSearch("");
          setGroup(undefined);
          setOnline("all");
        }}>清除筛选</Button>}
      </div>
      {loading ? <div className="probe-empty" role="status"><Spin size="small" />正在读取节点</div> : (
        <div className="node-grid">
          {shown.map(({ group: g, all, matches }) => {
            const running = all.filter(node => node.online);
            const totals = sumBandwidth(all);
            return (
              <section className="node-section" key={g.id} aria-labelledby={"node-group-" + g.id}>
                <header className="node-head">
                  <div className="node-group">
                    <Layers3 size={18} aria-hidden="true" />
                    <div>
                      {g.folder && <span className="data-secondary">{g.folder}</span>}
                      <h2 id={"node-group-" + g.id}>{g.name}</h2>
                    </div>
                    <span className="node-count">{running.length} / {all.length} 在线</span>
                  </div>
                  {all.length > 0 && <div className="probe-group-rates">
                    {trafficDirections.map(direction => <div key={direction.rate}>
                      <direction.Icon size={12} aria-hidden="true" />
                      <span className="probe-group-rate-label">总{direction.label}</span>
                      <TrafficValue bandwidth={totals} direction={direction} narrow={narrow} />
                    </div>)}
                  </div>}
                </header>
                {matches.length > 0 ? <Table<Node>
                  className="node-table"
                  size="small"
                  rowKey="id"
                  tableLayout="fixed"
                  scroll={mobile ? { x: (showExitIP ? 780 : 632) + (user.admin || lookingGlass ? 40 : 0) } : undefined}
                  dataSource={matches}
                  pagination={matches.length > 25 ? { pageSize: 25, hideOnSinglePage: true, size: "small" } : false}
                  columns={columns}
                /> : <p className="probe-group-empty">此设备组暂无节点</p>}
              </section>
            );
          })}
          {!shown.length && (received || !nodeError) && <div className="probe-empty">
            <Server size={23} aria-hidden="true" />
            <strong>{filtered ? "没有符合筛选条件的节点" : "暂无可见节点"}</strong>
            {user.admin && !filtered && <Button href="#/groups">设备组管理</Button>}
          </div>}
        </div>
      )}
      <Drawer
        open={!!active}
        onClose={() => setDetail(undefined)}
        title={active ? nodeDisplayName(active) : "节点详情"}
        width="min(480px, 100vw)"
        className="probe-drawer"
      >
        {diagError && (
          <Alert type="error" message={diagError} className="alert-gap" />
        )}
        {diagnostic && (
          <Alert
            type={diagnostic.status === "在线" ? "success" : "warning"}
            message={diagnostic.detail}
            description={
              diagnostic.age > 0
                ? "最后上报 " + diagnostic.age + " 秒前"
                : undefined
            }
            className="alert-gap"
          />
        )}
        {diagBusy && <div className="alert-gap">正在读取诊断</div>}
        {active && (
          <div className="details-grid probe-detail-grid">
            <div className="probe-detail-resources"><ResourceUsage node={active} narrow={narrow} /></div>
            <div className="probe-detail-bandwidth">
              <TrafficRates bandwidth={active.metrics} online={active.online} />
            </div>
            <dl>
              <dt>地区</dt>
              <dd className="node-name"><NodeFlag node={active} />{active.region || nodeRegion(active) || "—"}</dd>
            </dl>
            <dl>
              <dt>最近上报</dt>
              <dd>{Date.parse(active.lastSeen) > 0 ? date(Date.parse(active.lastSeen) / 1000) : "尚未上报"}</dd>
            </dl>
            {showExitIP && <dl>
              <dt>出口 IP</dt>
              <dd>{renderAddresses(active) || "—"}</dd>
            </dl>}
            <dl>
              <dt>运行时长</dt>
              <dd>{active.online ? uptime(active.metrics.uptime) : "—"}</dd>
            </dl>
            <dl>
              <dt>运行版本</dt>
              <dd>{active.version || "—"}</dd>
            </dl>
            {user.admin && <dl>
              <dt>HAProxy</dt>
              <dd>{active.acceptHAProxy ? "可用" : "未就绪"}</dd>
            </dl>}
            <dl>
              <dt>系统和架构</dt>
              <dd>
                {[active.os, active.arch].filter(Boolean).join(" / ") || "—"}
              </dd>
            </dl>
            <dl>
              <dt>进程内存</dt>
              <dd>{bytes(active.metrics.rss)}</dd>
            </dl>
            <dl>
              <dt>监听数量</dt>
              <dd>
                {active.metrics.listeners}
                {active.metrics.listenerLimit
                  ? " / " + active.metrics.listenerLimit
                  : ""}
              </dd>
            </dl>
            <dl>
              <dt>TCP / UDP 连接</dt>
              <dd>
                {active.metrics.tcpConnections ?? 0} /{" "}
                {active.metrics.udpSessions ?? 0}
              </dd>
            </dl>
            {!!active.metrics.connectionLimit && (
              <dl>
                <dt>转发会话 / 容量</dt>
                <dd>{active.metrics.connections} / {active.metrics.connectionLimit}</dd>
              </dl>
            )}
            {!!active.metrics.fileLimit && (
              <dl>
                <dt>文件描述符</dt>
                <dd>{active.metrics.fileDescriptors ?? 0} / {active.metrics.fileLimit}</dd>
              </dl>
            )}
            <dl>
              <dt>UDP 排队丢弃</dt>
              <dd>{active.metrics.udpDrop ?? 0}</dd>
            </dl>
            {user.admin && (
              <>
                <dl>
                  <dt>目标版本</dt>
                  <dd>{active.targetVersion || active.version || "—"}</dd>
                </dl>
                <dl>
                  <dt>生效配置</dt>
                  <dd className="mono">{active.revision || "—"}</dd>
                </dl>
                <dl>
                  <dt>应用及升级状态</dt>
                  <dd>
                    {active.applyError ||
                      active.updateError ||
                      (active.online ? "运行中" : "等待连接")}
                  </dd>
                </dl>
              </>
            )}
          </div>
        )}
        {user.admin && active?.online && <ConnectivityTest key={active.id} nodeID={active.id} />}
        {history.length > 1 && (
          <div className="probe-history">
            <h3>近一小时带宽</h3>
            <div className="probe-history-bars" aria-label="近一小时上下行带宽">
              {history.map(point => (
                <span key={point.timestamp} title={date(point.timestamp) + " · 下行 " + speed(point.in) + " / 上行 " + speed(point.out)}>
                  <i style={{ height: (historyPeak ? point.in / historyPeak : 0) * 100 + "%" }} />
                  <b style={{ height: (historyPeak ? point.out / historyPeak : 0) * 100 + "%" }} />
                </span>
              ))}
            </div>
            <div className="probe-history-legend">
              <span><i />下行</span><span><b />上行</span>
              <small>峰值 {speed(historyPeak)}</small>
            </div>
          </div>
        )}
      </Drawer>
      <Modal open={pingNodeID !== undefined} centered width={440}
        title={"节点 Ping 测试" + (pingNode ? " · " + nodeDisplayName(pingNode) : "")}
        onCancel={closePing} footer={null} destroyOnHidden>
        {!lookingGlass ? <Alert showIcon type="info" message="节点 Ping 测试已关闭"
          description={user.admin ? <a href="#/settings" onClick={closePing}>前往站点设置开启</a> : undefined} />
          : !pingNode?.online ? <Alert showIcon type="warning" message="节点当前离线" />
            : !pingNode.acceptPing ? <Alert showIcon type="info" message="当前节点版本尚不支持 Ping" />
              : <Space.Compact block>
                <Input aria-label="Ping 目标" placeholder="输入域名或 IPv4 / IPv6" value={pingHost} disabled={pingPending}
                  onChange={event => setPingHost(event.target.value)} onPressEnter={() => void ping()} />
                <Button type="primary" disabled={!pingHost.trim()} loading={pingPending} onClick={() => void ping()}>开始 Ping</Button>
              </Space.Compact>}
        {pingResult && pingResult.id === pingNodeID && <Alert style={{ marginTop: 12 }} showIcon
          type={pingResult.ok ? "success" : "warning"} message={pingResult.text} />}
      </Modal>
    </section>
  );
}
