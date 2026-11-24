import { useEffect, useMemo, useState } from "react";
import { Alert, App, Button, Drawer, Grid, Input, InputNumber, Select, Space, Spin, Table } from "antd";
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
} from "lucide-react";
import { api, bytes, date, useData } from "./api";
import type { Group, Node, User } from "./api";
import IconAction from "./icon-action";
import { NodeFlag, nodeDisplayName, nodeRegion } from "./node-location";

const speed = (mbps: number) =>
  mbps >= 1 ? mbps.toFixed(2) + " Mbps" : (mbps * 1000).toFixed(1) + " Kbps";
const uptime = (sec: number) => {
  const days = Math.floor(sec / 86400);
  return days > 0
    ? days + " 天"
    : new Date(Math.max(sec, 0) * 1000).toISOString().slice(11, 19);
};
const resources = [["cpu", "CPU"], ["ram", "内存"], ["disk", "磁盘"]] as const;

function ResourceUsage({ node }: { node: Node }) {
  return <dl className="probe-resources">
    {resources.map(([key, label]) => {
      const percent = Math.max(0, Math.min(100, Math.round(node.metrics[key] || 0)));
      return <div key={key}>
        <dt>{label}</dt><dd>{node.online ? percent + "%" : "—"}</dd>
        <span aria-hidden="true" className="probe-track">
          <i className={percent >= 80 && node.online ? "warn" : undefined} style={{ width: (node.online ? percent : 0) + "%" }} />
        </span>
      </div>;
    })}
  </dl>;
}

function TrafficRates({ outbound, inbound }: { outbound: number; inbound: number }) {
  return <dl className="node-speeds">
    <div><dt aria-label="上行"><ArrowUp size={13} aria-hidden="true" /></dt><dd>{speed(outbound)}</dd></div>
    <div><dt aria-label="下行"><ArrowDown size={13} aria-hidden="true" /></dt><dd>{speed(inbound)}</dd></div>
  </dl>;
}

type Event = { items: Node[]; removed: number[] };
type Sample = {
  timestamp: number;
  cpu: number;
  ram: number;
  disk: number;
  in: number;
  out: number;
};
type Diagnostic = { status: string; detail: string; age: number };
type NodeRollout = { version: string; name?: string; phase: string; reason?: string };

export default function Nodes({ user, lookingGlass }: { user: User; lookingGlass: boolean }) {
  const narrow = Grid.useBreakpoint().lg === false;
  const { message } = App.useApp();
  const [rollout, setRollout] = useState<NodeRollout>();
  const [resumingRollout, setResumingRollout] = useState(false);
  useEffect(() => {
    if (!user.admin) return;
    const request = new AbortController();
    let timer: number;
    async function refreshRollout() {
      try {
        const result = await api<NodeRollout>("/admin/node-rollout", "GET", undefined, request.signal);
        if (!request.signal.aborted) setRollout(result);
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
  const [ruleID,setRuleID]=useState<number|null>();
  const [probeResult, setProbeResult] = useState<{ connected: boolean; latencyMs: number; backup?: boolean }>();
  const [probePending,setProbePending]=useState(false);
  const [pingHost, setPingHost] = useState("");
  const [pingPending, setPingPending] = useState(false);
  const [pingResult, setPingResult] = useState<{ id: number; text: string; ok: boolean }>();
  async function ping(nodeID: number) {
    if (!pingHost.trim()) return;
    setPingResult(undefined);
    setPingPending(true);
    try {
      const result = await api<{ connected: boolean; latencyMs: number; address?: string; error?: string }>(
        "/nodes/" + nodeID + "/ping", "POST", { host: pingHost.trim() },
      );
      const label = result.connected ? "Ping 成功 · " + result.latencyMs + " ms" : result.error || "未收到 Ping 响应";
      setPingResult({ id: nodeID, ok: result.connected, text: label + (result.address ? " · " + result.address : "") });
    } catch (error) {
      setPingResult({ id: nodeID, ok: false, text: (error as Error).message });
    } finally {
      setPingPending(false);
    }
  }
  const groups = useData<Group[]>("/groups?online=1", []);
  useEffect(() => {
    let active = true;
    setHistory([]);
    if (detail !== undefined)
      void api<Sample[]>("/nodes/" + detail + "/history")
        .then((samples) => {
          if (active) setHistory(samples);
        })
        .catch(() => undefined);
    return () => {
      active = false;
    };
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
  useEffect(()=>{
    setProbeResult(undefined);
    setRuleID(null);
  },[detail])
  async function testTarget(id:number){
    if(!ruleID)return;
    setProbeResult(undefined);
    setDiagError("");
    setProbePending(true);
    try{setProbeResult(await api<{connected:boolean;latencyMs:number;backup?:boolean}>("/nodes/"+id+"/connectivity","POST",{ruleId:ruleID}))}
    catch(e){setDiagError((e as Error).message)}
    finally{setProbePending(false)}
  }
  useEffect(() => {
    const stream = new EventSource("/api/nodes/events");
    let alive = true;
    let reset = true;
    stream.onopen = () => {
      reset = true;
      setConnected(true);
    };
    stream.onerror = () => {
      reset = true;
      setConnected(false);
    };
    stream.onmessage = (event) => {
      const { items, removed } = JSON.parse(event.data) as Event;
      setReceived(true);
      setNodeError("");
      const replace = reset;
      reset = false;
      setNodes((current) => {
        const next = replace ? {} : { ...current };
        for (const node of items) next[node.id] = node;
        for (const id of removed) delete next[id];
        return next;
      });
    };
    void api<Node[]>("/nodes")
      .then((items) => {
        if (!alive || !reset) return;
        setNodes(Object.fromEntries(items.map((n) => [n.id, n])));
        setReceived(true);
      })
      .catch((error: Error) => {
        if (alive && reset) setNodeError(error.message);
      });
    return () => {
      alive = false;
      stream.close();
    };
  }, []);
  const visibleGroups = groups.value.filter(g => g.onlineDevices !== undefined);
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
    const matches = all.filter(node => (online === "all" || node.online === (online === "online")) &&
      [node.name, nodeDisplayName(node), nodeRegion(node), node.countryCode, node.region, node.ipv4, node.ipv6, node.address].some(value => value?.toLowerCase().includes(searchTerm)));
    return matches.length || ((user.admin || group.owner === user.id) && !searchTerm && online === "all")
      ? [{ group, all, matches }]
      : [];
  });
  const active = detail === undefined ? undefined : nodes[detail];
  const historyPeak = history.reduce((peak, point) => Math.max(peak, point.in, point.out), 0);
  const summary = [
    { label: "在线节点", value: onlineNodes.length, total: visibleNodes.length, icon: Server },
    { label: "离线节点", value: visibleNodes.length - onlineNodes.length, icon: Activity },
    { label: "实时上行", value: speed(onlineNodes.reduce((sum, node) => sum + node.metrics.outMbps, 0)), icon: ArrowUp },
    { label: "实时下行", value: speed(onlineNodes.reduce((sum, node) => sum + node.metrics.inMbps, 0)), icon: ArrowDown },
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
        <Alert showIcon className="alert-gap" type={rollout.phase === "paused" ? "warning" : "info"}
          message={`节点版本 ${rollout.version} · ${rollout.phase === "paused" ? "发布已暂停" : rollout.phase === "checking" ? "检查新节点版本" : "正在逐台升级"}`}
          description={[rollout.name, rollout.reason].filter(Boolean).join(" · ")}
          action={rollout.phase === "paused" && <Button size="small" loading={resumingRollout} onClick={() => void resumeRollout()}>跳过并继续</Button>} />}
      <dl className="probe-overview">
        {summary.map(({ label, value, total, icon: Icon }) => <div key={label}>
          <dt><Icon size={16} aria-hidden="true" />{label}</dt>
          <dd>{loading || (!received && nodeError) ? "—" : value}
            {!loading && received && total !== undefined && <small> / {total}</small>}
          </dd>
        </div>)}
      </dl>
      <div className="probe-filters">
        <Input
          aria-label="搜索节点"
          placeholder="搜索节点、地区或地址"
          prefix={<Search size={15} />}
          allowClear
          value={search}
          onChange={event => setSearch(event.target.value)}
        />
        <Select
          aria-label="设备组"
          value={group}
          allowClear
          placeholder="全部设备组"
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
                  {all.length > 0 && <TrafficRates
                    outbound={running.reduce((sum, node) => sum + node.metrics.outMbps, 0)}
                    inbound={running.reduce((sum, node) => sum + node.metrics.inMbps, 0)}
                  />}
                </header>
                {matches.length > 0 ? <Table<Node>
                  className="node-table"
                  size="middle"
                  rowKey="id"
                  showHeader={!narrow}
                  dataSource={matches}
                  pagination={matches.length > 25 ? { pageSize: 25, hideOnSinglePage: true, size: "small" } : false}
                  columns={[
                    {
                      title: "节点",
                      key: "name",
                      width: narrow ? undefined : "26%",
                      render: (_, node) => (
                        <div className="probe-node">
                          <div className="probe-node-heading">
                            <button type="button" className="button-link data-title node-name" onClick={() => showDetails(node.id)}>
                              <NodeFlag node={node} />
                              <span>{nodeDisplayName(node)}</span>
                            </button>
                            <span className={node.online ? "probe-status online" : "probe-status"}>
                              <i aria-hidden="true" className={node.online ? "status-dot online" : "status-dot"} />{node.online ? "在线" : "离线"}
                            </span>
                          </div>
                          {(node.region || node.online) && <p className="data-secondary">
                            {[node.region, node.online ? "运行 " + uptime(node.metrics.uptime) : ""].filter(Boolean).join(" · ")}
                          </p>}
                          {narrow && <div className="probe-mobile-metrics">
                            {renderAddresses(node)}
                            {node.online && <TrafficRates outbound={node.metrics.outMbps} inbound={node.metrics.inMbps} />}
                            <ResourceUsage node={node} />
                          </div>}
                          {narrow && <div className="probe-actions">
                            <Button size="small" type="text" icon={<Stethoscope size={14} />} onClick={() => void diagnose(node.id)}>诊断</Button>
                            <Button size="small" type="text" icon={<ChevronRight size={15} />} onClick={() => showDetails(node.id)}>详情</Button>
                          </div>}
                        </div>
                      ),
                    },
                    ...(!narrow ? [
                      {
                        title: "出口 IP",
                        key: "address",
                        width: "24%",
                        render: (_: unknown, node: Node) => renderAddresses(node) || "—",
                      },
                      {
                        title: "实时带宽",
                        key: "traffic",
                        width: "15%",
                        render: (_: unknown, node: Node) => node.online ? <TrafficRates outbound={node.metrics.outMbps} inbound={node.metrics.inMbps} /> : "—",
                      },
                      {
                        title: "资源占用",
                        key: "resources",
                        width: "24%",
                        render: (_: unknown, node: Node) => <ResourceUsage node={node} />,
                      },
                      {
                        title: "操作",
                        key: "action",
                        align: "right" as const,
                        render: (_: unknown, node: Node) => <div className="probe-actions">
                          <IconAction label="诊断" icon={<Stethoscope size={16} />} onClick={() => void diagnose(node.id)} />
                          <IconAction label="详情" icon={<ChevronRight size={17} />} onClick={() => showDetails(node.id)} />
                        </div>,
                      },
                    ] : []),
                  ]}
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
            <div className="probe-detail-resources"><ResourceUsage node={active} /></div>
            <dl>
              <dt>地区</dt>
              <dd className="node-name"><NodeFlag node={active} />{active.region || nodeRegion(active) || "—"}</dd>
            </dl>
            <dl>
              <dt>最近上报</dt>
              <dd>{date(Date.parse(active.lastSeen) / 1000)}</dd>
            </dl>
            <dl>
              <dt>出口 IP</dt>
              <dd className="mono">
                {([active.ipv4, active.ipv6].filter(Boolean).join(" / ") || active.address || "—")}
              </dd>
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
        {lookingGlass && active?.online && active.acceptPing && <div className="probe-history">
          <h3>Looking Glass</h3>
          <Space.Compact block>
            <Input aria-label="Ping 目标" placeholder="域名或 IP" value={pingHost} onChange={(event) => setPingHost(event.target.value)} onPressEnter={() => !pingPending && void ping(active.id)} />
            <Button disabled={!pingHost.trim()} loading={pingPending} onClick={() => void ping(active.id)}>Ping</Button>
          </Space.Compact>
          {pingResult?.id === active.id && <Alert className="alert-gap" type={pingResult.ok ? "success" : "warning"} message={pingResult.text} />}
        </div>}
        {user.admin&&active?.online&&<div className="probe-history">
          <h3>转发链路诊断</h3>
          <Space.Compact block>
            <InputNumber aria-label="规则 ID" min={1} value={ruleID} onChange={setRuleID} placeholder="规则 ID"/>
            <Button onClick={()=>void testTarget(active.id)} disabled={!ruleID} loading={probePending}>测试 TCP 链路</Button>
          </Space.Compact>
          {probeResult&&<Alert style={{marginTop:12}} type={probeResult.connected?"success":"warning"} message={probeResult.connected?(probeResult.backup?"备用链路已接通":"链路已接通")+" · "+probeResult.latencyMs+" ms":"目标连接失败"}/>}
        </div>}
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
    </section>
  );
}
