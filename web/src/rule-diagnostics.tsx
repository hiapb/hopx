import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Alert, Button, Modal, Pagination, Segmented, Spin, Tag } from "antd";
import { Activity, ChevronLeft, ChevronRight, Clock3, Crosshair, GitBranch, RadioTower, RefreshCw, Route, Server } from "lucide-react";
import { api } from "./api";
import type { Group, Rule } from "./api";
import DismissibleTooltip from "./dismissible-tooltip";
import { NodeFlag, nodeDisplayName } from "./node-location";
import { relayModeLabel } from "./relay-protocols";
import TrafficRatio from "./traffic-ratio";

type Step = { groupId?: number; transport?: string; status: string; phase?: string; latencyMs: number };
type Trace = { steps: Step[]; target?: string };
type Link = { network: string; lane: string; measuresTarget: boolean; traces: Trace[] | null };
type LegacyRoute = { status: string; latencyMs: number; trace?: { reached: number; hops: number } };
type Entry = { number: number; id?: number; name: string; region?: string; countryCode?: string; online: boolean; status: string; applyError?: string; links?: Link[]; primary?: LegacyRoute; backup?: LegacyRoute;
  recentRoutes?: { network: string; at: number; backup: boolean }[] };
type Diagnostic = {
  entry: string;
  nodes: Entry[];
  page: number;
  pageSize: number;
  total: number;
  enabled: boolean;
  compiled: boolean;
  primaryPath: number[] | null;
  backupPath: number[] | null;
};

type Stats = { attempts: number; failed: number; totalMs: number };
type Point = Stats & { at: number; samples?: number };
type Segment = Stats & { index: number; groupId: number; transport: string; target: boolean; points: Point[] };
type Lane = Stats & { network: string; lane: string; points: Point[]; segments: Segment[] | null };
type History = { lanes: Lane[]; latest: number; start: number; end: number; interval: number; sampledBuckets: number; completeBuckets: number };
type TimeRange = "live" | "1d" | "3d" | "7d";

const ranges: { label: string; value: TimeRange }[] = [{ label: "实时", value: "live" }, { label: "最近 1 天", value: "1d" },
  { label: "最近 3 天", value: "3d" }, { label: "最近 7 天", value: "7d" }];

const states: Record<string, [string, string]> = {
  paused: ["已暂停", "default"],
  offline: ["入口离线", "default"],
  revoked: ["需要重新接入", "warning"],
  failed: ["配置应用失败", "error"],
  syncing: ["等待同步", "processing"],
  inactive: ["规则未下发", "warning"],
  upgrade: ["节点需要更新", "warning"],
  busy: ["节点繁忙", "warning"],
  timeout: ["诊断超时", "error"],
  running: ["规则已加载", "success"],
  connected: ["目标可达", "success"],
  unreachable: ["连接失败", "error"],
  unavailable: ["暂无可用路径", "warning"],
};

const phaseLabels: Record<string, string> = {
  handshake: "传输握手", relay_connect: "连接中继", tcp_connect: "TCPing", target_connect: "打开目标连接", udp_echo: "UDP Echo", target_policy: "目标地址受限",
};

const laneKey = (link: { network: string; lane: string }) => link.network + "-" + link.lane;
const laneLabel = (link: { network: string; lane: string }) => link.network.toUpperCase() + (link.lane === "backup" ? " · 备用" : " · 主链路");
const segmentKey = (step: Segment) => [step.index, step.groupId, step.transport, step.target].join("-");
const clock = new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit" });
const calendar = new Intl.DateTimeFormat("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
const timestamp = (at: number) => calendar.format(at * 1000);
const loss = (stats: Stats) => stats.attempts ? (stats.failed / stats.attempts * 100).toFixed(1).replace(/\.0$/, "") + "%" : "—";
const average = (stats: Stats) => stats.attempts > stats.failed ? Math.round(stats.totalMs / (stats.attempts - stats.failed)) + " ms" : "—";
function noMeasurement(point: Point, start: number, end: number, resolution: number) {
  if (point.samples) return "已采样，无测量结果";
  if (point.at < start) return "时段未完整覆盖";
  if (point.at + resolution > end) return "当前时段待采样";
  return "未采样";
}
const transportLabel = (transport?: string) => transport === "dtls" ? "DTLS" : transport === "reverse" ? "反向 TLS" : transport ? relayModeLabel(transport) : "";
const entryDisplayName = (node: Entry) => nodeDisplayName(node, `入口 ${node.number}`);

function Status({ status }: { status: string }) {
  const [label, color] = states[status] ?? ["等待探测", "default"];
  return <Tag color={color} className="diagnostic-tag">{label}</Tag>;
}

function HistoryChart({ points, range, label, start, end, interval }: {
  points: Point[];
  range: TimeRange;
  label: string;
  start: number;
  end: number;
  interval: number;
}) {
  const [selection, setSelection] = useState<number>();
  const selectedIndex = points.findIndex(item => item.at === selection);
  const lastSample = points.map(item => (item.samples ?? item.attempts) > 0).lastIndexOf(true);
  const index = selectedIndex >= 0 ? selectedIndex : lastSample >= 0 ? lastSample : points.length - 1;
  const point = points[index];
  const maxLatency = Math.max(1, ...points.map(p => p.totalMs / Math.max(1, p.attempts - p.failed)));
  const axis = range === "live" ? clock : calendar;
  const resolution = points.length > 1 ? points[1].at - points[0].at : interval;
  const measurementLabel = (item: Point) => noMeasurement(item, start, end, resolution);
  return (
    <div className="diagnostic-chart" aria-label={label + "时间线"}>
      <div className="diagnostic-chart-head">
        <strong>{label}</strong>
        <div className="diagnostic-point-controls">
          <Button type="text" size="small" icon={<ChevronLeft size={15} />} aria-label="上一时段" disabled={index === 0}
            onClick={() => setSelection(points[index - 1].at)} />
          <span aria-live="polite">{timestamp(point.at)} · {point.attempts ? `${point.attempts} 次 · 丢包 ${loss(point)} · ${average(point)}` : measurementLabel(point)}</span>
          <Button type="text" size="small" icon={<ChevronRight size={15} />} aria-label="下一时段" disabled={index === points.length - 1}
            onClick={() => setSelection(points[index + 1].at)} />
        </div>
      </div>
      <div className="diagnostic-bars">
        {points.map(item => {
          const latency = item.totalMs / Math.max(1, item.attempts - item.failed);
          const color = !item.attempts ? "empty" : item.failed === item.attempts ? "down" : item.failed > 0 ? "degraded" : "up";
          return (
            <DismissibleTooltip key={item.at} title={timestamp(item.at) + (item.attempts ? " · 丢包 " + loss(item) + " · " + average(item) : " · " + measurementLabel(item))}>
              <button type="button" className="diagnostic-bar" data-state={color} aria-pressed={item.at === point?.at}
                aria-label={timestamp(item.at) + (item.attempts ? " 丢包 " + loss(item) : " " + measurementLabel(item))}
                onClick={() => setSelection(item.at)}>
                <span style={{ height: (color === "empty" ? 13 : Math.max(25, latency / maxLatency * 92)) + "%" }} />
              </button>
            </DismissibleTooltip>
          );
        })}
      </div>
      <div className="diagnostic-axis">
        <span>{axis.format(points[0].at * 1000)}</span>
        <span>{axis.format(points[Math.floor(points.length / 2)].at * 1000)}</span>
        <span>{axis.format(points[points.length - 1].at * 1000)}</span>
      </div>
      <div className="diagnostic-legend" aria-label="时间线图例">
        <span data-state="up">正常</span><span data-state="degraded">部分失败</span>
        <span data-state="down">失败</span><span data-state="empty">无样本</span>
      </div>
    </div>
  );
}

export default function RuleDiagnostics({ rule, entryGroup, describePath, renderPath, onClose }: {
  rule: Rule;
  entryGroup?: Group;
  describePath: (path: number[] | null) => string;
  renderPath: (path: number[] | null) => ReactNode;
  onClose: () => void;
}) {
  const [snapshot, setSnapshot] = useState<{ page: number; revision: number; data: Diagnostic }>();
  const [probed, setProbed] = useState<{ number: number; revision: number; data: Diagnostic; at: number }>();
  const [historyResponse, setHistoryResponse] = useState<{ ruleId: number; range: TimeRange; data: History }>();
  const [range, setRange] = useState<TimeRange>("live");
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [probeBusy, setProbeBusy] = useState(false);
  const [historyBusy, setHistoryBusy] = useState(true);
  const [liveError, setLiveError] = useState("");
  const [historyError, setHistoryError] = useState("");
  const [selectedEntry, setSelectedEntry] = useState<number>();
  const [selectedLane, setSelectedLane] = useState<string>();
  const [selectedSegment, setSelectedSegment] = useState<string>();
  const [attempt, setAttempt] = useState(0);
  const history = historyResponse?.ruleId === rule.id && historyResponse.range === range ? historyResponse.data : undefined;
  const status = snapshot?.page === page ? snapshot.data : undefined;
  const selected = status?.nodes.find(node => node.number === selectedEntry) ??
    status?.nodes.find(node => node.status === "running") ?? status?.nodes[0];
  const selectedNumber = selected?.number;
  const currentProbe = probed && probed.number === selectedNumber && probed.data.page === status?.page ? probed : undefined;
  const result = currentProbe?.revision === snapshot?.revision ? currentProbe?.data ?? status : status;
  const entry = result?.nodes.find(node => node.number === selectedNumber);
  const checkedAt = currentProbe?.at ?? 0;
  const statusBusy = (snapshot?.page !== page || snapshot.revision !== revision) && !liveError;
  const liveRange = range === "live";
  const busy = liveRange && (statusBusy || probeBusy);

  useEffect(() => {
    const request = new AbortController();
    setLiveError("");
    api<Diagnostic>(`/rules/${rule.id}/diagnose?status=1&page=${page}`, "POST", undefined, request.signal)
      .then(data => {
        if (!request.signal.aborted) setSnapshot({ page, revision, data });
      })
      .catch((error: Error) => { if (!request.signal.aborted) setLiveError(error.message); });
    return () => request.abort();
  }, [rule.id, page, revision]);

  useEffect(() => {
    if (!liveRange || !selectedNumber || selected?.status !== "running" || snapshot?.revision !== revision) {
      setProbeBusy(false);
      return;
    }
    const request = new AbortController();
    setProbeBusy(true);
    setLiveError("");
    api<Diagnostic>(`/rules/${rule.id}/diagnose?detail=1&page=${page}&node=${selectedNumber}`, "POST", undefined, request.signal)
      .then(data => {
        if (!request.signal.aborted) setProbed({ number: selectedNumber, revision, data, at: Math.floor(Date.now() / 1000) });
      })
      .catch((error: Error) => { if (!request.signal.aborted) setLiveError(error.message); })
      .finally(() => { if (!request.signal.aborted) setProbeBusy(false); });
    return () => request.abort();
  }, [rule.id, page, revision, snapshot, selectedNumber, selected?.status, liveRange]);

  useEffect(() => {
    const request = new AbortController();
    let timer: number | undefined;
    async function load() {
      try {
        const data = await api<History>(`/rules/${rule.id}/diagnose/history?range=${range}`, "GET", undefined, request.signal);
        if (request.signal.aborted) return;
        setHistoryResponse({ ruleId: rule.id, range, data });
        setHistoryError("");
      } catch (error) {
        if (!request.signal.aborted) setHistoryError((error as Error).message);
      } finally {
        if (!request.signal.aborted) {
          setHistoryBusy(false);
          if (range === "live") timer = window.setTimeout(load, 30_000);
        }
      }
    }
    setHistoryBusy(true);
    setHistoryError("");
    void load();
    return () => {
      request.abort();
      window.clearTimeout(timer);
    };
  }, [rule.id, range, liveRange ? checkedAt : 0]);

  const lanes = new Map<string, { network: string; lane: string }>();
  for (const link of [...(entry?.links ?? []), ...(history?.lanes ?? [])]) lanes.set(laneKey(link), link);
  const activeLane = selectedLane && lanes.has(selectedLane) ? selectedLane : lanes.keys().next().value;
  const live = entry?.links?.find(link => laneKey(link) === activeLane);
  const summary = history?.lanes.find(link => laneKey(link) === activeLane);
  const segment = summary?.segments?.find(item => segmentKey(item) === selectedSegment);
  const traces = live?.traces ?? [];
  const trace = traces[attempt] ?? traces[0];
  const stats = segment ?? summary;
  const points = segment?.points ?? summary?.points;
  const network = rule.effectiveNetwork || rule.protocol;
  const entryName = result?.entry || entryGroup?.name;
  const header = [rule.tlsSharedPort || rule.port, network === "both" ? "TCP + UDP" : network.toUpperCase()].filter(Boolean).join(" · ");
  const nameFor = (step: { groupId?: number }, index: number, target: boolean) => target ? "目标地址" : step.groupId ? describePath([step.groupId]) : "第 " + (index + 1) + " 跳";
  const backup = activeLane?.endsWith("-backup");
  const currentPath = backup ? result?.backupPath : result?.primaryPath;
  const configuredPath = backup ? rule.backupPath : rule.path;
  const path = activeLane === "tcp-primary" && rule.protocol.startsWith("haproxy-")
    ? "HAProxy 直连" : renderPath(configuredPath?.length ? configuredPath : currentPath ?? null);
  const lastStep = trace?.steps.at(-1);
  const checkedRoute = activeLane?.endsWith("-backup") ? entry?.backup : entry?.primary;
  const failedStep = trace?.steps.some(step => step.status === "failed");
  const routeStatus = !trace ? states[checkedRoute?.status ?? entry?.status ?? ""]?.[0] :
    failedStep ? "链路未接通" : lastStep?.status === "unknown" ? "目标未测量" : lastStep?.status === "ok" ? "链路已接通" : "暂无探测结果";

  return (
    <Modal open title={<span className="diagnostic-title"><span className="dialog-title-icon"><Activity size={19} aria-hidden="true" /></span>规则诊断</span>} width={840}
      className="rule-diagnostics" onCancel={onClose}
      footer={<Button onClick={onClose}>关闭</Button>}>
      <div className="diagnostic-heading">
        <div><h2>{rule.name}</h2><p className="rule-group-label">
          {entryName && <span className="rule-group-label">{entryName}<TrafficRatio ratio={entryGroup?.ratio} /></span>}
          <span>{header}</span>
        </p></div>
        <Button type="primary" icon={<RefreshCw size={15} />} loading={busy} onClick={() => {
          setRange("live");
          setAttempt(0);
          setRevision(value => value + 1);
        }}><span aria-live="polite">{busy ? "探测中" : "立即探测"}</span></Button>
      </div>

      <div className="diagnostic-toolbar">
        <Segmented<TimeRange> aria-label="诊断时间范围" options={ranges} value={range} onChange={setRange} />
        <div className="diagnostic-sampling">
          {history?.interval && <span><Clock3 size={14} aria-hidden="true" />目标间隔 {history.interval / 60} 分钟</span>}
          {history?.latest ? <span>上次收到样本 {timestamp(history.latest)}</span> : null}
        </div>
      </div>

      {liveError && range === "live" && <Alert type="error" showIcon message={liveError} />}
      {historyError && <Alert type="warning" showIcon message={historyError} />}

      {range === "live" && (
        <section className="diagnostic-section diagnostic-live" aria-label="实时链路">
          <div className="diagnostic-section-head">
            <h3><RadioTower size={17} />入口与链路</h3>
            {busy ? <span className="diagnostic-progress" role="status"><Spin size="small" />{statusBusy ? "读取入口状态" : "等待节点回报"}</span>
              : checkedAt > 0 && <time className="muted" dateTime={new Date(checkedAt * 1000).toISOString()}>最近探测 {clock.format(checkedAt * 1000)}</time>}
          </div>
          {!!result?.nodes.length && <div className="diagnostic-entry-list" role="group" aria-label="入口设备">
            {result.nodes.map(node => {
              const identity = <><span className="diagnostic-node-name"><NodeFlag node={node} />{entryDisplayName(node)}</span><Status status={node.status} /></>;
              return result.nodes.length === 1 ? <div key={node.number} className="diagnostic-entry-choice">{identity}</div> :
                <button key={node.number} type="button" className="diagnostic-entry-choice"
                  aria-pressed={entry?.number === node.number} onClick={() => {
                    setSelectedEntry(node.number);
                    setAttempt(0);
                  }}>
                  {identity}<ChevronRight size={14} aria-hidden="true" />
                </button>;
            })}
          </div>}
          {result && result.total > result.pageSize && <div className="diagnostic-entry">
            <Pagination simple size="small" current={result.page} pageSize={result.pageSize}
              total={result.total} onChange={value => { setPage(value); setSelectedEntry(undefined); setAttempt(0); }} disabled={busy} />
          </div>}
          {entry && <dl className="diagnostic-link-summary">
            <div><dt>节点心跳</dt><dd><span className={entry.online ? "diagnostic-dot online" : "diagnostic-dot"} />{entry.online ? "在线" : "离线"}</dd></div>
            {busy || trace || checkedRoute ? <div><dt>{live?.lane === "backup" ? "备用链路" : "链路探测"}</dt><dd>{busy ? "探测中" : routeStatus}</dd></div> : null}
          </dl>}
          {!!result?.backupPath?.length && entry?.status === "running" && <div className="diagnostic-recent-routes">
            <span>最近实际转发</span>
            {entry.recentRoutes?.length ? entry.recentRoutes.map(route => <Tag key={route.network}>
              {route.network.toUpperCase()} · {route.backup ? "备用链路" : "主链路"} · {timestamp(route.at)}
            </Tag>) : <span className="muted">暂无连接记录</span>}
          </div>}
          {entry?.applyError && <Alert type="error" showIcon message={entry.applyError} />}
          {result && !entry && <p className="diagnostic-empty">入口组尚未接入设备</p>}
          {entry?.status === "running" && !busy && !entry.links?.length && <p className="diagnostic-empty">
            {entry.primary ? <><Status status={entry.primary.status} />{entry.primary.latencyMs} ms · 入口节点更新后可查看逐跳结果</>
              : !rule.enabled ? "启用规则后可探测链路。" : rule.tlsShared ? "共享 TLS 的目标链路在各 SNI 子规则中查看。" : "等待入口发回逐跳探测结果。"}
          </p>}
        </section>
      )}

      <div className="diagnostic-lanes">
        {Array.from(lanes, ([key, lane]) => (
          <Button key={key} type={key === activeLane ? "primary" : "default"} size="small" aria-pressed={key === activeLane}
            onClick={() => { setSelectedLane(key); setSelectedSegment(undefined); setAttempt(0); }}>{laneLabel(lane)}</Button>
        ))}
      </div>

      {range === "live" && live && (
        <section className="diagnostic-section" aria-label="逐跳探测">
          <div className="diagnostic-section-head">
            <h3><Route size={17} />逐跳探测</h3><span className="muted">{path}</span>
          </div>
          {traces.length > 1 && <div className="diagnostic-attempts">
            {traces.map((sample, index) => (
              <Button key={index} size="small" type={(traces[attempt] ?? traces[0]) === sample ? "primary" : "text"}
                onClick={() => setAttempt(index)}>第 {index + 1} 次</Button>
            ))}
          </div>}
          {trace && entry ? <ol className="diagnostic-steps">
            <li data-state="ok">
              <span className="diagnostic-step-icon"><Server size={16} /></span>
              <div><strong className="diagnostic-node-name"><NodeFlag node={entry} />{entryDisplayName(entry)}</strong><small>探测起点</small></div>
            </li>
            {trace.steps.map((step, index) => {
              const target = index === trace.steps.length - 1;
              return <li key={index} data-state={step.status}>
                <span className="diagnostic-step-icon">{target ? <Crosshair size={16} /> : <GitBranch size={16} />}</span>
                <div><strong>{target && trace.target ? trace.target : nameFor(step, index, target)}</strong>
                  <small>{[transportLabel(step.transport), phaseLabels[step.phase ?? ""]].filter(Boolean).join(" · ") ||
                    (step.status === "unknown" ? "未启用 UDP Echo" : "等待上游链路")}</small></div>
                <span className="diagnostic-step-result">
                  {step.status === "ok" ? step.latencyMs + " ms" : step.status === "failed" ? "失败" : step.status === "unknown" ? "无目标样本" : "未到达"}
                </span>
              </li>;
            })}
          </ol> : <p className="diagnostic-empty">当前没有可探测的出站路径。</p>}
        </section>
      )}

      <section className="diagnostic-section diagnostic-history" aria-label="历史时间线">
        <div className="diagnostic-section-head">
          <h3><Activity size={17} />{range === "live" ? "最近 1 小时" : "历史时间线"}</h3>
          {historyBusy ? <Spin size="small" /> : !!history?.completeBuckets &&
            <span className="muted">采样覆盖 {history.sampledBuckets} / {history.completeBuckets} 个完整时段</span>}
        </div>
        {history && summary && stats && points?.length ? <>
          <div className="diagnostic-metrics">
            <div><span>探测丢包率</span><strong>{loss(stats)}</strong></div>
            <div><span>{segment ? "历史单跳均值" : "历史全链路均值"}</span><strong>{average(stats)}</strong></div>
            <div><span>失败 / 探测</span><strong>{stats.failed} / {stats.attempts}</strong></div>
          </div>
          <HistoryChart key={range + activeLane + selectedSegment} points={points} range={range}
            start={history.start} end={history.end} interval={history.interval}
            label={segment ? nameFor(segment, segment.index, segment.target) : "端到端"} />
          {!!summary.segments?.length && <div className="diagnostic-segments">
            <button type="button" className="diagnostic-segment" aria-pressed={!segment} onClick={() => setSelectedSegment(undefined)}>
              <span>端到端</span><strong>{loss(summary)}</strong><span>{average(summary)}</span><ChevronRight size={14} />
            </button>
            {summary.segments.map(item => (
              <button type="button" key={segmentKey(item)} className="diagnostic-segment" aria-pressed={segment === item}
                onClick={() => setSelectedSegment(segmentKey(item))}>
                <span>{nameFor(item, item.index, item.target)}<small>{transportLabel(item.transport)}</small></span>
                <strong>{loss(item)}</strong><span>{average(item)}</span><ChevronRight size={14} />
              </button>
            ))}
          </div>}
        </> : !historyError && <p className="diagnostic-empty">{historyBusy ? "正在读取样本" : "这个时间范围暂无探测样本。"}</p>}
        <p className="diagnostic-caption">样本保留 7 天。丢包率按有测量结果的探测统计。</p>
      </section>
    </Modal>
  );
}
