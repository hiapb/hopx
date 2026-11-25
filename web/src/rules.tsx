import { useEffect, useMemo, useRef, useState } from "react";
import type { Key } from "react";
import {
  Alert,
  App,
  Button,
  Checkbox,
  Descriptions,
  Drawer,
  Dropdown,
  Form,
  Grid,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tabs,
} from "antd";
import {
  Copy,
  Download,
  Pencil,
  Activity,
  Plus,
  Network,
  Search,
  Upload,
  Code2,
  Ellipsis,
  Pause,
  Play,
  Trash2,
  ArrowRightLeft,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { api, bytes, date, hasPlan, planExpiryLabel, ruleLimitLabel, useData } from "./api";
import type { DataReload, Group, Rule, User } from "./api";
import RefreshButton from "./refresh-button";
import { useConfirmAction } from "./confirm-action";
import IconAction from "./icon-action";
import MultiSelect from "./multi-select";
import { relayModeLabel } from "./relay-protocols";
import JsonEditor from "./json-editor";
import RuleDiagnostics from "./rule-diagnostics";
import { batchConfigs, clipboardConfigs, clipboardNeedsGroups, legacyRule, nyanpassExport, portChanges, ruleExport } from "./rule-transfer";

const defaults: Partial<Rule> = {
  enabled: true,
  protocol: "inherit",
  strategy: "round-robin",
  path: [],
  backupPath: [],
  maxIPs: 0,
  maxConns: 0,
  rateMbps: 0,
};
type InputRule = Omit<Rule, "targets" | "path" | "backupPath" | "tlsAllowedUsers"> & {
  targets: string;
  path: number[];
  backupPath: number[];
  tlsAllowedUsers?: string[];
};
type BatchInput = { entry?: number; path?: number[]; targets: string; options?: string };
type RuleFilters = { name?: string; entry?: number; exit?: number; port?: number; target?: string };
const runtimeLabels: Record<string, { label: string; color: string }> = {
  paused: { label: "已暂停", color: "default" },
  offline: { label: "入口离线", color: "default" },
  syncing: { label: "等待同步", color: "processing" },
  failed: { label: "入口应用失败", color: "error" },
  proxy_unavailable: { label: "等待节点升级", color: "processing" },
  inactive: { label: "未下发", color: "warning" },
  route_repair: { label: "待重新选线", color: "warning" },
  subscription_blocked: { label: "转发已停用", color: "warning" },
  waiting_exit: { label: "出口不可用", color: "warning" },
  partial: { label: "部分入口已生效", color: "warning" },
  running: { label: "已生效", color: "success" },
};

function RuleStatus({ rule }: { rule: Rule }) {
  const status = runtimeLabels[rule.runtime || (rule.enabled ? "syncing" : "paused")];
  const title = rule.routeRepair ? "设备组权限已变更，请重新选择线路" :
    rule.serviceBlock || (rule.reportedAt ? "最近心跳 " + date(rule.reportedAt) : undefined);
  return <Tag className="rule-status" color={status?.color} title={title}>{status?.label || "等待同步"}</Tag>;
}

export default function Rules({ user, initialQuery, refreshUser, siteProbeInterval, showShop }: {
  user: User;
  initialQuery?: string;
  refreshUser: DataReload;
  siteProbeInterval: number;
  showShop: boolean;
}) {
  const screens = Grid.useBreakpoint();
  const narrow = screens.md === false;
  const wide = !!screens.xl;
  const params = new URLSearchParams(initialQuery);
  const ruleID = Number(params.get("id") || params.get("goto")) || undefined;
  const adminSearch = user.admin && params.has("search");
  const ruleTableWidth = (narrow ? 916 : wide ? 1120 : 1060) + (adminSearch ? 130 : 0);
  const [showSearch, setShowSearch] = useState(adminSearch);
  const [detailFilters, setDetailFilters] = useState<RuleFilters>({});
  const [searchForm] = Form.useForm();
  const [search, setSearch] = useState("");
  const [label, setLabel] = useState<string>();
  const [folderEditor, setFolderEditor] = useState<"move" | "rename" | "create">();
  const [folderForm] = Form.useForm<{ from?: string; name?: string }>();
  const [owner, setOwner] = useState<number | null>(() => {
    const params = new URLSearchParams(initialQuery);
    const id = Number(params.get("owner") || params.get("affect"));
    return user.admin && id > 0 ? id : null;
  });
  const [statistics, setStatistics] = useState<{total: number; enabled: number; inbound: number; outbound: number; today: number; yesterday: number}>();
  const [diagnosticRule, setDiagnosticRule] = useState<Rule>();
  const [rerouting, setRerouting] = useState(false);
  const [routeForm] = Form.useForm<{entry?: number; path?: number[]; updatePath?: boolean}>();
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const [pageSize, setPageSize] = useState(20);
  const [offset, setOffset] = useState(0);
  const [before, setBefore] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const [selected, setSelected] = useState<Key[]>([]);
  const [editing, setEditing] = useState<Partial<Rule> | null>(null);
  const saveRequest = useRef<AbortController | null>(null);
  const [saveError, setSaveError] = useState("");
  useEffect(() => () => saveRequest.current?.abort(), []);
  const [detailID, setDetailID] = useState<number>();
  const [addressRule, setAddressRule] = useState<Rule>();
  const [jsonRule, setJsonRule] = useState<Rule>();
  const [importing, setImporting] = useState<"create" | "update">();
  const [importForm] = Form.useForm<BatchInput>();
  const [bulkAdd, setBulkAdd] = useState(false);
  const [bulkForm] = Form.useForm<BatchInput>();
  const [bulkAdvanced, setBulkAdvanced] = useState(false);
  const [copiedRules, setCopiedRules] = useState("");
  const [exporting, setExporting] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [proxyRule, setProxyRule] = useState<Rule | null>(null);
  const [proxyConfig, setProxyConfig] = useState("");
  const [proxyBusy, setProxyBusy] = useState(false);
  const [proxyForm] = Form.useForm<{ bind: string; backends: string }>();
  const [form] = Form.useForm<InputRule>();
  const ruleEntry = Form.useWatch("entry", form);
  const rulePath = Form.useWatch("path", form);
  const forwardMode = Form.useWatch("protocol", form);
  const pureHAProxy = forwardMode === "haproxy-tcp";
  const mixedHAProxy = forwardMode === "haproxy-both";
  const usesHAProxy = pureHAProxy || mixedHAProxy;
  const backupPath = Form.useWatch("backupPath", form);
  const bulkEntry = Form.useWatch("entry", bulkForm);
  const importEntry = Form.useWatch("entry", importForm);
  const importTargets = Form.useWatch("targets", importForm) || "";
  const legacyInput = clipboardNeedsGroups(importTargets);
  const sharedTLS = Form.useWatch("tlsShared", form);
  const sharedPort = Form.useWatch("tlsSharedPort", form);
  const generateTLS = Form.useWatch("tlsGenerateFor", form);
  const { message } = App.useApp();
  const confirmAction = useConfirmAction();
  const filters = new URLSearchParams({ q: search.trim(), state: status, sort });
  if (label === "") filters.set("ungrouped", "1");
  else if (label) filters.set("label", label);
  if (owner) filters.set("owner", String(owner));
  if (ruleID) filters.set("id", String(ruleID));
  for (const [key, value] of Object.entries(detailFilters)) {
    if (value !== undefined && value !== null && value !== "") filters.set(key, String(value));
  }
  const list = useData<Rule[]>(
    "/rules?limit=" + pageSize + "&" + filters + (adminSearch ? "&owners=1" : "") + (sort ? "&direction=" + direction + "&offset=" + offset : "&before=" + before),
    [],
  );
  const countFilters = new URLSearchParams(filters);
  countFilters.delete("sort");
  const hasFilter = Boolean(ruleID || owner || label !== undefined || search.trim() || status ||
    Object.values(detailFilters).some(value => value !== undefined && value !== null && value !== ""));
  const firstRule = !list.value.length && !list.busy && !list.error && !hasFilter && !adminSearch && !before && offset === 0;
  const allRules = useData<{ total: number }>(owner || adminSearch ? null : "/rules/count", { total: 0 });
  const showFilteredTotal = hasFilter || adminSearch;
  const filteredRules = useData<{ total: number; owner?: number; serviceBlock?: string }>(showFilteredTotal ? "/rules/count?" + countFilters : null, { total: 0 });
  const ownRules = !owner || owner === user.id;
  const creationBlock = ownRules ? user.serviceBlock
    : filteredRules.value.owner === owner ? filteredRules.value.serviceBlock : undefined;
  const subscribed = hasPlan(user);
  const totals = showFilteredTotal ? filteredRules : allRules;
  const foldersPath = "/rules/folders" + (owner ? "?owner=" + owner : "");
  const folders = useData<{ name: string; count: number }[]>(foldersPath, []);
  const groups = useData<Group[]>("/groups?online=1" + (owner ? "&owner=" + owner : ""), []);
  const names = useMemo(
    () => new Map(groups.value.map((g) => [g.id, g.name])),
    [groups.value],
  );
  const toOption = (group: Group) => ({
    value: group.id,
    label: group.name,
    description: [
      group.kind === "chain" ? "链式出口" : group.owner ? "自有出口" : "",
      ["relay", "exit", "both"].includes(group.kind) ? "GOST · " + relayModeLabel(group.relayMode) : "",
      group.onlineDevices === 0 ? "无在线节点" : "",
    ].filter(Boolean).join(" · "),
  });
  const renderGroupOption = ({ data }: { data: ReturnType<typeof toOption> }) => (
    <div className="route-option">
      <span>{data.label}</span>
      {data.description && <small>{data.description}</small>}
    </div>
  );
  const entries = groups.value
    .filter((g) => g.kind === "entry" || g.kind === "both")
    .map(toOption);
  const hops = groups.value
    .filter((g) => g.kind !== "entry" && g.kind !== "monitor")
    .map(toOption);
  const chosenEntry = groups.value.find(group => group.id === ruleEntry);
  const chosenBulkEntry = groups.value.find(group => group.id === bulkEntry);
  const chosenImportEntry = groups.value.find(group => group.id === importEntry);
  const ingress = chosenEntry?.ingress;
  const restrictions = [
    { key: "allow", label: "允许域名", value: ingress?.allowedHosts },
    { key: "host", label: "屏蔽域名", value: ingress?.blockedHosts },
    { key: "path", label: "屏蔽路径", value: ingress?.blockedPaths },
    { key: "type", label: "屏蔽协议", value: ingress?.blockedTypes },
    { key: "udp", label: "UDP", value: ingress?.disableUDP ? ["禁用"] : [] },
    { key: "sni", label: "TLS", value: ingress?.rejectEmptySNI ? ["拒绝空 SNI"] : [] },
  ].filter(item => item.value?.length);
  const selectedHops = (rulePath || []).flatMap(id => {
    const group = groups.value.find(group => group.id === id);
    return group?.kind === "chain" && group.chain?.length ? group.chain : [id];
  }).map(id => groups.value.find(group => group.id === id));
  const requiresExit = (group?: Group) => group?.routing?.ingressMode === "relay" || group?.routing?.ingressMode === "personal";
  const directEntry = chosenEntry?.routing?.ingressMode === "direct" || pureHAProxy;
  const confirmWithoutPrimary = editing?.routeRepair?.path && !sharedTLS && !requiresExit(chosenEntry) && (directEntry || !rulePath?.length);
  const confirmWithoutBackup = editing?.routeRepair?.backupPath && (directEntry || !backupPath?.length);
  function exitOptions(entry: Group | undefined, selected: number[] = []) {
    const previous = groups.value.find(group => group.id === selected.at(-1)) || entry;
    return hops.filter(({value}) => {
      if (selected.includes(value)) return true;
      if (value === entry?.id || previous?.kind === "chain") return false;
      const next = groups.value.find(group => group.id === value);
      if (!next || (next.kind === "chain" && selected.length > 0)) return false;
      if (entry?.routing?.ingressMode === "personal") return selected.length === 0 && next.owner === (owner ?? user.id);
      if (next.owner && previous?.ingress?.blockPersonal) return false;
      if (next.allowedFrom?.length && previous && !next.allowedFrom.includes(previous.id)) return false;
      if (previous?.allowedTo?.length && !previous.allowedTo.includes(value) &&
          !(next.owner && previous.ingress?.siteOutboundOnly)) return false;
      return true;
    });
  }
  const describePath = (path: number[] | null, missing = false) =>
    missing ? "未选择" : path?.map((id) => names.get(id) || "#" + id).join(" → ") || "直出";
  const connectionAddresses = (rule: Rule) => {
    if (!rule.entry) return [];
    const raw = groups.value.find(group => group.id === rule.entry)?.connectHost || "";
    const port = String(rule.tlsSharedPort || rule.port);
    const hosts = raw.split("\n").map(host => host.trim()).filter(Boolean);
    if (!hosts.length) return [":" + port];
    return hosts.map(host => {
      const ipv6 = host.split(":").length > 2 && !host.startsWith("[") && !host.includes(" ");
      return (ipv6 ? "[" + host + "]" : host) + ":" + port;
    });
  };
  const protocolLabel = (rule: Rule) => rule.tlsShared || rule.tlsSharedPort
      ? "共享 TLS"
      : rule.protocol === "haproxy-tcp" ? "HAProxy TCP"
        : rule.protocol === "haproxy-both" ? "HAProxy TCP + UDP"
        : (rule.effectiveNetwork || rule.protocol).replace("both", "TCP + UDP").toUpperCase();
  const detail = list.value.find((rule) => rule.id === detailID);

  function resetPage() {
    setBefore("");
    setCursors([]);
    setOffset(0);
    setSelected([]);
  }

  function sortRules(key: string, order: "asc" | "desc" = key === "traffic" ? "desc" : "asc") {
    setSort(key);
    setDirection(order);
    resetPage();
  }

  function sortable(key: string) {
    return { key, sorter: true, sortOrder: sort !== key ? null : direction === "asc" ? "ascend" as const : "descend" as const };
  }

  const ruleReloads = [list.reload, allRules.reload, filteredRules.reload, folders.reload, refreshUser];

  async function reloadRules() {
    await Promise.all(ruleReloads.map(reload => reload()));
  }

  function deleteRule(rule: Rule) {
    confirmAction({ title: "删除 " + rule.name + "？", okButtonProps: { danger: true }, onOk: () => batch("delete", [rule.id]) });
  }

  function openImport() {
    importForm.resetFields();
    setImporting(creationBlock ? "update" : "create");
  }

  function openReroute() {
    routeForm.resetFields();
    setRerouting(true);
  }

  function edit(rule?: Partial<Rule>) {
    const next = { ...defaults, owner: owner ?? undefined, ...rule };
    setAdvanced(Boolean(next.routeRepair?.backupPath));
    setSaveError("");
    setEditing(next);
    form.resetFields();
    form.setFieldsValue({
      ...next,
      entry: next.entry || undefined,
      port: next.port || undefined,
      confirmRoute: false,
      probeInterval: next.probeInterval ?? 0,
      targets: next.targets?.join("\n") ?? "",
      path: next.path ?? [],
      backupPath: next.backupPath ?? [],
      tlsAllowedUsers: next.tlsAllowedUsers?.map(String),
    });
  }

  function rulePayload(v: InputRule) {
    return {
      ...editing,
      ...v,
      ...(v.protocol === "haproxy-tcp" || chosenEntry?.routing?.ingressMode === "direct" ? { path: [], backupPath: [] } : {}),
      ...(v.tlsGenerateFor ? { tlsCert: "", tlsKey: "", tlsGenerateFor: v.tlsGenerateFor.trim() } : {}),
      tlsSharedPort: v.tlsShared ? 0 : v.tlsSharedPort,
      tlsAllowedUsers: v.tlsShared ? v.tlsAllowedUsers?.map(Number) : undefined,
      targets: v.tlsShared ? [] : (v.targets || "").split("\n").map(x => x.trim()).filter(Boolean),
    };
  }

  async function save(v: InputRule) {
    if (saveRequest.current) return;
    const request = new AbortController();
    saveRequest.current = request;
    setSaveError("");
    setBusy(true);
    try {
      const rule = await api<Rule>(
        "/rules" + (editing?.id ? "/" + editing.id : ""),
        editing?.id ? "PUT" : "POST",
        rulePayload(v),
        request.signal,
      );
      if (request.signal.aborted) return;
      setEditing(null);
      await reloadRules();
      message.success(editing?.id ? "规则已保存" : `规则已添加 · 监听端口 ${rule.tlsSharedPort || rule.port}`);
    } catch (e) {
      if (!request.signal.aborted) setSaveError((e as Error).message);
    } finally {
      saveRequest.current = null;
      setBusy(false);
    }
  }

  async function batch(action: string, ids = selected, label?: string) {
    try {
      await api("/rules/batch", "POST", { action, ids, label });
      setSelected([]);
      await reloadRules();
      return true;
    } catch (e) {
      message.error((e as Error).message);
      return false;
    }
  }

  function editFolder(action: "move" | "rename" | "create") {
    folderForm.setFieldsValue({ from: action === "rename" ? label || undefined : undefined, name: action === "move" ? label || "" : "" });
    setFolderEditor(action);
  }

  async function saveFolder(values: { from?: string; name?: string }) {
    setBusy(true);
    const name = (values.name || "").trim();
    try {
      if (folderEditor === "move") {
        if (!await batch("label", selected, name)) return;
      } else {
        await api(foldersPath, "PUT", { from: folderEditor === "rename" ? values.from : undefined, name });
        await reloadRules();
      }
      if (label !== undefined && (folderEditor === "move" || values.from === label)) setLabel(name);
      resetPage();
      setFolderEditor(undefined);
      message.success("规则分组已保存");
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function switchRoutes(values: { entry?: number; path?: number[]; updatePath?: boolean }) {
    if (!values.entry && !values.updatePath) {
      message.warning("请选择新入口或出口");
      return;
    }
    setBusy(true);
    try {
      await api("/rules/batch", "POST", { action: "reroute", ids: selected, ...values });
      setRerouting(false);
      setSelected([]);
      await reloadRules();
      message.success("已切换所选规则");
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function addRules(values: BatchInput) {
    setBusy(true);
    try {
      const path = chosenBulkEntry?.routing?.ingressMode === "direct" ? [] : values.path || [];
      const rows = batchConfigs(values.targets, values.options || "");
      if (rows.length === 0 || rows.length > 1000) throw new Error("每批须填写 1 至 1000 条规则");
      const rules = rows.map((config, index) => {
        try { return legacyRule(config, chosenBulkEntry, path, owner ?? undefined); }
        catch (error) { throw new Error(`第 ${index + 1} 条规则：${(error as Error).message}`); }
      });
      await api("/rules/batch", "POST", {
        action: "import",
        rules,
      });
      setBulkAdd(false);
      bulkForm.resetFields();
      setBulkAdvanced(false);
      resetPage();
      await reloadRules();
      message.success("已添加 " + rules.length + " 条规则");
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function exportRules(rows: Rule[]) {
    const data = new Blob(
      [JSON.stringify(ruleExport(rows), null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(data);
    const link = document.createElement("a");
    link.href = url;
    link.download = "hopx-rules.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function copyRules(legacy = false) {
    const selectedRows = list.value.filter(row => selected.includes(row.id));
    let rows;
    try {
      rows = legacy ? nyanpassExport(selectedRows, groups.value) : ruleExport(selectedRows);
    } catch (error) {
      message.error((error as Error).message);
      return;
    }
    if (!rows.length) return;
    const content = rows.map(rule => JSON.stringify(rule)).join("\n");
    try {
      await navigator.clipboard.writeText(content);
      message.success(`成功复制 ${rows.length} 条规则`);
    } catch {
      setCopiedRules(content);
    }
  }

  async function generateProxy(values: { bind: string; backends: string }) {
    if (!proxyRule) return;
    setProxyBusy(true);
    try {
      const result = await api<{ config: string }>(
        "/admin/rules/" + proxyRule.id + "/haproxy",
        "POST",
        { bind: values.bind.trim(), backends: values.backends.split(/\s+/).filter(Boolean) },
      );
      setProxyConfig(result.config);
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setProxyBusy(false);
    }
  }

  function downloadProxy() {
    const url = URL.createObjectURL(new Blob([proxyConfig], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "haproxy-" + proxyRule?.id + ".cfg";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function exportFiltered() {
    setExporting(true);
    try {
      const query = new URLSearchParams(filters);
      query.delete("sort");
      query.set("limit", "1000");
      const rows: Rule[] = [];
      for (;;) {
        const page = await api<Rule[]>("/rules?" + query);
        rows.push(...page);
        if (page.length < 1000) break;
        query.set("before", String(page[page.length - 1].id));
      }
      exportRules(rows);
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setExporting(false);
    }
  }
  async function importRules(values: BatchInput) {
    setBusy(true);
    let imported = 0;
    let rules: Partial<Rule>[] = [];
    try {
      if (importing === "update") {
        const changes = portChanges(values.targets, chosenImportEntry);
        const result = await api<{ count: number }>("/rules/batch/by-port", "POST", { entry: values.entry, owner, changes });
        setImporting(undefined);
        importForm.resetFields();
        await reloadRules();
        message.success(`已更新 ${result.count} 条规则`);
        return;
      }
      const path = chosenImportEntry?.routing?.ingressMode === "direct" ? [] : values.path || [];
      rules = clipboardConfigs(values.targets).map((config, index) => {
        try {
          if ("dest" in config || "listen_port" in config) return legacyRule(config, chosenImportEntry, path, owner ?? undefined);
          return { ...config, ...(owner ? { owner } : {}) } as Partial<Rule>;
        } catch (error) {
          throw new Error(`第 ${index + 1} 条规则：${(error as Error).message}`);
        }
      }).sort((a, b) => Number(Boolean(b.tlsShared)) - Number(Boolean(a.tlsShared)));
      if (!rules.length) throw new Error("请粘贴至少一条规则");
      while (imported < rules.length) {
        const batch = rules.slice(imported, imported + 1000);
        await api("/rules/batch", "POST", { action: "import", rules: batch });
        imported += batch.length;
      }
      setImporting(undefined);
      importForm.resetFields();
      resetPage();
      await reloadRules();
      message.success("导入完成");
    } catch (e) {
      if (imported > 0) {
        importForm.setFieldValue("targets", rules.slice(imported).map(rule => JSON.stringify(rule)).join("\n"));
        await reloadRules();
      }
      message.error((imported ? "已导入 " + imported + " 条，" : "") + (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const listActions = <>
    <Button aria-expanded={showSearch} onClick={() => setShowSearch(value => !value)}>高级筛选</Button>
    <Dropdown trigger={["click"]} menu={{ items: [
      ...(narrow ? [
        { key: "bulk-add", label: "批量添加", disabled: Boolean(creationBlock), onClick: () => setBulkAdd(true) },
        { key: "bulk-import", label: creationBlock ? "批量修改" : "批量导入", onClick: openImport },
        { key: "bulk-export", label: "批量导出", disabled: !selected.length, onClick: () => void copyRules() },
        { key: "nyanpass", label: "复制 nyanpass JSON", disabled: !selected.length, onClick: () => void copyRules(true) },
        { key: "bulk-switch", label: "批量切换", disabled: !selected.length, onClick: openReroute },
      ] : []),
      { key: "download", label: selected.length ? "下载选中" : "下载筛选结果", icon: <Download size={15} />, onClick: () => selected.length
        ? exportRules(list.value.filter(row => selected.includes(row.id))) : void exportFiltered() },
      ...(!ruleID && !adminSearch ? [{ key: "new-folder", label: "新增分组", onClick: () => editFolder("create") }] : []),
      ...(!ruleID && !adminSearch && (!user.admin || owner !== null) ? [{ key: "folders", label: "管理分组", disabled: !folders.value.some(folder => folder.name), onClick: () => editFolder("rename") }] : []),
    ] }}><Button loading={exporting} icon={<Ellipsis size={17} />}>列表操作</Button></Dropdown>
  </>;

  return (
    <>
      <section className="table-section panel-table rules-table">
      <header className="page-head">
        <div>
          <h1>{adminSearch ? "搜索转发规则" : "转发规则"}</h1>
          {owner && <p>用户 UID {owner}</p>}
          {ruleID && <p>规则 ID {ruleID} · <a href={owner ? "#/rules?owner=" + owner : "#/rules"}>查看全部规则</a></p>}
        </div>
        <Space wrap={!narrow}>
          {adminSearch && <Button href="#/users">返回用户管理</Button>}
          {!owner && !adminSearch && <Button onClick={async () => {
            try { setStatistics(await api("/rules/statistics")); }
            catch (error) { message.error((error as Error).message); }
          }}>统计数据</Button>}
          <RefreshButton reload={[...ruleReloads, groups.reload]} />
        </Space>
      </header>
      {!owner && !adminSearch && <dl className="rule-summary">
        <div><dt>流量</dt><dd>{bytes(user.used)} / {subscribed && user.unlimitedTraffic ? "不限流量" : bytes(subscribed ? user.quota : 0)}</dd></div>
        <div><dt>到期</dt><dd>{planExpiryLabel(user)}</dd></div>
        <div><dt>规则数</dt><dd>{allRules.value.total} / {ruleLimitLabel(user)}</dd></div>
      </dl>}
      {creationBlock && <Alert className="alert-gap" type="info" showIcon message={creationBlock}
        action={ownRules && (subscribed || showShop) && <Button size="small" href={subscribed ? "#/profile" : "#/shop"}>
          {subscribed ? "前往续费" : "选购套餐"}
        </Button>} />}
      {!ruleID && !adminSearch && <Tabs activeKey={label === undefined ? "all" : "folder:" + label} onChange={key => {
        setLabel(key === "all" ? undefined : key.slice(7));
        resetPage();
      }} items={[
        { key: "all", label: "全部" },
        { key: "folder:", label: `未分组 (${folders.value.find(folder => folder.name === "")?.count || 0})` },
        ...folders.value.filter(folder => folder.name).map(folder => ({
          key: "folder:" + folder.name, label: `${folder.name} (${folder.count})`,
        })),
      ]} />}
      {(list.error || groups.error) && (
        <Alert
          className="alert-gap"
          type="error"
          showIcon
          message={list.error || groups.error}
        />
      )}
        <div className="operator-toolbar">
          <Space size={[6, 7]} wrap={!narrow} className="operator-actions">
            {!firstRule && <Button type="primary" icon={<Plus size={15} />} disabled={Boolean(creationBlock)} onClick={() => edit(owner ? { owner } : undefined)}>添加规则</Button>}
            {!narrow && <>
              <Button disabled={Boolean(creationBlock)} onClick={() => setBulkAdd(true)}>批量添加</Button>
              <Button icon={<Upload size={15} />} onClick={openImport}>{creationBlock ? "批量修改" : "批量导入"}</Button>
              <Dropdown.Button disabled={!selected.length} onClick={() => void copyRules()} menu={{
                items: [{ key: "nyanpass", label: "复制 nyanpass JSON", onClick: () => void copyRules(true) }],
              }} trigger={["click"]}>批量导出</Dropdown.Button>
              <Button icon={<ArrowRightLeft size={15} />} disabled={!selected.length} onClick={openReroute}>批量切换</Button>
            </>}
            {narrow && listActions}
          </Space>
          <Space wrap={!narrow} className={"operator-filters rule-filters" + (user.admin ? " rule-filters-admin" : "")}>
            <Input
              aria-label="搜索规则"
              placeholder="搜索规则"
              prefix={<Search size={15} />}
              allowClear
              onChange={(event) => {
                setSearch(event.target.value);
                resetPage();
              }}
            />
            {user.admin && (
              <InputNumber
                min={1}
                value={owner}
                aria-label="用户 ID"
                placeholder="用户 ID"
                onChange={(id) => { setOwner(id); setLabel(undefined); resetPage(); }}
              />
            )}
            <Select
              aria-label="规则状态筛选"
              value={status}
              options={[
                { value: "", label: "全部状态" },
                { value: "enabled", label: "已启用" },
                { value: "disabled", label: "已暂停" },
                { value: "failed", label: "同步失败" },
              ]}
              onChange={(value) => { setStatus(value); resetPage(); }}
            />
            <Select
              aria-label="规则排序"
              value={sort}
              options={[
                { value: "", label: "最新规则" },
                { value: "name", label: "按名称" },
                { value: "port", label: "按端口" },
                { value: "entry", label: "按入口" },
                { value: "exit", label: "按出口" },
                { value: "traffic", label: "按流量" },
              ]}
              onChange={value => sortRules(value)}
            />
            {!narrow && listActions}
          </Space>
        </div>
        {showSearch && <Form name="rule-search" form={searchForm} layout="vertical" className="rule-search-form" onFinish={(values) => {
          setDetailFilters(values);
          resetPage();
        }}>
          <div className="settings-fields">
            <Form.Item name="name" label="规则名称"><Input allowClear /></Form.Item>
            <Form.Item name="entry" label="入口"><Select allowClear showSearch optionFilterProp="label" options={entries} /></Form.Item>
            <Form.Item name="exit" label="出口"><Select allowClear showSearch optionFilterProp="label"
              options={[{ value: 0, label: "直出" }, ...hops]} /></Form.Item>
            <Form.Item name="port" label="监听端口"><InputNumber min={1} max={65535} precision={0} style={{ width: "100%" }} /></Form.Item>
            <Form.Item name="target" label="目标地址或端口"><Input allowClear /></Form.Item>
          </div>
          <Space>
            <Button type="primary" htmlType="submit">搜索规则</Button>
            <Button onClick={() => { searchForm.resetFields(); setDetailFilters({}); resetPage(); }}>清除筛选</Button>
          </Space>
        </Form>}
        {selected.length > 0 && (
          <Space wrap={!narrow} className="batch-toolbar">
            <span className="selection-count">已选 {selected.length} 条</span>
            <Button size="small" onClick={() => void batch("enable")}>
              批量启动
            </Button>
            <Button size="small" onClick={() => void batch("disable")}>
              批量暂停
            </Button>
            <Button
              size="small"
              onClick={() =>
                confirmAction({
                  title: "清除所选规则的统计流量？",
                  onOk: () => batch("clear"),
                })
              }
            >
              清空统计
            </Button>
            <Button size="small" onClick={() => editFolder("move")}>
              移动分组
            </Button>
            <Button
              size="small"
              danger
              onClick={() =>
                confirmAction({
                  title: "删除所选规则？",
                  onOk: () => batch("delete"),
                })
              }
            >
              批量删除
            </Button>
          </Space>
        )}
        <Table<Rule>
          className={!list.value.length ? "rule-results-empty" : undefined}
          sticky={!narrow ? { offsetHeader: 58 } : undefined}
          size="middle"
          loading={list.busy}
          locale={{ emptyText: (
            <div className="rule-empty">
              {!list.busy && (list.error ? <strong>规则加载失败</strong> : firstRule ? <>
                <strong>还没有转发规则</strong>
                <Button type="primary" icon={<Plus size={15} />} disabled={Boolean(creationBlock)} onClick={() => edit(owner ? { owner } : undefined)}>添加规则</Button>
              </> : <strong>{hasFilter || adminSearch ? "没有符合条件的规则" : "当前页没有规则"}</strong>)}
            </div>
          ) }}
          rowKey="id"
          dataSource={list.value}
          pagination={false}
          showHeader={!narrow || list.value.length > 0}
          tableLayout="fixed"
          scroll={narrow && !list.value.length ? undefined : { x: ruleTableWidth }}
          onChange={(_, __, sorter, extra) => {
            if (extra.action !== "sort") return;
            const active = Array.isArray(sorter) ? sorter[0] : sorter;
            sortRules(active?.order ? String(active.columnKey) : "", active?.order === "descend" ? "desc" : "asc");
          }}
          rowSelection={{ selectedRowKeys: selected, onChange: setSelected, columnWidth: narrow ? 36 : undefined }}
          columns={[
            ...(adminSearch ? [{ title: "用户", key: "owner", width: 130, render: (_: unknown, rule: Rule) => (
              <a href={"#/rules?owner=" + rule.owner}>{rule.ownerName || "UID " + rule.owner}</a>
            ) }] : []),
            {
              title: "规则名称",
              ...sortable("name"),
              width: narrow ? 102 : 156,
              render: (_, r) => (
                <div className="rule-cell">
                  <button type="button" className="button-link rule-name" onClick={() => setDetailID(r.id)}>{r.name || "未命名规则"}</button>
                  <div className="data-secondary">
                    #{r.id}
                    {r.label ? " · " + r.label : ""}
                  </div>
                  {adminSearch && <a className="data-secondary" href={"#/rules?owner=" + r.owner + "&id=" + r.id}>定位规则</a>}
                </div>
              ),
            },
            {
              title: "入口",
              ...sortable("entry"),
              width: narrow ? 188 : undefined,
              render: (_, r) => {
                const addresses = connectionAddresses(r);
                return <div className="rule-cell rule-entry-cell">
                  <div className="rule-entry-meta">
                    <span className="data-title">{r.entry ? names.get(r.entry) || r.entry : "未选择"}</span>
                    {addresses.length > 0 && <span className="protocol-label">{protocolLabel(r)}</span>}
                  </div>
                  {addresses.length > 0 && <div className="rule-entry-connection">
                    <button type="button" className="button-link rule-entry-address mono"
                      aria-label={"查看入口连接地址 " + addresses[0]} onClick={() => setAddressRule(r)}>{addresses[0]}</button>
                    {addresses.length > 1 && <button type="button" className="button-link rule-cell-link" onClick={() => setAddressRule(r)}>
                      {addresses.length} 个地址
                    </button>}
                  </div>}
                </div>;
              },
            },
            {
              title: "出口 / 目标",
              ...sortable("exit"),
              width: narrow ? 220 : undefined,
              render: (_, r) => {
                const targets = r.targets ?? [];
                return <div className="rule-cell">
                  {r.protocol === "haproxy-both" ? <>
                    <span className="data-title">TCP · HAProxy 直出</span>
                    <span className="data-secondary">UDP · {describePath(r.path, r.routeRepair?.path)}</span>
                  </> : <span className="data-title">{r.tlsShared ? "按 SNI 分流" : r.protocol === "haproxy-tcp" ? "HAProxy 直出" : describePath(r.path, r.routeRepair?.path)}</span>}
                  {narrow ? <>
                    {targets.slice(0, 2).map((target, index) => <span className="data-secondary mono table-address" key={index}>{target}</span>)}
                    {targets.length > 2 && <button type="button" className="button-link rule-cell-link" onClick={() => setDetailID(r.id)}>
                      查看全部 {targets.length} 个目标
                    </button>}
                  </> : <span className="data-secondary mono">{r.targets?.join(", ")}</span>}
                  {(!!r.backupPath?.length || r.routeRepair?.backupPath) && <span className="data-secondary">{r.protocol === "haproxy-both" ? "UDP 备用" : "备用"} · {describePath(r.backupPath, r.routeRepair?.backupPath)}</span>}
                </div>;
              },
            },
            {
              title: "已用流量",
              ...sortable("traffic"),
              width: 106,
              align: "right",
              render: (_, r) => (
                <span className="mono">{((r.in + r.out) / 2 ** 30).toFixed(2)} GiB</span>
              ),
            },
            {
              title: "状态",
              key: "status",
              width: narrow ? 112 : 120,
              render: (_, r) => <RuleStatus rule={r} />,
            },
            {
              title: "操作",
              key: "actions",
              width: narrow ? 152 : wide ? 248 : 188,
              render: (_, r) => (
                <Space className="row-actions" size={2}>
                  {!narrow && !r.routeRepair && <IconAction label={r.enabled ? "暂停规则" : "启动规则"}
                    icon={r.enabled ? <Pause size={15} /> : <Play size={15} />}
                    onClick={() => void batch(r.enabled ? "disable" : "enable", [r.id])} />}
                  <IconAction
                    label="编辑"
                    icon={<Pencil size={15} />}
                    onClick={() => edit(r)}
                  />
                  <IconAction
                    label={r.routeRepair ? "请先重新选择线路" : r.serviceBlock || "链路诊断"}
                    icon={<Activity size={15} />}
                    disabled={Boolean(r.serviceBlock || r.routeRepair)}
                    onClick={() => setDiagnosticRule(r)}
                  />
                  {!narrow && <IconAction
                    label={r.routeRepair ? "请先重新选择线路" : r.serviceBlock || "复制"}
                    icon={<Copy size={14} />}
                    disabled={Boolean(r.serviceBlock || r.routeRepair)}
                    onClick={() =>
                      edit({ ...r, id: 0, port: 0, name: r.name + " 副本" })
                    }
                  />}
                  {wide && <IconAction label="编辑规则 JSON"
                    icon={<Code2 size={15} />} onClick={() => setJsonRule(r)} />}
                  {wide && <IconAction danger label="删除规则"
                    icon={<Trash2 size={15} />} onClick={() => deleteRule(r)} />}
                  <Dropdown trigger={["click"]} menu={{ items: [
                    ...(narrow ? [{ key: "copy", label: "复制规则", disabled: Boolean(r.serviceBlock || r.routeRepair), onClick: () => edit({ ...r, id: 0, port: 0, name: r.name + " 副本" }) }] : []),
                    { key: "advanced", label: "高级编辑", onClick: () => { edit(r); setAdvanced(true); } },
                    ...(!wide ? [{ key: "json", label: "编辑规则 JSON", onClick: () => setJsonRule(r) }] : []),
                    ...(user.admin && !r.routeRepair && (r.effectiveNetwork || r.protocol) !== "udp" ? [{ key: "haproxy", label: "生成 HAProxy 配置", icon: <Network size={14} />, onClick: () => {
                      setProxyConfig("");
                      setProxyRule(r);
                      proxyForm.setFieldsValue({ bind: "0.0.0.0:" + (r.tlsSharedPort || r.port), backends: "" });
                    } }] : []),
                    { key: "clear", label: "清空统计", onClick: () => confirmAction({ title: "清空本条规则的统计？", onOk: () => batch("clear", [r.id]) }) },
                    ...(!wide ? [{ key: "delete", label: "删除规则", danger: true, onClick: () => deleteRule(r) }] : []),
                  ] }}><IconAction label="规则更多操作" icon={<Ellipsis size={16} />} /></Dropdown>
                  {narrow && !r.routeRepair && <Switch
                    size="small"
                    checked={r.enabled}
                    aria-label="切换规则状态"
                    onChange={(enabled) =>
                      void batch(enabled ? "enable" : "disable", [r.id])
                    }
                  />}
                </Space>
              ),
            },
          ]}
        />
        <div className="table-footer rule-pagination">
          <span className="muted">共 {totals.value.total} 条规则</span>
          <Space wrap>
            <Button
              aria-label="上一页"
              icon={narrow ? <ChevronLeft size={16} /> : undefined}
              disabled={list.busy || (sort ? offset === 0 : !cursors.length)}
              onClick={() => {
                if (sort) {
                  setOffset((value) => Math.max(0, value - pageSize));
                } else {
                  setBefore(cursors.at(-1) || "");
                  setCursors((v) => v.slice(0, -1));
                }
                setSelected([]);
              }}
            >
              {!narrow && "上一页"}
            </Button>
            <Button
              aria-label="下一页"
              icon={narrow ? <ChevronRight size={16} /> : undefined}
              disabled={list.busy || totals.busy || (sort ? offset : cursors.length * pageSize) + list.value.length >= totals.value.total}
              onClick={() => {
                if (sort) {
                  setOffset((value) => value + pageSize);
                } else {
                  setCursors([...cursors, before]);
                  setBefore(String(list.value.at(-1)?.id));
                }
                setSelected([]);
              }}
            >
              {!narrow && "下一页"}
            </Button>
            <Select aria-label="每页规则数" value={pageSize} onChange={(size) => { setPageSize(size); resetPage(); }}
              options={[10, 20, 50, 100, 200, 500, 1000].map(size => ({ value: size, label: size + " 条/页" }))} />
          </Space>
        </div>
      </section>
      {jsonRule && <JsonEditor title={"规则 JSON · " + jsonRule.name}
        value={Object.fromEntries(Object.entries(jsonRule).filter(([key]) => !["in", "out", "effectiveNetwork", "runtime", "reportedAt"].includes(key)))}
        onClose={() => setJsonRule(undefined)}
        onSave={async (values) => {
          await api("/rules/" + jsonRule.id, "PUT", values);
          await reloadRules();
          message.success("规则已保存");
          return true;
        }} />}
      <Modal open={bulkAdd} title="批量添加规则" onCancel={() => setBulkAdd(false)} onOk={() => bulkForm.submit()}
        confirmLoading={busy} okText="添加" okButtonProps={{ disabled: Boolean(creationBlock) }}>
        <Form name="rule-batch" form={bulkForm} layout="vertical" onFinish={addRules}>
          <Form.Item name="entry" label="入口设备组" rules={[{ required: true }]}>
            <Select showSearch optionFilterProp="label" optionRender={renderGroupOption} options={entries} onChange={() => bulkForm.setFieldValue("path", [])} />
          </Form.Item>
          {chosenBulkEntry?.routing?.ingressMode !== "direct" && <Form.Item name="path" label="出口路径"
            rules={requiresExit(chosenBulkEntry) ? [{required:true}] : undefined}>
            <MultiSelect maxCount={chosenBulkEntry?.routing?.ingressMode === "personal" ? 1 : 8}
              optionFilterProp="label" optionRender={renderGroupOption}
              options={exitOptions(chosenBulkEntry)} placeholder={requiresExit(chosenBulkEntry) ? "选择出口设备组" : "入口直出"} />
          </Form.Item>}
          <Form.Item name="targets" label="批量规则" rules={[{ required: true }]}>
            <Input.TextArea className="dialog-code" spellCheck={false} rows={6} placeholder={"每行一条规则\n支持 host:port、nyanpass JSON、名称#监听端口#目标地址#目标端口"} />
          </Form.Item>
          <Button type="link" className="advanced-toggle" aria-expanded={bulkAdvanced} onClick={() => setBulkAdvanced(!bulkAdvanced)}>JSON 设置</Button>
          <div hidden={!bulkAdvanced}>
            <Form.Item name="options" label="共用规则配置" extra="填写 JSON 对象，覆盖每条规则中目标地址以外的字段。">
              <Input.TextArea className="dialog-code" spellCheck={false} rows={4} placeholder={'{"dest_policy":"round"}'} />
            </Form.Item>
          </div>
        </Form>
      </Modal>
      <Modal open={rerouting} title="批量切换规则" onCancel={() => setRerouting(false)} onOk={() => routeForm.submit()} confirmLoading={busy} okText="切换">
        <Form name="rule-reroute" form={routeForm} layout="vertical" onFinish={switchRoutes}>
          <Form.Item name="entry" label="切换入口"><Select allowClear options={entries} placeholder="留空保留现有入口" /></Form.Item>
          <Form.Item name="updatePath" label="同时切换出口" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="path" label="新出口路径"><MultiSelect options={hops} placeholder="切换出口时留空表示直出" /></Form.Item>
          <p className="dialog-note">更换入口时会从目标设备组重新分配端口。</p>
        </Form>
      </Modal>
      {diagnosticRule && <RuleDiagnostics rule={diagnosticRule} entryName={names.get(diagnosticRule.entry)} describePath={describePath} onClose={() => setDiagnosticRule(undefined)} />}
      <Drawer open={!!addressRule} title="入口连接地址" onClose={() => setAddressRule(undefined)}>
        {addressRule && <Space direction="vertical" style={{width:"100%"}}>
          {connectionAddresses(addressRule).map((address, index) => <div className="connection-address" key={index}>
            <code>{address}</code>
            <Button size="small" icon={<Copy size={14} />} onClick={() => navigator.clipboard.writeText(address)
              .then(() => message.success("地址已复制"), () => message.error("复制失败"))}>复制</Button>
          </div>)}
        </Space>}
      </Drawer>
      <Drawer open={!!statistics} title="规则统计" onClose={() => setStatistics(undefined)}>
        {statistics && <div className="details-grid">
          <dl><dt>规则总数</dt><dd>{statistics.total}</dd></dl>
          <dl><dt>已启用</dt><dd>{statistics.enabled}</dd></dl>
          <dl><dt>入站流量</dt><dd>{bytes(statistics.inbound)}</dd></dl>
          <dl><dt>出站流量</dt><dd>{bytes(statistics.outbound)}</dd></dl>
          <dl><dt>我的今日流量</dt><dd>{bytes(statistics.today)}</dd></dl>
          <dl><dt>我的昨日流量</dt><dd>{bytes(statistics.yesterday)}</dd></dl>
        </div>}
      </Drawer>
      <Drawer
        open={!!detail}
        onClose={() => setDetailID(undefined)}
        title={detail?.name || "规则详情"}
        extra={detail && (
          <Button icon={<Pencil size={15} />} onClick={() => { setDetailID(undefined); edit(detail); }}>编辑</Button>
        )}
      >
        {detail && (
          <>
            <RuleStatus rule={detail} />
            <div className="details-grid rule-details">
              <dl>
                <dt>入口</dt>
              <dd>{detail.entry ? names.get(detail.entry) || detail.entry : "未选择"}
                {detail.entry > 0 && <>
                  <div className="rule-entry-meta"><span className="protocol-label">{protocolLabel(detail)}</span></div>
                  {connectionAddresses(detail).map((address, index) => <div className="mono table-address" key={index}>{address}</div>)}
                </>}
              </dd>
              </dl>
              <dl><dt>规则编号</dt><dd>#{detail.id}</dd></dl>
              {detail.protocol === "haproxy-tcp" || detail.protocol === "haproxy-both" ? <>
                <dl><dt>TCP 路径</dt><dd>HAProxy 直连目标</dd></dl>
                {detail.protocol === "haproxy-both" && <dl><dt>UDP 路径</dt><dd>{describePath(detail.path, detail.routeRepair?.path)}</dd></dl>}
              </> : <dl><dt>出口</dt><dd>{describePath(detail.path, detail.routeRepair?.path)}</dd></dl>}
              {(!!detail.backupPath?.length || detail.routeRepair?.backupPath) && <dl><dt>{detail.protocol === "haproxy-both" ? "UDP 备用路径" : "备用链路"}</dt><dd>{describePath(detail.backupPath, detail.routeRepair?.backupPath)}</dd></dl>}
              <dl><dt>入站流量</dt><dd>{bytes(detail.in)}</dd></dl>
              <dl><dt>出站流量</dt><dd>{bytes(detail.out)}</dd></dl>
              <dl>
                <dt>目标地址</dt>
                <dd>{detail.tlsShared ? "按 SNI 分流" : detail.targets?.map((target, index) => <div className="mono table-address" key={index}>{target}</div>)}</dd>
              </dl>
            </div>
          </>
        )}
      </Drawer>
      {user.admin && (
        <Modal
          open={proxyRule !== null}
          title="HAProxy 入口负载均衡"
          onCancel={() => { if (!proxyBusy) setProxyRule(null); }}
          footer={[
            <Button key="download" icon={<Download size={16} />} disabled={!proxyConfig} onClick={downloadProxy}>下载</Button>,
            <Button key="generate" type="primary" loading={proxyBusy} onClick={() => proxyForm.submit()}>生成配置</Button>,
          ]}
          forceRender
        >
          <p className="dialog-note">
            HAProxy 将 TCP 连接分配到健康的 HopX 入口节点。UDP 由 HopX 入口直接处理。
            入口节点端口为 {proxyRule?.tlsSharedPort || proxyRule?.port}。
          </p>
          <Form name="rule-haproxy" form={proxyForm} layout="vertical" onFinish={generateProxy} onValuesChange={() => setProxyConfig("")} disabled={proxyBusy}>
            <Form.Item name="bind" label="HAProxy 监听地址" rules={[{ required: true }]}>
              <Input placeholder="0.0.0.0:443" />
            </Form.Item>
            <Form.Item name="backends" label="HopX 入口节点地址" rules={[{ required: true }]}>
              <Input.TextArea rows={3} placeholder={"每行一个 host:port\nIPv6 使用 [地址]:端口"} />
            </Form.Item>
          </Form>
          {proxyConfig && <Input.TextArea className="dialog-code proxy-config-output" aria-label="HAProxy 配置" value={proxyConfig} readOnly rows={10} />}
        </Modal>
      )}
      <Modal
        open={editing !== null}
        title={editing?.id ? "编辑规则" : "添加规则"}
        onCancel={() => { if (!saveRequest.current) setEditing(null); }}
        onOk={() => form.submit()}
        confirmLoading={busy}
        forceRender
        width={660}
        okText={busy && !editing?.id ? "检查端口并保存…" : "保存"}
        okButtonProps={{ "aria-label": "保存" }}
        cancelButtonProps={{ disabled: busy }}
        closable={!busy}
        maskClosable={!busy}
      >
        <Form name="rule-editor" form={form} layout="vertical" onFinish={save} disabled={busy}
          onValuesChange={() => { if (saveError) setSaveError(""); }} className="rule-editor">
          {editing?.routeRepair && <Alert className="alert-gap" showIcon type="warning"
            message="设备组权限已变更"
            description="失去权限的线路已清空。选好可用线路并保存后，原来已启用的规则会恢复转发。" />}
          {saveError && <Alert className="alert-gap" showIcon type="error" message={saveError} />}
          <div className="details-grid">
            <Form.Item name="name" label="名称" rules={[{ required: true }]}>
              <Input />
            </Form.Item>
            <Form.Item name="label" label="规则分组">
              <Input allowClear />
            </Form.Item>
            <Form.Item
              name="entry"
              label="入口设备组"
              rules={[{ required: true }]}
            >
              <Select showSearch optionFilterProp="label" optionRender={renderGroupOption} options={entries}
                placeholder="选择入口设备组" onChange={() => {
                  if (!editing?.routeRepair?.entry || ruleEntry) form.setFieldsValue({ path: [], backupPath: [] });
                  form.setFieldValue("confirmRoute", false);
                }} />
            </Form.Item>
            <Form.Item name="port" label={sharedPort ? "规则端口编号" : "监听端口"}>
              <InputNumber
                min={0}
                max={65535}
                style={{ width: "100%" }}
                placeholder="留空时从端口池分配"
              />
            </Form.Item>
            <Form.Item name="protocol" label="转发方式" className="field-wide" extra={usesHAProxy ?
              <span className="rule-engine-note"><Network size={14} aria-hidden="true" />由入口节点按需启动 HAProxy，同节点的规则共用进程。</span> : undefined}>
              <Select options={[
                { value: "inherit", label: "继承入口设备组" },
                { value: "tcp", label: "TCP" },
                { value: "udp", label: "UDP" },
                { value: "both", label: "TCP + UDP" },
                ...(user.admin ? [
                  { value: "haproxy-tcp", label: "HAProxy TCP", disabled: requiresExit(chosenEntry) },
                  { value: "haproxy-both", label: "HAProxy TCP + GOST UDP", disabled: requiresExit(chosenEntry) || chosenEntry?.ingress?.disableUDP || !!chosenEntry?.ingress?.allowedHosts?.length },
                ] : []),
              ]} />
            </Form.Item>
          </div>
          {chosenEntry && <dl className="entry-summary">
            <div><dt>入口地址</dt><dd>{chosenEntry.connectHost?.split("\n").filter(Boolean).join("、") || "由设备提供"}</dd></div>
            <div><dt>端口池</dt><dd>{chosenEntry.portRanges || `${chosenEntry.firstPort}–${chosenEntry.lastPort}`}</dd></div>
            <div><dt>流量倍率</dt><dd>{chosenEntry.ratio / 1000} 倍</dd></div>
          </dl>}
          {!!restrictions.length && <Descriptions size="small" column={1} className="alert-gap"
            items={restrictions.map(({ key, label, value }) => ({ key, label, children: value?.join("、") }))} />}
          {(!sharedTLS || chosenEntry?.routing?.ingressMode !== "direct") && <div className="editor-section">
            <h3>转发目标</h3>
            {!sharedTLS && <Form.Item
              name="targets"
              label="目标地址"
              rules={[{ required: true }]}
            >
              <Input.TextArea
                rows={3}
                placeholder={"一行一个 host:port\n例如 example.com:443"}
              />
            </Form.Item>}
            {!pureHAProxy && chosenEntry && chosenEntry.routing?.ingressMode !== "direct" && <Form.Item name="path" label={mixedHAProxy ? "UDP 出口路径" : "出口路径"}
              tooltip={mixedHAProxy ? "留空时 UDP 直出。选中出口后，UDP 使用该出口设备组配置的 GOST 传输协议。" :
                "选择一个出口，或按转发顺序选择多跳。已配置的链式出口可直接选择。"}
              rules={requiresExit(chosenEntry) && !sharedTLS ? [{required:true}] : undefined}>
              <MultiSelect
                maxCount={chosenEntry.routing?.ingressMode === "personal" ? 1 : 8}
                optionFilterProp="label"
                optionRender={renderGroupOption}
                options={exitOptions(chosenEntry, rulePath)}
                placeholder={requiresExit(chosenEntry) || editing?.routeRepair?.path ? "选择出口设备组" : "入口直出"}
                allowClear
              />
            </Form.Item>}
            {chosenEntry && !sharedTLS && (usesHAProxy || selectedHops.length > 0 || chosenEntry.routing?.ingressMode === "direct") &&
              <div className="route-preview" aria-label="转发路径">
                {usesHAProxy && <div className="route-preview-row">
                  <strong>TCP</strong><span>{chosenEntry.name}<ChevronRight size={13} aria-hidden="true" />目标地址</span>
                  <small>HAProxy 直连</small>
                </div>}
                {!pureHAProxy && <div className="route-preview-row">
                  {mixedHAProxy && <strong>UDP</strong>}
                  <span>{chosenEntry.name}</span>
                  {selectedHops.map((hop, index) => (
                    <span key={index}><ChevronRight size={13} aria-hidden="true" />{hop?.name ?? "设备组"}
                      {hop && hop.kind !== "chain" && <small title="设备组默认传输协议">{relayModeLabel(hop.relayMode)}</small>}
                    </span>
                  ))}
                  <span><ChevronRight size={13} aria-hidden="true" />目标地址</span>
                  {mixedHAProxy && selectedHops.length === 0 && <small>入口直出</small>}
                </div>}
              </div>}
          </div>}
          {chosenEntry && (confirmWithoutPrimary || confirmWithoutBackup) && <Form.Item name="confirmRoute" valuePropName="checked" preserve={false}>
            <Checkbox>确认{[confirmWithoutPrimary && "由入口直出", confirmWithoutBackup && "取消备用出口"].filter(Boolean).join("并")}</Checkbox>
          </Form.Item>}
          <Button className="editor-disclosure" type="text"
            icon={<ChevronDown size={15} className={advanced ? "rotate" : undefined} />}
            aria-expanded={advanced} aria-controls="rule-advanced" onClick={() => setAdvanced(!advanced)}>
            {advanced ? "收起高级设置" : "高级设置"}
          </Button>
          <div id="rule-advanced" className="editor-section" hidden={!advanced}>
            {user.admin && (
              <Form.Item name="owner" label="所属用户 ID">
                <InputNumber
                  min={1}
                  style={{ width: "100%" }}
                  placeholder="默认为当前账号"
                />
              </Form.Item>
            )}
            {!pureHAProxy && chosenEntry?.routing?.ingressMode !== "direct" && <Form.Item name="backupPath" label={mixedHAProxy ? "UDP 备用路径" : "备用出口路径"}>
              <MultiSelect optionFilterProp="label" optionRender={renderGroupOption}
                maxCount={chosenEntry?.routing?.ingressMode === "personal" ? 1 : 8}
                options={exitOptions(chosenEntry, backupPath)} placeholder="选择备用出口" allowClear />
            </Form.Item>}
            {!sharedTLS && <section className="rule-probe-options" aria-labelledby="rule-probe-options-title">
              <h3 id="rule-probe-options-title"><Activity size={16} aria-hidden="true" />链路监测</h3>
              <div className="details-grid">
                <Form.Item name="probeInterval" label="历史采样间隔">
                  <Select options={[
                    { value: 0, label: `继承站点设置 · ${siteProbeInterval / 60} 分钟` },
                    { value: 60, label: "每 1 分钟" },
                    { value: 300, label: "每 5 分钟" },
                  ]} />
                </Form.Item>
                {["udp", "both", "inherit", "haproxy-both"].includes(forwardMode ?? "inherit") &&
                  <Form.Item name="udpProbe" label="UDP Echo 探测" valuePropName="checked"
                    tooltip="目标 UDP 服务须原样返回探测数据。开启后可统计目标回包和超时。">
                    <Switch />
                  </Form.Item>}
              </div>
            </section>}
            <div className="details-grid">
              <Form.Item name="strategy" label="负载策略">
                <Select
                  options={[
                    { value: "round-robin", label: "轮询" },
                    { value: "random", label: "随机" },
                    { value: "first", label: "优先首个" },
 {value:"ip-hash",label:"IP 哈希"},
 {value:"least-connections",label:"最小连接数"},
                  ]}
                />
              </Form.Item>
              <Form.Item name="rateMbps" label="限速 Mbps">
                <InputNumber min={0} />
              </Form.Item>
              <Form.Item name="maxIPs" label="IP 数量上限">
                <InputNumber min={0} />
              </Form.Item>
              <Form.Item name="maxConns" label="连接数上限">
                <InputNumber min={0} />
              </Form.Item>
              <Form.Item
                name="proxyIn"
                label="接收 Proxy Protocol"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
              <Form.Item
                name="proxyOut"
                label="发送 Proxy Protocol"
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
              <Form.Item name="proxyInVersion" label="接收版本（开启接收后生效）">
                <Select options={[{value:0,label:"自动"},{value:1,label:"v1"},{value:2,label:"v2"}]} placeholder="自动"/>
              </Form.Item>
              <Form.Item name="proxyOutVersion" label="发送版本（开启发送后生效）">
                <Select options={[{value:0,label:"默认 v1"},{value:1,label:"v1 · TCP"},{value:2,label:"v2 · TCP 和 UDP"}]} placeholder="v1"/>
              </Form.Item>
              <Form.Item name="tlsGenerateFor" label="生成自签证书" tooltip="填写证书域名或 IP。保存后可在规则中查看证书。">
                <Input allowClear disabled={!!sharedPort} placeholder="留空时使用下方证书" />
              </Form.Item>
              <Form.Item name="tlsCert" label="TLS 证书">
                <Input.TextArea rows={2} disabled={!!generateTLS} />
              </Form.Item>
              <Form.Item name="tlsKey" label="TLS 私钥">
                <Input.TextArea rows={2} disabled={!!generateTLS} />
              </Form.Item>
              {user.admin && (
                <Form.Item name="tlsShared" label="启用共享 TLS 入口" valuePropName="checked">
                  <Switch />
                </Form.Item>
              )}
              {sharedTLS ? (
                <>
                  <Form.Item name="tlsAllowedNames" label="授权域名或后缀">
                    <MultiSelect mode="tags" tokenSeparators={[",", "，"]} placeholder="例如 app.example.com 或 .example.com" />
                  </Form.Item>
                  <Form.Item name="tlsAllowedUsers" label="允许创建子规则的用户 ID">
                    <MultiSelect mode="tags" tokenSeparators={[",", "，"]} placeholder="留空仅自己，0 允许全部" />
                  </Form.Item>
                </>
              ) : (
                <Form.Item name="tlsSharedPort" label="共享 TLS 端口">
                  <InputNumber min={1} max={65535} placeholder="留空时独立监听" />
                </Form.Item>
              )}
              <Form.Item name="tlsServerNames" label="允许的 TLS SNI">
                <MultiSelect mode="tags" tokenSeparators={[",", "，"]} />
              </Form.Item>
              <Form.Item name="tlsALPN" label="允许的 TLS ALPN">
                <MultiSelect mode="tags" tokenSeparators={[",", "，"]} />
              </Form.Item>
              <Form.Item name="tlsRequireEmpty" label="只允许空 SNI" valuePropName="checked">
                <Switch />
              </Form.Item>
              {!sharedTLS && (
                <Form.Item name="tlsOrigin" label="回源 TLS">
                  <Select options={[
                    { value: 0, label: "关闭" },
                    { value: 1, label: "空 SNI，不校验证书" },
                    { value: 2, label: "客户端 SNI，不校验证书" },
                    { value: 3, label: "客户端 SNI，校验证书" },
                  ]} placeholder="关闭" />
                </Form.Item>
              )}
              <Form.Item name="responseFilters" label="回源响应筛选">
                <MultiSelect options={[
                  { value: 1, label: "拒绝旧版 TLS" },
                  { value: 2, label: "拒绝 TLS" },
                  { value: 3, label: "拒绝 HTTP/1（保留 101）" },
                  { value: 4, label: "拒绝 HTTP 101" },
                  { value: 2000, label: "IPv6 跳过筛选" },
                ]} />
              </Form.Item>
            </div>
          </div>
        </Form>
      </Modal>
      <Modal
        open={!!importing}
        title={importing === "update" ? "批量导入（修改）" : "批量导入规则"}
        onCancel={() => setImporting(undefined)}
        onOk={() => importForm.submit()}
        confirmLoading={busy}
        okText={importing === "update" ? "更新规则" : "导入"}
        okButtonProps={{ disabled: importing === "create" && Boolean(creationBlock) }}
      >
        <Form name="rule-import" form={importForm} layout="vertical" onFinish={importRules}>
          <Button type="link" className="advanced-toggle" disabled={busy || (importing === "update" && Boolean(creationBlock))}
            onClick={() => setImporting(importing === "update" ? "create" : "update")}>
            {importing === "update" ? "切换为批量新增" : "切换为批量修改"}
          </Button>
          {importing === "update" && <p className="dialog-note">按入口和监听端口匹配已有规则，只更新填写的配置项。</p>}
          <Form.Item name="targets" label="规则内容" rules={[{ required: true }]}>
            <Input.TextArea className="dialog-code" spellCheck={false} rows={10} placeholder={importing === "update"
              ? '{"listen_port":12345,"dest":["example.com:443"]}'
              : "粘贴逐行规则或 HopX JSON 数组\n旧格式为 名称#监听端口#目标地址#目标端口"} />
          </Form.Item>
          {(legacyInput || importing === "update") && <>
            <Form.Item name="entry" label="入口设备组" rules={[{ required: true }]}>
              <Select showSearch optionFilterProp="label" optionRender={renderGroupOption} options={entries} onChange={() => importForm.setFieldValue("path", [])} />
            </Form.Item>
            {importing !== "update" && chosenImportEntry?.routing?.ingressMode !== "direct" && <Form.Item name="path" label="出口路径">
              <MultiSelect maxCount={chosenImportEntry?.routing?.ingressMode === "personal" ? 1 : 8}
                optionFilterProp="label" optionRender={renderGroupOption}
                options={exitOptions(chosenImportEntry)} placeholder={requiresExit(chosenImportEntry) ? "选择出口设备组" : "入口直出"} />
            </Form.Item>}
          </>}
        </Form>
      </Modal>
      <Modal open={!!copiedRules} title="批量导出" onCancel={() => setCopiedRules("")}
        footer={<Button onClick={() => setCopiedRules("")}>关闭</Button>}>
        <Input.TextArea className="dialog-code" aria-label="规则导出内容" readOnly value={copiedRules} rows={10}
          onFocus={event => event.target.select()} />
      </Modal>
      <Modal open={!!folderEditor} title={folderEditor === "move" ? "移动分组" : folderEditor === "create" ? "新增分组" : "管理分组"}
        onCancel={() => setFolderEditor(undefined)} onOk={() => folderForm.submit()} okText="保存分组"
        confirmLoading={busy} okButtonProps={{ "aria-label": "保存分组" }} forceRender>
        <Form form={folderForm} name="rule-folder" layout="vertical" onFinish={saveFolder}>
          {folderEditor === "rename" && <Form.Item label="现有分组" name="from" rules={[{ required: true }]}>
            <Select options={folders.value.filter(folder => folder.name).map(folder => ({ value: folder.name, label: folder.name }))} />
          </Form.Item>}
          <Form.Item label={folderEditor === "rename" ? "新名称" : "分组名称"} name="name"
            rules={folderEditor === "create" ? [{ required: true, whitespace: true }] : undefined}
            extra={folderEditor !== "create" ? "留空移到未分组，填写已有名称可合并。" : undefined}>
            <Input autoComplete="off" maxLength={100} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
