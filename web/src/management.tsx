import { useEffect, useState } from "react";
import type { HTMLAttributes, ReactNode } from "react";
import {
  Alert,
  App,
  Button,
  Checkbox,
  DatePicker,
  Descriptions,
  Dropdown,
  Drawer,
  Form,
  Grid,
  Input,
  InputNumber,
  Modal,
  Pagination,
  QRCode,
  Segmented,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tabs,
  Tag,
} from "antd";
import dayjs from "dayjs";
import {
  CalendarDays,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  Globe,
  Ellipsis,
  FileJson,
  Gauge,
  GripVertical,
  Gift,
  Link2,
  Network,
  Settings2,
  Trash2,
  Unlink,
  Pencil,
  Plus,
  ShoppingBag,
  Ticket,
  Server,
  Terminal,
  Timer,
  Wallet,
  Workflow,
} from "lucide-react";
import { api, bytes, currency, date, planExpiryLabel, ruleLimitLabel, useData } from "./api";
import type { Group, Node, Plan, User } from "./api";
import JsonEditor from "./json-editor";
import { paymentKinds } from "./payment-channels";
import type { PaymentOption } from "./payment-channels";
import { relayModes, relayModeHelp, relayModeLabel } from "./relay-protocols";
import RefreshButton from "./refresh-button";
import { useConfirmAction } from "./confirm-action";
import IconAction from "./icon-action";
import { NodeFlag, nodeDisplayName } from "./node-location";
import MultiSelect from "./multi-select";

type Row = Record<string, any>;
type Field = {
  name: string;
  path?: string[];
  label: string;
  kind?: "number" | "decimal" | "date" | "switch" | "checkbox" | "secret" | "area" | "select" | "multi" | "tags";
  unit?: string;
  help?: string;
  placeholder?: string;
  options?: { value: string | number; label: string; disabled?: boolean }[];
  required?: boolean;
  min?: number;
  max?: number;
  precision?: number;
  step?: number;
};
type Editor = {
  title: string;
  path: string;
  method: string;
  fields: Field[];
  value: Row;
};
type GroupConfig = {
  revision: string;
  rules: { id: number; name: string; port: number; network: string; targets?: string[]; path?: number[]; backupPath?: number[]; routes: number; backup: number }[];
};

type Accounting = { userId: number; amount: number; description?: string };
type AccountingPreview = { name: string; balance: number; after: number; values: Accounting };
type OfflineNotice = { default: number; groups: Record<string, number> };

const groupKinds = [
  { value: "monitor", label: "仅监控" },
  { value: "entry", label: "入口" },
  { value: "exit", label: "出口" },
  { value: "chain", label: "链式出口" },
];
const groupKindCategory = (kind: string) => kind === "both" ? "entry" : kind === "relay" ? "exit" : kind;
const groupKindLabel = (kind: string) => groupKinds.find(option => option.value === groupKindCategory(kind))?.label ?? kind;
const labels: Record<string, string> = {
  epay: "易支付充值",
 epusdt:"EPUSDT 充值",
 tokenpay:"TokenPay 充值",
 cryptomus:"Cryptomus 充值",
  pending: "待支付",
  referral: "邀请返佣",
  affiliate_transfer: "佣金转入钱包",
  affiliate_manual: "佣金手动记账",
  legacy_affiliate: "历史佣金记录",
  recorded: "已记录",
 transfer: "余额划转",
  purchase: "购买套餐",
  renew: "续费",
  manual: "手工记账",
  payment: "充值",
  redeem: "兑换",
  paid: "已支付",
};
const groupFields: Field[] = [
  { name: "name", label: "名称", required: true },
  {
    name: "kind",
    label: "类型",
    kind: "select",
    options: groupKinds,
    required: true,
  },
  { name: "relayMode", label: "GOST 传输协议", kind: "select", options: relayModes, help: "供经过此设备组的 GOST 链路使用。新接入节点采用此默认值。" },
  { name: "defaultNetwork", label: "默认监听协议", kind: "select", options: [
    { value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }, { value: "both", label: "TCP + UDP" },
  ] },
  { name: "tlsIngress", label: "TLS 入站策略", kind: "select", options: [
    {value: 0, label: "普通和 TLS 规则"},
    {value: 1, label: "仅 TLS 规则"},
    {value: 2, label: "仅共享 TLS"},
  ] },
  { name: "firstPort", label: "起始端口", kind: "number", min: 1, max: 65535 },
  { name: "lastPort", label: "结束端口", kind: "number", min: 1, max: 65535 },
  { name: "connectHost", label: "连接地址", kind: "area", placeholder: "留空时使用节点地址", help: "每行填写一个供用户连接的入口地址。" },
  { name: "portRanges", label: "自定义端口池", help: "填写后覆盖上方端口范围，例如 443,10000-65525" },
  { name: "ratio", label: "流量倍率", kind: "decimal", unit: "倍", min: 0, max: 100, step: 1, required: true, help: "填 2 表示按 2 倍计算本组流量" },
  { name: "offlineSeconds", label: "离线判定秒数", kind: "number" },
  { name: "folder", label: "设备组文件夹" },
  { name: "note", label: "备注", help: "仅管理员可见。" },
  { name: "showOrder", label: "排序值（从小到大）", kind: "number" },
  { name: "statusVisibility", path: ["routing", "statusVisibility"], label: "节点状态可见性", kind: "select", options: [
    {value:"all",label:"对所有用户可见"}, {value:"admin",label:"仅管理员可见"}, {value:"none",label:"对所有用户隐藏"},
  ] },
];
const ingressFields: Field[] = [
  { name: "ingressMode", path: ["routing", "ingressMode"], label: "入口转发模式", kind: "select", options: [
    { value: "", label: "允许直出或转发" }, { value: "direct", label: "仅入口直出" },
    { value: "relay", label: "必须经过出口" }, { value: "personal", label: "仅自有出口" },
  ] },
  { name: "allowPrivateTargets", path: ["routing", "allowPrivateTargets"], label: "允许普通用户转发到私网", kind: "switch", help: "默认仅允许经站点节点转发到公网。仅在入口对用户开放私网服务时启用。" },
  { name: "blockPersonal", path: ["ingress", "blockPersonal"], label: "禁止单端出口", kind: "switch" },
  { name: "siteOutboundOnly", path: ["ingress", "siteOutboundOnly"], label: "出口限制仅适用于站点设备", kind: "switch" },
  { name: "disableUDP", path: ["ingress", "disableUDP"], label: "禁用 UDP", kind: "switch" },
  { name: "rejectEmptySNI", path: ["ingress", "rejectEmptySNI"], label: "拒绝空 SNI", kind: "switch" },
  { name: "allowedHosts", path: ["ingress", "allowedHosts"], label: "允许的域名或后缀", kind: "tags" },
  { name: "blockedHosts", path: ["ingress", "blockedHosts"], label: "屏蔽的域名或后缀", kind: "tags" },
  { name: "blockedPaths", path: ["ingress", "blockedPaths"], label: "屏蔽的 HTTP 路径后缀", kind: "tags" },
  { name: "blockedTypes", path: ["ingress", "blockedTypes"], label: "屏蔽协议", kind: "multi", options: [
    { value: "http", label: "HTTP" },
    { value: "tls", label: "TLS 透传" },
    { value: "socks", label: "SOCKS" },
    { value: "fet", label: "疑似全加密流量（FET）" },
  ] },
];
const planFields: Field[] = [
  {name:"kind",label:"套餐类型",kind:"select",options:[{value:"day",label:"日付"},{value:"month",label:"月付"},{value:"traffic",label:"不限时流量包"},{value:"stack",label:"可叠加流量包"}],required:true},
  { name: "name", label: "名称", required: true },
  { name: "description", label: "套餐简介", kind: "area", placeholder: "选填，显示在商城卡片上" },
  { name: "priceAmount", label: "价格", kind: "decimal", unit: "¥", precision: 2, max: 2 ** 40 / 100, required: true },
  { name: "duration", label: "有效期", kind: "number", min: 1, max: 3650, required: true },
  {
    name: "quotaGiB",
    label: "流量配额",
    kind: "decimal",
    unit: "GiB",
    required: true,
  },
  { name: "unlimitedTraffic", label: "不限流量", kind: "switch" },
  { name: "groupId", label: "用户组", kind: "select" },
  { name: "enabled", label: "上架", kind: "switch" },
  { name: "rules", label: "转发规则上限", kind: "number", min: 0, max: 100000, unit: "条", placeholder: "不限制" },
  { name: "rateMbps", label: "用户限速", kind: "number", min: 0, max: 100000, unit: "Mbps", placeholder: "不限制" },
  { name: "maxIPs", label: "IP 数量上限", kind: "number", min: 0, unit: "个", placeholder: "不限制" },
  { name: "maxConnections", label: "连接数上限", kind: "number", min: 0, unit: "个", placeholder: "不限制" },
];
const planLimitFields = new Set(["rules", "rateMbps", "maxIPs", "maxConnections"]);

function authorizedUserGroups(group: Group) {
  const ids = group.userGroups?.length ? group.userGroups : [group.userGroup];
  return ids.filter(id => id > 0);
}

function PlanCard({ plan, actions, badge, sortControl, group, ...dragEvents }: {
  plan: Plan;
  actions: ReactNode;
  badge?: ReactNode;
  sortControl?: ReactNode;
  group?: string;
} & Pick<HTMLAttributes<HTMLElement>, "onDrop" | "onDragOver">) {
  const heading = "plan-" + plan.id;
  const period = plan.kind === "traffic" || plan.kind === "stack"
    ? "不限时" : plan.duration + (plan.kind === "month" ? " 个月" : " 天");
  return (
    <article {...dragEvents} className="shop-plan" aria-labelledby={heading}>
      <header className="shop-plan-head">
        <h3 id={heading}>{plan.name}</h3>
        {(badge || sortControl || plan.kind === "stack") && <div className="shop-plan-badges">
          {plan.kind === "stack" && <Tag>流量可叠加</Tag>}
          {badge}
          {sortControl}
        </div>}
      </header>
      <p className="shop-plan-price">{currency(plan.price)}</p>
      {plan.description && <p className="plan-description">{plan.description}</p>}
      <dl className="shop-plan-terms">
        <div><dt><CalendarDays size={16} aria-hidden="true" />有效期</dt><dd>{period}</dd></div>
        <div><dt><Gauge size={16} aria-hidden="true" />流量配额</dt><dd>{plan.unlimitedTraffic ? "不限流量" : bytes(plan.quota)}</dd></div>
        <div><dt><Workflow size={16} aria-hidden="true" />转发规则</dt><dd>{plan.rules ? plan.rules + " 条" : "不限制"}</dd></div>
        {plan.rateMbps > 0 && <div><dt><Timer size={16} aria-hidden="true" />用户限速</dt><dd>{plan.rateMbps} Mbps</dd></div>}
        {plan.maxIPs > 0 && <div><dt><Network size={16} aria-hidden="true" />IP 数量上限</dt><dd>{plan.maxIPs} 个</dd></div>}
        {plan.maxConnections > 0 && <div><dt><Link2 size={16} aria-hidden="true" />连接数上限</dt><dd>{plan.maxConnections} 个</dd></div>}
        {group && <div><dt><Server size={16} aria-hidden="true" />用户组</dt><dd>{group}</dd></div>}
      </dl>
      <footer className="shop-plan-actions">{actions}</footer>
    </article>
  );
}
const tunnelFields = groupFields.filter(field => ["name", "relayMode", "offlineSeconds"].includes(field.name));
const userFields: Field[] = [
  { name: "banned", label: "封禁", kind: "switch" },
  { name: "admin", label: "管理员", kind: "switch" },
  { name: "group", label: "用户组", kind: "select" },
  { name: "usedGiB", label: "已用流量", kind: "decimal", unit: "GiB", required: true },
  { name: "quotaGiB", label: "流量配额", kind: "decimal", unit: "GiB", required: true },
  { name: "unlimitedTraffic", label: "不限流量", kind: "switch" },
  { name: "expiresAt", label: "到期时间", kind: "date" },
  { name: "maxRules", label: "最大规则数", kind: "number" },
  { name: "rateOverride", label: "用户限速", kind: "number", unit: "Mbps", help: "留空沿用套餐，0 为不限" },
  { name: "ipsOverride", label: "用户 IP 限制", kind: "number", help: "留空沿用套餐，0 为不限" },
  { name: "connectionsOverride", label: "用户连接数限制", kind: "number", help: "留空沿用套餐，0 为不限" },
  { name: "balanceAmount", label: "钱包余额", kind: "decimal", unit: "¥", required: true },
  { name: "allowDevice", label: "允许接入个人出口", kind: "switch" },
  { name: "note", label: "备注（仅管理员可见）", kind: "area" },
];
const gib = 1024 ** 3;
const maxAccountingAmount = 2 ** 40 / 100;
const displayGiB = (bytes: number) => Number((bytes / gib).toFixed(6));
const userColumns = [
  { key: "id", label: "UID" }, { key: "name", label: "用户名" },
  { key: "expires", label: "过期时间" }, { key: "traffic", label: "流量" },
  { key: "planId", label: "套餐" }, { key: "group", label: "用户组" },
  { key: "maxRules", label: "最大规则数" }, { key: "balance", label: "钱包余额" },
  { key: "note", label: "备注" }, { key: "telegramId", label: "Telegram" },
  { key: "admin", label: "管理员" }, { key: "banned", label: "封禁" },
];
const defaultUserColumns = userColumns.slice(0, 9).map(column => column.key);

function FieldInput({ field, ...props }: { field: Field; [key: string]: any }) {
  switch (field.kind) {
    case "number":
      return <InputNumber {...props} style={{ width: "100%" }} precision={0} min={field.min} max={field.max}
        addonAfter={field.unit} placeholder={field.placeholder} />;
    case "decimal":
      return <InputNumber {...props} style={{ width: "100%" }} min={field.min ?? 0} max={field.max}
        step={field.step ?? 0.01} precision={field.precision} addonAfter={field.unit}
        formatter={field.unit === "GiB" ? (value, { userTyping, input }) => userTyping ? input : String(value ?? "") : undefined} />;
    case "date":
      return <DatePicker {...props} style={{ width: "100%" }} showTime format="YYYY-MM-DD HH:mm:ss" />;
    case "switch":
      return <Switch {...props} />;
    case "checkbox":
      return <Checkbox {...props}>{field.label}</Checkbox>;
    case "secret":
      return <Input.Password {...props} autoComplete="new-password" />;
    case "area":
      return <Input.TextArea {...props} placeholder={field.placeholder} rows={field.name === "connectHost" ? 2 : 3} />;
    case "select":
      return <Select {...props} options={field.options} placeholder={field.placeholder}
        showSearch={Boolean(field.options && field.options.length > 8)} optionFilterProp="label" />;
    case "multi":
      return (
        <MultiSelect {...props} options={field.options} placeholder={field.placeholder} optionFilterProp="label" allowClear />
      );
    case "tags":
      return <MultiSelect {...props} mode="tags" tokenSeparators={[",", "，"]} allowClear />;
    default:
      return <Input {...props} />;
  }
}

type Props = { page: string; user: User; refresh: () => Promise<void> };
const routes: Record<
  string,
  { title: string; path?: string }
> = {
  shop: {
    title: "商城",
    path: "/plans",
  },
  orders: {
    title: "我的订单",
    path: "/orders",
  },
  "admin-orders": {
    title: "订单管理",
    path: "/orders?all=1",
  },
  notifications: {
    title: "推送通知",
    path: "/notifications",
  },
  users: {
    title: "用户管理",
    path: "/admin/users",
  },
  "user-groups": {
    title: "用户组管理",
    path: "/admin/user-groups",
  },
  plans: {
    title: "套餐管理",
    path: "/plans",
  },
  redeem: {
    title: "兑换码管理",
    path: "/admin/redeem",
  },
  tunnels: {
    title: "我的单端隧道",
    path: "/groups",
  },
  groups: {
    title: "设备组管理",
    path: "/groups",
  },
  invites: {
    title: "邀请记录",
    path: "/invites?all=1",
  },
  "my-invites": {
    title: "我的邀请记录",
    path: "/invites",
  },
};

function panelOrigin(value: string): string | undefined {
  if (!/^https?:\/\/[^\s/]+\/?$/i.test(value) || /[?#\\]/.test(value)) return;
  try {
    const url = new URL(value);
    if (!url.username && !url.password && url.pathname === "/") return url.origin;
  } catch {
    return;
  }
}

export default function Management({ page, user, refresh }: Props) {
  const spec = routes[page];
  const narrow = Grid.useBreakpoint().md === false;
  const isGroupEditor = page === "groups";
  const [advancedGroup, setAdvancedGroup] = useState(false);
  const [jsonGroup, setJsonGroup] = useState<Group>();
  const [editor, setEditor] = useState<Editor>();
  const [accounting, setAccounting] = useState<AccountingPreview>();
  const [working, setWorking] = useState(false);
  const [selectedGroups, setSelectedGroups] = useState<number[]>([]);
  const [groupQuery, setGroupQuery] = useState("");
  const [groupType, setGroupType] = useState("");
  const [groupOwner, setGroupOwner] = useState("");
  const [folderFilter, setFolderFilter] = useState<string>();
  const [selectedOrders, setSelectedOrders] = useState<React.Key[]>([]);
  const [selectedCodes, setSelectedCodes] = useState<React.Key[]>([]);
  const [draggedID, setDraggedID] = useState<number>();
  const [orderQuery, setOrderQuery] = useState("");
  const [orderKind, setOrderKind] = useState("");
  const [orderStatus, setOrderStatus] = useState("");
  const [orderPage, setOrderPage] = useState(0);
  const [userSearch, setUserSearch] = useState("");
  const [userRole, setUserRole] = useState("");
  const [userBanned, setUserBanned] = useState("");
  const [userSort, setUserSort] = useState("");
  const [userDirection, setUserDirection] = useState<"asc" | "desc" | "">("");
  const [userPage, setUserPage] = useState(0);
  const [userPageSize, setUserPageSize] = useState(10);
  const [userGroupFilter, setUserGroupFilter] = useState("");
  const [userPlanFilter, setUserPlanFilter] = useState("");
  const columnPreference = "hopx.users.columns." + user.id;
  const [columnsOpen, setColumnsOpen] = useState(false);
  const [visibleUserColumns, setVisibleUserColumns] = useState<string[]>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(columnPreference) || "null") as unknown;
      if (Array.isArray(saved)) return userColumns.filter(column => saved.includes(column.key)).map(column => column.key);
    } catch { /* Use defaults when storage is unavailable. */ }
    return defaultUserColumns;
  });
  const [configSummary, setConfigSummary] = useState<GroupConfig & { groupName: string }>();
  const userPlans = useData<Plan[]>((page === "users" || page === "redeem") ? "/plans" : null, []);
  const [voucherQuote, setVoucherQuote] = useState<{ code: string; name: string; price: number; payable: number }>();
  const [checkoutForm] = Form.useForm<{amount:number;channel:string;gateway:string}>();
  const shopSite = useData<{ paymentChannels?: PaymentOption[]; minRecharge?: string }>("/site", {});
  const paymentGateways = shopSite.value.paymentChannels || [];
  const gatewayID = Form.useWatch("gateway", checkoutForm) || paymentGateways[0]?.id;
  const gateway = paymentGateways.find(({ id }) => id === gatewayID);
  const checkoutAmount = Math.round((Form.useWatch("amount", checkoutForm) || 0) * 100);
  const minimumRecharge = Number(shopSite.value.minRecharge || 100);
  const paymentRate = gateway?.fee || 0;
  const checkoutFee = Math.round(checkoutAmount * paymentRate / 10000);
  const [enroll, setEnroll] = useState<{
    token: string;
    groupName: string;
    relay: boolean;
    reverseIngress?: boolean;
    reverseEgress?: boolean;
  }>();
  const [relayAddress, setRelayAddress] = useState("");
  const [reverseAddress,setReverseAddress]=useState("");
  const [reverseOnly,setReverseOnly]=useState(false);
  const [relayTransport, setRelayTransport] = useState("tls");
  const [offlineInstall, setOfflineInstall] = useState(false);
  const [customPanel, setCustomPanel] = useState("");
  const [bindAddresses, setBindAddresses] = useState("");
  const [nodeInstance, setNodeInstance] = useState("");
  const [planPage, setPlanPage] = useState(1);
  const [udpSmartBind, setUDPSmartBind] = useState(false);
  const [enrollAdvanced, setEnrollAdvanced] = useState(false);
  const [groupDetail, setGroupDetail] = useState<Group>();
  const [nodes, setNodes] = useState<Node[]>([]);
  const [form] = Form.useForm<Row>();
  const editingKind = Form.useWatch("kind", form);
  const planUsesPeriod = editingKind !== "traffic" && editingKind !== "stack";
  const editingPlan = editor?.fields === planFields;
  const unlimitedTraffic = Form.useWatch("unlimitedTraffic", form);
  const assignedPlan = Form.useWatch("planId", form);
  const editingUserPlan = editor?.path.endsWith("/plan");
  const pushingPlan = editor?.path.endsWith("/push");
  const editingUser = editor?.fields === userFields;
  const customReferral = Form.useWatch("custom", form);
  const { message, modal } = App.useApp();
  const confirmAction = useConfirmAction();
  const isAffiliatePage = page === "invites" || page === "my-invites";
  const [affiliateTab, setAffiliateTab] = useState("ledger");
  const ledger = isAffiliatePage && affiliateTab === "ledger";
  const adminOrders = page === "admin-orders" || (page === "invites" && ledger);
  const isOrderPage = page === "orders" || page === "admin-orders" || ledger;
  const orderParams = new URLSearchParams({ all: adminOrders ? "1" : "0", affiliate: ledger ? "1" : "0", q: orderQuery, kind: orderKind, status: orderStatus, limit: "51", offset: String(orderPage * 50) });
  const userFilters = new URLSearchParams({ q: userSearch, role: userRole, banned: userBanned, group: userGroupFilter, plan: userPlanFilter });
  const userParams = new URLSearchParams(userFilters);
  userParams.set("sort", userSort);
  userParams.set("direction", userDirection);
  userParams.set("limit", String(userPageSize));
  userParams.set("offset", String(userPage * userPageSize));
  const dataPath = isOrderPage ? "/orders?" + orderParams : page === "users" ? "/admin/users?" + userParams : spec?.path || "/me";
  const isPaged = isOrderPage || page === "users";
  const data = useData<Row[] | Row>(dataPath, []);
  const userTotal = useData<{ total: number }>(page === "users" ? "/admin/users/count?" + userFilters : null, { total: 0 });
  useEffect(() => {
    if (page === "users" && !userTotal.busy && !userTotal.error) {
      const lastPage = Math.max(0, Math.ceil(userTotal.value.total / userPageSize) - 1);
      if (userPage > lastPage) setUserPage(lastPage);
    }
  }, [page, userPage, userPageSize, userTotal.busy, userTotal.error, userTotal.value.total]);
  const list = Array.isArray(data.value)
    ? data.value.filter((row) => page !== "tunnels" || row.owner === user.id)
    : [];
  const deviceFolders = useData<{ name: string; count: number }[]>(isGroupEditor ? "/admin/groups/folders" : null, []);
  const folderCounts = new Map(deviceFolders.value.map(folder => [folder.name, folder.count]));
  const equipmentQuery = groupQuery.trim().toLowerCase();
  const visibleGroups = isGroupEditor ? list.filter(row => {
    const folderMatches = folderFilter === undefined || (folderFilter !== "" && !folderCounts.has(folderFilter)) || (row.folder || "") === folderFilter;
    const ownershipMatches = !groupOwner || (groupOwner === "personal" ? row.owner > 0 : row.owner === 0);
    const textMatches = !equipmentQuery || [row.id, row.name, row.connectHost, row.note].some(value => value != null && String(value).toLowerCase().includes(equipmentQuery));
    return folderMatches && ownershipMatches && textMatches && (!groupType || groupKindCategory(row.kind) === groupType);
  }) : list;
  const isTunnel = page === "tunnels";
  const groupTotals = useData<Record<number, {online: number; devices: number; traffic: number}>>(
    isGroupEditor || isTunnel ? "/groups/totals" : null, {},
  );
  const groupUsers = useData<{ id: number; name: string }[]>(
    (page === "groups" || page === "users" || page === "plans") ? "/admin/user-groups" : null,
    [],
  );
  const groupAPI = isTunnel ? "/tunnels" : "/admin/groups";
  const offlineNotice = useData<OfflineNotice>(page === "notifications" ? "/admin/notifications/offline" : null, { default: 0, groups: {} });
  const noticeGroups = useData<Group[]>(page === "notifications" ? "/groups" : null, []);
  const [noticeDraft, setNoticeDraft] = useState<OfflineNotice>();
  const noticeConfig = noticeDraft ?? offlineNotice.value;
  const chainFields: Field[] = [
    ...groupFields,
    ...ingressFields,
    {
      name: "allowedFrom", label: "允许的上游组", kind: "multi",
      options: list.map(group => ({value: group.id, label: group.name})),
    },
    {
      name: "allowedTo", label: "允许的出口", kind: "multi", placeholder: "留空时不限制",
      options: list.map(group => ({value: group.id, label: group.name})),
    },
    {
      name: "reverseGroups", label: "首跳要求反向接入的组", kind: "multi",
      options: [{ value: 0, label: "全部出口（其他选项作为例外）" }, ...list
        .filter(group => ["exit", "relay", "both"].includes(group.kind))
        .map(group => ({value: group.id, label: group.name}))],
    },
    {
      name: "ipv6Groups",
      path: ["routing", "ipv6Groups"],
      label: "优先走 IPv6 的设备组",
      kind: "multi",
      options: [
        { value: 0, label: "全部出口（其他选项作为例外）" },
        ...list.filter((group) => ["exit", "relay", "both"].includes(group.kind))
          .map((group) => ({ value: group.id, label: group.name })),
      ],
    },
    { name: "addressMode", path: ["routing", "addressMode"], label: "出口连接地址", kind: "select", options: [
      { value: "", label: "自动" },
      { value: "ipv4", label: "强制 IPv4" },
      { value: "ipv6", label: "强制 IPv6" },
      { value: "static", label: "固定地址" },
    ] },
    { name: "applyRelayMode", path: ["routing", "applyRelayMode"], label: "向已接入节点下发设备组协议", kind: "switch" },
    { name: "nativeUDP", path: ["routing", "nativeUDP"], label: "单跳原生 UDP（出口开放同端口 UDP）", kind: "switch" },
    { name: "staticAddress", path: ["routing", "staticAddress"], label: "固定出口地址（单节点，主机:端口）" },
    { name: "maxFailures", path: ["routing", "maxFailures"], label: "切换前连续失败次数（0 为关闭）", kind: "number" },
    { name: "recoverySeconds", path: ["routing", "recoverySeconds"], label: "失败线路恢复间隔（秒，默认 30）", kind: "number" },
    {
      name: "fallbackGroup",
      label: "默认备用出口",
      kind: "select",
      options: [{ value: 0, label: "未设置" }, ...list
        .filter((group) => ["exit", "both", "chain"].includes(group.kind) && !group.owner)
        .map((group) => ({ value: group.id, label: group.name }))],
    },
    {
      name: "userGroups",
      label: "授权用户组",
      placeholder: "留空时不授权",
      kind: "multi",
      options: Array.isArray(groupUsers.value)
        ? groupUsers.value.filter(g => g.id > 0).map(g => ({ value: g.id, label: g.name }))
        : [],
    },
    {
      name: "chain",
      label: "出口链路",
      help: "按转发顺序选择设备组，最后一跳选出口。",
      kind: "multi",
      required: true,
      options: list
        .filter((g) => ["exit", "relay", "both"].includes(g.kind) && !g.owner)
        .map((g) => ({ value: g.id, label: g.name })),
    },
  ];

  function edit(
    title: string,
    path: string,
    method: string,
    fields: Field[],
    value: Row = {},
  ) {
    form.resetFields();
    form.setFieldsValue(value);
    setAccounting(undefined);
    setAdvancedGroup(false);
    setEditor({ title, path, method, fields, value });
  }

  function editPlan(plan?: Plan) {
    edit(plan ? "编辑套餐" : "添加套餐", "/admin/plans" + (plan ? "/" + plan.id : ""), plan ? "PUT" : "POST", planFields, {
      kind: "day", enabled: true, duration: 30, groupId: 0, unlimitedTraffic: false,
      ...plan,
      rules: plan?.rules || undefined,
      rateMbps: plan?.rateMbps || undefined,
      maxIPs: plan?.maxIPs || undefined,
      maxConnections: plan?.maxConnections || undefined,
      priceAmount: (plan?.price || 0) / 100,
      quotaGiB: displayGiB(plan?.quota || 0),
    });
  }

  async function action(
    path: string,
    method: string,
    values?: unknown,
    label = "操作成功",
  ) {
    try {
      await api(path, method, values);
      await Promise.all([data.reload(), refresh(), groupTotals.reload(), deviceFolders.reload(), userTotal.reload()]);
      message.success(label);
      return true;
    } catch (e) {
      message.error((e as Error).message);
      return false;
    }
  }

  async function saveOfflineNotice() {
    if (!noticeDraft) return;
    setWorking(true);
    try {
      await api("/admin/notifications/offline", "PUT", noticeDraft);
      await offlineNotice.reload();
      setNoticeDraft(undefined);
      message.success("离线通知已保存");
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setWorking(false);
    }
  }

  async function submit(value: Row) {
    if (!editor) return;
    setWorking(true);
    const payload = { ...editor.value, ...value };
    if (editor.path === "/admin/credit" || editor.path === "/admin/affiliate/credit") {
      try {
        if (!accounting) {
          const values = { userId: payload.userId, amount: Math.round(payload.amount * 100), description: payload.description };
          const quote = await api<Omit<AccountingPreview, "values">>("/admin/accounting/preview", "POST", { ...values, affiliate: ledger });
          setAccounting({ ...quote, values });
        } else if (await action(editor.path, editor.method, { ...accounting.values, expectedBalance: accounting.balance })) {
          setEditor(undefined);
          setAccounting(undefined);
        }
      } catch (error) {
        message.error((error as Error).message);
      } finally {
        setWorking(false);
      }
      return;
    }
    if (editor.fields === userFields) {
      const original = editor.value;
      const { usedGiB, quotaGiB, expiresAt, balanceAmount } = value;
      delete payload.usedGiB;
      delete payload.quotaGiB;
      delete payload.expiresAt;
      delete payload.balanceAmount;
      payload.expires = expiresAt?.unix() ?? 0;
      if (payload.unlimitedTraffic) payload.quota = 0;
      else if (quotaGiB !== original.quotaGiB) payload.quota = Math.round(quotaGiB * gib);
      if (usedGiB !== original.usedGiB) payload.usageAdjustment = {
        from: original.used, to: Math.round(usedGiB * gib), epoch: original.quotaEpoch,
      };
      if (balanceAmount !== original.balanceAmount) payload.balanceAdjustment = {
        from: original.balance, to: Math.round(balanceAmount * 100),
      };
    }
    if (editor.fields === planFields) {
      payload.price = Math.round(value.priceAmount * 100);
      for (const field of planLimitFields) payload[field] = value[field] ?? 0;
      if (payload.unlimitedTraffic) payload.quota = 0;
      else if (value.quotaGiB !== editor.value.quotaGiB || !editor.value.id) payload.quota = Math.round(value.quotaGiB * gib);
      if (!planUsesPeriod) payload.duration = 1;
      delete payload.priceAmount;
      delete payload.quotaGiB;
    }
    if (editingUserPlan && !payload.planId) {
      for (const key of ["quota", "group", "rules", "limits", "expires"]) payload[key] = false;
    }
    if (editor.path.endsWith("/referral")) {
      payload.rate = Math.round((payload.ratePercent ?? 0) * 100);
      delete payload.ratePercent;
    }
    if (page === "groups") payload.userGroup = 0;
    if (editor.path === "/admin/redeem/batch") {
      payload.codes = String(value.codes || "").split(/\r?\n/).map(code => code.trim()).filter(Boolean);
      payload.discount = Math.round((100 - value.payablePercent) * 100);
      payload.expiry = value.validUntil?.unix();
      delete payload.payablePercent;
      delete payload.validUntil;
    }
    if (await action(editor.path, editor.method, payload)) {
      setEditor(undefined);
      if (editor.path.startsWith("/nodes/") && groupDetail) await groupNodes(groupDetail);
      if (editor.path === "/admin/groups/folders") {
        setSelectedGroups([]);
        if (folderFilter !== undefined) setFolderFilter(String(payload.name || "").trim());
      }
    }
    setWorking(false);
  }

  async function previewVoucher(code: string) {
    setVoucherQuote(undefined);
    setWorking(true);
    try {
      const quote = await api<{ name: string; price: number; payable: number }>("/redeem/preview", "POST", { code });
      setVoucherQuote({ ...quote, code });
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setWorking(false);
    }
  }

  async function redeemVoucher() {
    if (!voucherQuote) return;
    setWorking(true);
    if (await action("/redeem", "POST", { code: voucherQuote.code, expectedPayable: voucherQuote.payable }, "兑换成功")) {
      setVoucherQuote(undefined);
    }
    setWorking(false);
  }

  async function pay(value:{amount:number;channel:string;gateway:string}) {
    setWorking(true);
    try {
      const result = await api<{ url: string; qr?: boolean }>(
        "/payment/checkout",
        "POST",
        { ...value, gateway: value.gateway || gatewayID, amount: Math.round(value.amount * 100) },
      );
      if (result.qr) {
        showPaymentQR(result.url);
      } else {
        window.location.assign(result.url);
      }
    } catch (e) {
      message.error((e as Error).message);
    } finally {
      setWorking(false);
    }
  }

  function showPaymentQR(url: string) {
    modal.info({
      title: "请扫码支付",
      width: 360,
      icon: null,
      okText: "关闭",
      content: <QRCode className="dialog-qr" value={url} size={208} color="#16251d" bgColor="#ffffff" aria-label="支付二维码" />,
    });
  }

  async function resumePayment(id:number){
    try{
      const result = await api<{url: string; qr?: boolean}>("/orders/" + id + "/checkout", "POST");
      if (result.qr) {
        showPaymentQR(result.url);
      } else {
        window.location.assign(result.url);
      }
    }catch(e){message.error((e as Error).message)}
  }

  function confirm(
    title: string,
    path: string,
    method = "DELETE",
    value?: unknown,
  ) {
    confirmAction({
      title,
      okText: "确认",
      okButtonProps: { danger: method === "DELETE" },
      onOk: () => action(path, method, value),
    });
  }

  async function enlist(group: Group) {
    try {
      setRelayAddress("");
      setBindAddresses("");
      setNodeInstance("");
      setUDPSmartBind(false);
      setEnrollAdvanced(false);
      setOfflineInstall(false);
      setCustomPanel("");
      setReverseAddress("");
      setReverseOnly(false);
      setRelayTransport(group.relayMode || "tls");
      setEnroll(await api(groupAPI + "/" + group.id + "/enrollment", "POST"));
    } catch (e) {
      message.error((e as Error).message);
    }
  }

  async function inspectGroup(group: Group) {
    try {
      const config = await api<GroupConfig>("/groups/" + group.id + "/configuration");
      setConfigSummary({ ...config, groupName: group.name });
    }
    catch (error) { message.error((error as Error).message); }
  }

  async function groupNodes(group: Group) {
    try {
      const data = await api<Node[]>("/groups/" + group.id + "/devices");
      setNodes(data);
      setGroupDetail(group);
    } catch (e) {
      message.error((e as Error).message);
    }
  }

  const reorderPaths: Record<string, string> = {
    groups: "/admin/groups/reorder", plans: "/admin/plans/reorder", "user-groups": "/admin/user-groups/reorder",
  };
  function reorder(from: number, to: number) {
    const ids = list.map((row) => Number(row.id));
    const fromIndex = ids.indexOf(from), toIndex = ids.indexOf(to);
    if (fromIndex < 0 || toIndex < 0 || fromIndex === toIndex) return;
    ids.splice(fromIndex, 1);
    ids.splice(toIndex, 0, from);
    void action(reorderPaths[page], "POST", { ids }, "排序已保存");
  }

  function dropTarget(id: number): Pick<HTMLAttributes<HTMLElement>, "onDragOver" | "onDrop"> {
    return {
      onDragOver: event => { if (draggedID !== undefined) event.preventDefault(); },
      onDrop: event => {
        event.preventDefault();
        if (draggedID !== undefined) reorder(draggedID, id);
        setDraggedID(undefined);
      },
    };
  }

  function sortHandle(row: { id: number; name: string; showOrder?: number }, index: number, siblings: readonly { id: number }[]) {
    return <button className="sort-handle" type="button" title="拖动排序，或用方向键移动"
      aria-label={"调整 " + row.name + " 的顺序"} draggable
      onDragStart={event => { event.dataTransfer.setData("text/plain", String(row.id)); setDraggedID(row.id); }}
      onDragEnd={() => setDraggedID(undefined)}
      onKeyDown={event => {
        if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
        event.preventDefault();
        const current = siblings.findIndex(item => item.id === row.id);
        const adjacent = siblings[current + (event.key === "ArrowUp" ? -1 : 1)];
        if (adjacent) reorder(row.id, adjacent.id);
      }}><GripVertical size={15} aria-hidden="true" /><span>{row.showOrder || index + 1}</span></button>;
  }

  function table(columns: any[], toolbar?: React.ReactNode) {
    const shownColumns = page === "users" && !narrow
      ? columns.filter(column => column.key === "action" || visibleUserColumns.includes(column.dataIndex || column.key))
      : columns;
    const tableRows = isPaged ? list.slice(0, isOrderPage ? 50 : userPageSize) : visibleGroups;
    function saveUserColumns(keys: string[]) {
      setVisibleUserColumns(keys);
      try { localStorage.setItem(columnPreference, JSON.stringify(keys)); }
      catch { /* The current tab can still use the selection. */ }
    }
    const orderKinds = ledger ? ["referral", "affiliate_transfer", "affiliate_manual", "legacy_affiliate"] :
      ["purchase", "renew", "redeem", "epay", "epusdt", "tokenpay", "cryptomus", "manual", "transfer"];
    const groupActions = page === "groups" ? [
      { key: "move", label: "分组", disabled: !selectedGroups.length, onClick: () => edit("批量分组", "/admin/groups/folders", "PUT", [
        { name: "name", label: "分组名称", help: "留空可移到未分组" },
      ], { ids: selectedGroups, name: folderFilter || "" }) },
      { key: "folders", label: "管理分组", disabled: folderCounts.size === Number(folderCounts.has("")), onClick: () => edit("管理分组", "/admin/groups/folders", "PUT", [
        { name: "from", label: "现有分组", kind: "select", required: true,
          options: [...folderCounts.keys()].filter(Boolean).map(name => ({ value: name, label: name })) },
        { name: "name", label: "新名称", help: "填已有分组名称可合并，留空可移到未分组" },
      ], { from: folderFilter || undefined, name: "" }) },
      { key: "traffic", label: "清空流量", disabled: !selectedGroups.some(id => list.some(row => row.id === id && ["entry", "both"].includes(row.kind))),
        onClick: () => confirmAction({
          title: "清空所选入口设备组的流量统计？",
          onOk: async () => {
            const saved = await action("/admin/groups/clear-traffic", "POST", { ids: selectedGroups });
            if (saved) setSelectedGroups([]);
            return saved;
          },
        }) },
    ] : [];
    return (
      <section className="table-section panel-table">
        <header className="page-head">
          <h1>{spec.title}</h1>
          {page === "users" ? !narrow && <Dropdown
            trigger={["click"]}
            placement="bottomRight"
            open={columnsOpen}
            onOpenChange={setColumnsOpen}
            autoFocus
            destroyOnHidden
            popupRender={() => (
              <div id="user-column-picker" className="column-picker" role="group" aria-label="显示列" tabIndex={-1}
                onKeyDown={event => { if (event.key === "Tab") event.stopPropagation(); }}>
                <Checkbox.Group value={visibleUserColumns} onChange={saveUserColumns}>
                  {userColumns.map(({ key, label }) => (
                    <Checkbox key={key} value={key}>{label}</Checkbox>
                  ))}
                </Checkbox.Group>
              </div>
            )}
          >
            <Button size="small" icon={<Settings2 size={14} />} aria-expanded={columnsOpen}
              aria-controls={columnsOpen ? "user-column-picker" : undefined}>显示列</Button>
          </Dropdown> : toolbar}
        </header>
        {isAffiliatePage && <Tabs activeKey={affiliateTab} onChange={key => {
          setAffiliateTab(key);
          setOrderQuery("");
          setOrderKind("");
          setOrderStatus("");
          setOrderPage(0);
          setSelectedOrders([]);
        }} items={[{key: "ledger", label: "佣金账单"}, {key: "registrations", label: "邀请注册"}]} />}
        {page === "users" && <div className="operator-toolbar">
          <div className="operator-actions">{toolbar}</div>
          <Space wrap={!narrow} className="operator-filters user-filters">
            <Input.Search allowClear placeholder="用户名或用户 ID" onSearch={value => { setUserSearch(value); setUserPage(0); }} />
            <Select aria-label="账号角色" value={userRole} onChange={value => { setUserRole(value); setUserPage(0); }} options={[
              { value: "", label: "全部角色" }, { value: "admin", label: "管理员" }, { value: "member", label: "普通用户" },
            ]} />
            <Select aria-label="封禁状态" value={userBanned} onChange={value => { setUserBanned(value); setUserPage(0); }} options={[
              { value: "", label: "全部状态" }, { value: "false", label: "正常" }, { value: "true", label: "封禁" },
            ]} />
            <Select aria-label="账号排序" value={userSort} onChange={value => { setUserSort(value); setUserDirection(value === "name" ? "asc" : value ? "desc" : ""); setUserPage(0); }} options={[
              { value: "", label: "最新注册" }, { value: "id", label: "用户 ID" }, { value: "name", label: "用户名" }, { value: "expires", label: "到期时间" },
              { value: "traffic", label: "已用流量" }, { value: "balance", label: "钱包余额" }, { value: "rules", label: "最大规则数" },
            ]} />
            <Select aria-label="套餐筛选" popupMatchSelectWidth={220} value={userPlanFilter} onChange={value => { setUserPlanFilter(value); setUserPage(0); }} options={[
              { value: "", label: "全部套餐" }, { value: "0", label: "无套餐" }, ...userPlans.value.map(plan => ({ value: String(plan.id), label: plan.name })),
            ]} />
            <Select aria-label="用户组筛选" popupMatchSelectWidth={220} value={userGroupFilter} onChange={value => { setUserGroupFilter(value); setUserPage(0); }} options={[
              { value: "", label: "全部用户组" }, ...groupUsers.value.map(group => ({ value: String(group.id), label: group.name })),
            ]} />
          </Space>
        </div>}
        {isOrderPage && <Space wrap={!narrow} className="list-toolbar">
          <Input.Search allowClear placeholder={adminOrders ? "订单号、用户名或 UID" : "订单号"} onSearch={value => { setOrderQuery(value.trim()); setOrderPage(0); }} />
          <Select aria-label="订单类型" value={orderKind} onChange={value => { setOrderKind(value); setOrderPage(0); }} options={[
            { value: "", label: "全部类型" }, ...orderKinds.map(value => ({ value, label: labels[value] || value })),
          ]} />
          <Select aria-label="订单状态" value={orderStatus} onChange={value => { setOrderStatus(value); setOrderPage(0); }} options={[
            { value: "", label: "全部状态" }, { value: "pending", label: "待支付" }, { value: "paid", label: "已支付" },
          ]} />
          {adminOrders && <Button disabled={!selectedOrders.length}
            onClick={() => confirmAction({ title: "移除选中的订单？", content: "账务记录会保留，可继续处理已创建的支付回调。",
              onOk: async () => {
                const saved = await action("/admin/orders/archive", "POST", { ids: selectedOrders.map(Number) });
                if (saved) setSelectedOrders([]);
                return saved;
              } })}>删除选中</Button>}
        </Space>}
        {page === "redeem" && <Space wrap={!narrow} className="list-toolbar">
          <Button disabled={!selectedCodes.length} onClick={() => confirmAction({ title: "删除选中的兑换码？",
            onOk: async () => {
              const saved = await action("/admin/redeem/batch", "POST", { codes: selectedCodes, delete: true });
              if (saved) setSelectedCodes([]);
              return saved;
            } })}>删除选中</Button>
        </Space>}
        {page === "groups" && <>
          <Tabs activeKey={folderFilter === undefined || (folderFilter && !folderCounts.has(folderFilter)) ? "all" : "folder:" + folderFilter} onChange={key => {
            setFolderFilter(key === "all" ? undefined : key.slice(7));
            setSelectedGroups([]);
          }} items={[
            { key: "all", label: "全部" },
            { key: "folder:", label: `未分组 (${folderCounts.get("") || 0})` },
            ...[...folderCounts].filter(([name]) => name).map(([name, count]) => ({ key: "folder:" + name, label: `${name} (${count})` })),
          ]} />
          <div className="operator-toolbar">
            <Space wrap={!narrow} className="operator-actions">
              <Button onClick={() => edit("新增分组", "/admin/groups/folders", "PUT", [
                { name: "name", label: "分组名称", required: true },
              ])}>新增分组</Button>
              {narrow ? <Dropdown trigger={["click"]} menu={{ items: groupActions }}>
                <Button icon={<Ellipsis size={17} />}>更多操作</Button>
              </Dropdown> : groupActions.map(({ key, label, disabled, onClick }) => (
                <Button key={key} disabled={disabled} onClick={onClick}>{label}</Button>
              ))}
              <RefreshButton reload={[data.reload, groupTotals.reload, deviceFolders.reload]} />
              {selectedGroups.length > 0 && <Tag>已选 {selectedGroups.length} 个设备组</Tag>}
            </Space>
            <Space wrap={!narrow} className="operator-filters">
              <Input aria-label="搜索设备组" placeholder="名称、ID 或地址" allowClear value={groupQuery}
                onChange={event => { setGroupQuery(event.target.value); setSelectedGroups([]); }} />
              <Select aria-label="设备组类型" value={groupType} onChange={value => { setGroupType(value); setSelectedGroups([]); }}
                options={[{ value: "", label: "全部类型" }, ...groupKinds]} />
              <Select aria-label="设备组归属" value={groupOwner} onChange={value => { setGroupOwner(value); setSelectedGroups([]); }}
                options={[{ value: "", label: "全部归属" }, { value: "site", label: "站点设备组" }, { value: "personal", label: "用户单端隧道" }]} />
            </Space>
          </div>
        </>}
        <Table<Row>
          onChange={page === "users" ? (_, __, sorter) => {
            const active = Array.isArray(sorter) ? sorter[0] : sorter;
            if (active?.order) {
              setUserSort(String(active.columnKey));
              setUserDirection(active.order === "ascend" ? "asc" : "desc");
            } else {
              setUserSort("");
              setUserDirection("");
            }
            setUserPage(0);
          } : undefined}
          rowSelection={page === "groups" ? {
            selectedRowKeys: selectedGroups,
            onChange: (keys) => setSelectedGroups(keys.map(Number)),
          } : page === "redeem" ? {
            selectedRowKeys: selectedCodes, onChange: setSelectedCodes,
          } : adminOrders ? {
            selectedRowKeys: selectedOrders, onChange: setSelectedOrders,
          } : undefined}
          onRow={reorderPaths[page] ? row => dropTarget(row.id) : undefined}
          size="middle"
          rowKey={(r) => r.id ?? r.code}
          loading={data.busy}
          locale={{ emptyText: data.busy ? " " : <div className="muted">{data.error ? "加载失败" : "没有可显示的记录"}</div> }}
          dataSource={tableRows}
          showHeader={!narrow || tableRows.length > 0}
          columns={reorderPaths[page] ? [{
            title: "排序", key: "order", width: 80,
            render: (_: unknown, row: Row, index: number) => sortHandle({ id: row.id, name: row.name, showOrder: row.showOrder }, index, visibleGroups),
          }, ...shownColumns] : shownColumns}
          scroll={narrow && !tableRows.length ? undefined : { x: page === "users" ? Math.max(650, shownColumns.length * 96 + 100) : narrow && (isGroupEditor || isTunnel) ? 980 : 620 }}
          pagination={isPaged ? false : { pageSize: 15, hideOnSinglePage: true }}
        />
        {page === "users" && <Pagination className="table-footer page-controls" size="small"
          current={userPage + 1} total={userTotal.value.total} pageSize={userPageSize}
          showTotal={total => `共 ${total} 位用户`} showSizeChanger pageSizeOptions={[10, 20, 50, 100, 200, 500]}
          onChange={(nextPage, nextSize) => { setUserPage(nextSize === userPageSize ? nextPage - 1 : 0); setUserPageSize(nextSize); }} />}
        {page === "users" && userTotal.error && <Alert type="error" showIcon message={userTotal.error} />}
        {isOrderPage && <Space className="table-footer page-controls" wrap>
          <Button disabled={orderPage === 0 || data.busy} onClick={() => setOrderPage(value => value - 1)}>上一页</Button>
          <span>第 {orderPage + 1} 页</span>
          <Button disabled={list.length <= 50 || data.busy} onClick={() => setOrderPage(value => value + 1)}>下一页</Button>
        </Space>}
      </section>
    );
  }

  function render() {
    switch (page) {
      case "shop": {
        const plans = (list as Plan[]).filter(plan => plan.enabled);
        return (
          <div className="shop-layout">
            <section className="shop-catalog" aria-labelledby="shop-plans">
              <h2 id="shop-plans">购买套餐</h2>
              {plans.length > 0 ? (
                <div className="shop-plan-grid">
                  {plans.map(plan => (
                    <PlanCard key={plan.id} plan={plan} actions={
                      <Button type="primary" block onClick={() => confirm("购买 " + plan.name + "？", "/plans/" + plan.id + "/buy", "POST")}>
                        购买套餐
                      </Button>
                    } />
                  ))}
                </div>
              ) : !data.error && <div className="shop-empty" role="status">
                {data.busy ? <><Spin size="small" />正在加载套餐</> : <><ShoppingBag size={20} aria-hidden="true" />暂无可购买套餐</>}
              </div>}
            </section>
            <aside className="shop-tools">
              <section className="shop-tool" aria-labelledby="shop-wallet">
                <h2 id="shop-wallet"><Wallet size={17} aria-hidden="true" />我的钱包</h2>
                <p className="shop-wallet-balance">{currency(user.balance)}</p>
                {paymentGateways.length > 0 ? <Form layout="vertical" form={checkoutForm} onFinish={pay}
                  initialValues={{ amount: Math.max(1000, minimumRecharge) / 100, channel: "alipay" }}>
                  <div className="shop-payment-fields">
                    <Form.Item name="amount" label="充值金额" rules={[{ required: true, type: "number", min: minimumRecharge / 100 }]}>
                      <InputNumber prefix="¥" min={minimumRecharge / 100} max={1000000} precision={2} step={0.01} style={{ width: "100%" }} />
                    </Form.Item>
                    <Form.Item label="支付通道">
                      <Select value={gatewayID} options={paymentGateways.map(option => ({
                        value: option.id,
                        label: (option.name || paymentKinds[option.kind] || option.kind) + (option.fee > 0 ? " · " + option.fee / 100 + "% 手续费" : ""),
                      }))} onChange={value => checkoutForm.setFieldValue("gateway", value)} />
                      <Form.Item name="gateway" hidden><Input /></Form.Item>
                    </Form.Item>
                    {gateway?.kind === "epay" && <Form.Item name="channel" label="支付方式" rules={[{required:true}]}>
                      <Select options={[{value:"alipay",label:"支付宝"}, {value:"wxpay",label:"微信支付"}, {value:"qqpay",label:"QQ 钱包"}]} />
                    </Form.Item>}
                  </div>
                  <Space wrap>
                    <Button htmlType="submit" type="primary" loading={working}>充值</Button>
                    {paymentRate > 0 && <span className="muted">手续费 {currency(checkoutFee)} · 合计 {currency(checkoutAmount + checkoutFee)}</span>}
                  </Space>
                </Form> : <p className="muted">
                  {shopSite.busy ? "正在读取支付通道" : shopSite.error ? "无法加载支付通道" : "暂无可用支付通道"}
                </p>}
              </section>
              <section className="shop-tool" aria-labelledby="shop-voucher">
                <h2 id="shop-voucher"><Ticket size={17} aria-hidden="true" />兑换套餐</h2>
                <Form className="shop-voucher-form" layout="vertical" onFinish={(values: {code: string}) => void previewVoucher(values.code)}
                  onValuesChange={() => setVoucherQuote(undefined)}>
                  <Form.Item name="code" rules={[{required:true,whitespace:true}]}>
                    <Input aria-label="兑换码" prefix={<Ticket size={15} />} placeholder="兑换码" allowClear />
                  </Form.Item>
                  <Button htmlType="submit" loading={working} block>查询兑换详情</Button>
                </Form>
                {voucherQuote && <div className="voucher-quote">
                  <Descriptions size="small" column={1} items={[
                    { key: "plan", label: "套餐", children: voucherQuote.name },
                    { key: "price", label: "原价", children: currency(voucherQuote.price) },
                    { key: "payable", label: "余额支付", children: currency(voucherQuote.payable) },
                  ]} />
                  <Button type="primary" loading={working} onClick={() => void redeemVoucher()}>确认兑换</Button>
                </div>}
              </section>
            </aside>
          </div>
        );
      }
      case "my-invites":
      case "invites":
        if (!ledger) return table([
          { title: "用户 ID", dataIndex: "id" },
          { title: "账号", dataIndex: "name" },
          { title: "邀请者 ID", dataIndex: "inviter" },
          { title: "注册时间", dataIndex: "created", render: date },
        ]);
        // The commission ledger uses the same order controls.
        // falls through
      case "orders":
      case "admin-orders":
        return table(
          [
            { title: "订单号", dataIndex: "reference", render: (value: string, row: Row) => value || "#" + row.id },
            ...(adminOrders
              ? [{ title: "用户", dataIndex: "userName", render: (name: string, row: Row) => <a href={"#/rules?owner=" + row.userId}>{name} (#{row.userId})</a> }]
              : []),
            {
              title: "类型",
              dataIndex: "kind",
              render: (v: string) => labels[v] || v,
            },
            { title: "说明", dataIndex: "description" },
            { title: "金额", dataIndex: "amount", render: currency },
            {
              title: "状态",
              dataIndex: "status",
              render: (v: string) => (
                <Tag color={v === "paid" ? "green" : "orange"}>
                  {labels[v] || v}
                </Tag>
              ),
            },
            { title: "创建时间", dataIndex: "created", render: date },
            { title: "支付时间", dataIndex: "paidAt", render: date },
            {
              title:"操作",
              key:"operation",
              render: (_: unknown, row: Row) => <Space className={narrow ? "row-actions" : undefined} wrap={!narrow}>
                {["epay", "epusdt", "tokenpay", "cryptomus"].includes(row.kind) && row.status === "pending" &&
                  (adminOrders ? <Button size="small" onClick={() => confirm("确认已核实入账并补单？", "/admin/orders/" + row.id + "/settle", "POST")}>补单</Button> :
                    <Button size="small" onClick={() => void resumePayment(row.id)}>继续支付</Button>)}
                {adminOrders && <Button size="small" onClick={() => confirm("移除此订单？", "/admin/orders/archive", "POST", { ids: [row.id] })}>删除</Button>}
              </Space>
            },
          ],
          adminOrders ? (
            <Button
              type="primary"
              onClick={() =>
                edit("手动记账", ledger ? "/admin/affiliate/credit" : "/admin/credit", "POST", [
                  {
                    name: "userId",
                    label: "用户 ID",
                    kind: "number",
                    required: true,
                  },
                  {
                    name: "amount",
                    label: "记账金额",
                    kind: "decimal",
                    unit: "¥",
                    min: -maxAccountingAmount,
                    max: maxAccountingAmount,
                    precision: 2,
                    help: "正数入账，负数扣除",
                    required: true,
                  },
                  { name: "description", label: "说明" },
                ])
              }
            >
              手动记账
            </Button>
          ) : undefined,
        );
      case "notifications":
        return table(
          [
            { title: "标题", dataIndex: "title" },
            { title: "内容", dataIndex: "body" },
            { title: "时间", dataIndex: "created", render: date },
          ],
          <Button
            type="primary"
            icon={<Plus size={15} />}
            onClick={() =>
              edit("发布通知", "/admin/notifications", "POST", [
                { name: "title", label: "标题", required: true },
                { name: "body", label: "内容", kind: "area", required: true },
                {
                  name: "telegram",
                  label: "通知已订阅的 Telegram 用户",
                  kind: "switch",
                },
              ])
            }
          >
            发布通知
          </Button>,
        );
      case "users": {
        const sortable = (key: string) => ({ key, sorter: true, sortOrder: userSort !== key ? null : userDirection === "asc" ? "ascend" : "descend" });
        const cleanupActions = [
          { key: "users", label: "清理无效用户", onClick: async () => {
            try {
              const result = await api<{ count: number }>("/admin/users/cleanup", "POST", { confirm: false });
              if (!result.count) { message.info("没有可清理的用户"); return; }
              confirmAction({ title: "清理 " + result.count + " 个无有效套餐、余额或关联记录的账号？", content: "关联的转发规则将同时删除。", onOk: () => action("/admin/users/cleanup", "POST", { confirm: true }) });
            } catch (error) { message.error((error as Error).message); }
          } },
          { key: "rules", label: "清理无效规则", onClick: async () => {
            try {
              const result = await api<{ count: number }>("/admin/rules/cleanup", "POST", { confirm: false });
              if (!result.count) { message.info("没有失去关联设备组的规则"); return; }
              confirmAction({ title: "清理 " + result.count + " 条无效规则？", onOk: () => action("/admin/rules/cleanup", "POST", { confirm: true }) });
            } catch (error) { message.error((error as Error).message); }
          } },
        ];
        return table(
          [
            { title: "UID", dataIndex: "id", ...sortable("id") },
            { title: "用户名", dataIndex: "name", ...sortable("name"), render: (name: string) => <span className="data-title">{name}</span> },
            { title: "过期时间", dataIndex: "expires", ...sortable("expires"), render: (_: number, r: User) => planExpiryLabel(r) },
            { title: "流量", ...sortable("traffic"), render: (_: unknown, r: User) => bytes(r.used) + " / " + (r.unlimitedTraffic ? "不限流量" : bytes(r.quota)) },
            { title: "套餐", dataIndex: "planId", render: (id: number) => userPlans.value.find(plan => plan.id === id)?.name || (id ? "#" + id : "—") },
            { title: "用户组", dataIndex: "group", render: (id: number) => groupUsers.value.find(group => group.id === id)?.name || "#" + id },
            { title: "最大规则数", dataIndex: "maxRules", ...sortable("rules"), render: (_: number, account: User) => ruleLimitLabel(account) },
            { title: "钱包余额", dataIndex: "balance", ...sortable("balance"), render: currency },
            { title: "Telegram", dataIndex: "telegramId", render: (id?: number) => id || "—" },
            { title: "管理员", dataIndex: "admin", render: (admin: boolean) => admin ? <Tag color="blue">是</Tag> : "—" },
            { title: "封禁", dataIndex: "banned", render: (banned: boolean) => banned ? <Tag color="red">封禁</Tag> : "—" },
            {
              title: "操作",
              key: "action",
              width: narrow ? 128 : 198,
              render: (_: unknown, r: User) => {
                const actions = [
                  { label: "重置密码", icon: Unlink, onClick: () => edit("重置 " + r.name + " 的密码", "/admin/users/" + r.id + "/password", "PUT", [{ name: "password", label: "新密码", kind: "secret", required: true }]) },
                  { label: "编辑用户", icon: Pencil, onClick: () => edit(`编辑用户 ${r.name} (UID=${r.id})`, "/admin/users/" + r.id, "PUT", userFields, {
                    ...r, usedGiB: displayGiB(r.used), quotaGiB: displayGiB(r.quota),
                    expiresAt: r.expires ? dayjs.unix(r.expires) : null, balanceAmount: r.balance / 100,
                  }) },
                  { label: "编辑用户套餐", icon: ShoppingBag, onClick: () => edit(`编辑用户套餐 · ${r.name}`, "/admin/users/" + r.id + "/plan", "PUT", [
                    { name: "planId", label: "套餐", kind: "select", required: true, options: [{ value: 0, label: "无套餐" }, ...(Array.isArray(userPlans.value) ? userPlans.value.map((plan) => ({value: plan.id, label: plan.name})) : [])] },
                    { name: "expires", label: "同步到期时间", kind: "checkbox", help: "从保存时计算新的有效期。" },
                    { name: "quota", label: "同步流量并重置已用量", kind: "checkbox" },
                    { name: "group", label: "同步用户组", kind: "checkbox" },
                    { name: "rules", label: "同步规则上限", kind: "checkbox" },
                    { name: "limits", label: "同步限速与连接限制", kind: "checkbox" },
                  ], { planId: r.planId, expires: !r.expires }) },
                  { label: "邀请返佣设置", icon: Gift, onClick: async () => {
                    const path = "/admin/users/" + r.id + "/referral";
                    try {
                      const options = await api<Row>(path);
                      edit("邀请注册设置 · " + r.name, path, "PUT", [
                        { name: "custom", label: "使用个人邀请设置", kind: "switch" },
                        { name: "registrationEnabled", label: "启用邀请注册", kind: "switch" },
                        { name: "ratePercent", label: "返佣比例", kind: "decimal", unit: "%", required: true },
                        { name: "firstOnly", label: "仅首次消费返佣", kind: "switch" },
                        { name: "requireBinding", label: "要求绑定 Telegram", kind: "switch" },
                      ], { ...options, ratePercent: options.rate / 100 });
                    } catch (error) { message.error((error as Error).message); }
                  } },
                  { label: "删除用户", icon: Trash2, disabled: r.admin, onClick: () => confirm("删除账号 " + r.name + " 及其规则？", "/admin/users/" + r.id) },
                ];
                const direct = narrow ? actions.filter(item => item.label === "编辑用户") : actions;
                return <Space className="row-actions" size={2}>
                  <IconAction label="管理规则" icon={<Link2 size={15} />} href={"#/rules?owner=" + r.id} />
                  {direct.map(({ label, icon: Icon, disabled, onClick }) => (
                    <IconAction key={label} label={label} icon={<Icon size={15} />} danger={label === "删除用户"} disabled={disabled} onClick={onClick} />
                  ))}
                  {narrow && <Dropdown trigger={["click"]} menu={{ items: actions.filter(item => item.label !== "编辑用户")
                    .map(({ label, icon: Icon, disabled, onClick }) => ({ key: label, label, icon: <Icon size={14} />, disabled, onClick, danger: label === "删除用户" })) }}>
                    <IconAction label="用户更多操作" icon={<Ellipsis size={16} />} />
                  </Dropdown>}
                </Space>;
              },
            },
            { title: "备注", dataIndex: "note", render: (note?: string) => note?.split("\n")[0] || "—" },
          ],
          <Space wrap={!narrow}>
            <Button type="primary" icon={<Plus size={15} />} onClick={() => edit("添加用户", "/admin/users", "POST", [
              { name: "name", label: "账号", required: true },
              { name: "password", label: "密码", kind: "secret", required: true },
            ])}>添加用户</Button>
            {narrow ? <Dropdown trigger={["click"]} menu={{ items: [
              { key: "search", label: <a href="#/rules?search=1">搜索规则</a> },
              ...cleanupActions.map(({ key, label, onClick }) => ({ key, label, onClick, icon: <Trash2 size={14} /> })),
            ] }}>
              <Button icon={<Ellipsis size={17} />}>更多操作</Button>
            </Dropdown> : <>
              <Button href="#/rules?search=1">搜索规则</Button>
              {cleanupActions.map(({ key, label, onClick }) => (
                <Button key={key} icon={<Trash2 size={14} />} onClick={onClick}>{label}</Button>
              ))}
            </>}
            <RefreshButton reload={[data.reload, userTotal.reload]} />
          </Space>,
        );
      }
      case "user-groups":
        return table(
          [
            { title: "ID", dataIndex: "id" },
            { title: "名称", dataIndex: "name" },
            { title: "用户数量", dataIndex: "userCount" },
            {
              title: "操作",
              key: "action",
              render: (_: unknown, r: Row) => (
                  <Space>
                    <Button
                      size="small"
                      onClick={() =>
                        edit(
                          "编辑用户组",
                          "/admin/user-groups/" + r.id,
                          "PUT",
                          [{ name: "name", label: "名称", required: true }],
                          r,
                        )
                      }
                    >
                      编辑
                    </Button>
                    {r.id > 0 && <Button
                      size="small"
                      danger
                      onClick={() =>
                        confirm("删除用户组？", "/admin/user-groups/" + r.id)
                      }
                    >
                      删除
                    </Button>}
                  </Space>
                ),
            },
          ],
          <Button
            type="primary"
            icon={<Plus size={15} />}
            onClick={() =>
              edit("添加用户组", "/admin/user-groups", "POST", [
                { name: "name", label: "名称", required: true },
              ])
            }
          >
            添加用户组
          </Button>,
        );
      case "plans": {
        const plans = list as Plan[];
        const currentPage = Math.min(planPage, Math.max(1, Math.ceil(plans.length / 15)));
        return (
          <section className="shop-catalog">
            <header className="page-head">
              <h1>{spec.title}</h1>
              <Button type="primary" icon={<Plus size={15} />} onClick={() => editPlan()}>添加套餐</Button>
            </header>
            {plans.length > 0 ? (
              <div className="shop-plan-grid">
                {plans.slice((currentPage - 1) * 15, currentPage * 15).map((plan, index) => (
                  <PlanCard key={plan.id} plan={plan}
                    {...dropTarget(plan.id)}
                    badge={<Tag color={plan.enabled ? "success" : "default"}>{plan.enabled ? "上架" : "下架"}</Tag>}
                    sortControl={sortHandle(plan, (currentPage - 1) * 15 + index, plans)}
                    group={groupUsers.value.find(group => group.id === plan.groupId)?.name || "#" + plan.groupId}
                    actions={
                      <>
                        <Button size="small" onClick={() => editPlan(plan)}>编辑</Button>
                        <Button size="small" onClick={() => edit(`推送套餐更新 · ${plan.name}`, "/admin/plans/" + plan.id + "/push", "POST", [
                          { name: "expires", label: "同步到期时间", kind: "checkbox", help: "从推送时计算新的有效期。" },
                          { name: "quota", label: "同步流量配额", kind: "checkbox" },
                          { name: "group", label: "同步用户组", kind: "checkbox" },
                          { name: "rules", label: "同步规则上限", kind: "checkbox" },
                          { name: "limits", label: "同步限速、IP 和连接数上限", kind: "checkbox" },
                        ])}>推送更新</Button>
                        <Dropdown trigger={["click"]} menu={{ items: [{
                          key: "delete", label: "删除套餐", danger: true, onClick: () => confirm("删除 " + plan.name + "？", "/admin/plans/" + plan.id),
                        }] }}>
                          <IconAction type="default" label="更多套餐操作" icon={<Ellipsis size={16} />} />
                        </Dropdown>
                      </>
                    }
                  />
                ))}
              </div>
            ) : !data.error && <div className="shop-empty" role="status">
              {data.busy ? <><Spin size="small" />正在加载套餐</> : <><ShoppingBag size={20} aria-hidden="true" />暂无套餐</>}
            </div>}
            {plans.length > 15 && <Pagination className="table-footer page-controls" current={currentPage}
              total={plans.length} pageSize={15} showSizeChanger={false} onChange={setPlanPage} />}
          </section>
        );
      }
      case "redeem":
        return table(
          [
            { title: "兑换码", dataIndex: "code" },
            { title: "套餐", dataIndex: "planName", render: (name: string, row: Row) => name || "#" + row.planId },
            { title: "剩余次数", dataIndex: "remaining" },
            {
              title: "实付比例",
              dataIndex: "discount",
              render: (v: number) => (10000 - v) / 100 + "%",
            },
            { title: "有效期", dataIndex: "expiry", render: date },
            {
              title: "操作",
              key: "action",
              render: (_: unknown, r: Row) => (
                <Button
                  size="small"
                  danger
                  onClick={() =>
                    confirm(
                      "删除兑换码？",
                      "/admin/redeem/" + encodeURIComponent(r.code),
                    )
                  }
                >
                  删除
                </Button>
              ),
            },
          ],
          <Button
            type="primary"
            icon={<Plus size={15} />}
            onClick={() =>
              edit(
                "批量添加兑换码",
                "/admin/redeem/batch",
                "POST",
                [
                  { name: "codes", label: "兑换代码（每行一个）", kind: "area", required: true },
                  { name: "planId", label: "套餐", kind: "select", required: true,
                    options: userPlans.value.map(plan => ({ value: plan.id, label: plan.name })) },
                  {
                    name: "remaining",
                    label: "可用次数",
                    kind: "number",
                    required: true,
                  },
                  {
                    name: "payablePercent",
                    label: "实付比例",
                    kind: "decimal",
                    unit: "%",
                    max: 100,
                    precision: 2,
                    required: true,
                    help: "9 折填 90，免费兑换填 0",
                  },
                  {
                    name: "validUntil",
                    label: "到期时间",
                    kind: "date",
                    required: true,
                  },
                ],
                {
                  remaining: 1,
                  payablePercent: 0,
                  validUntil: dayjs().add(30, "day").startOf("second"),
                },
              )
            }
          >
            批量添加兑换码
          </Button>,
        );
      case "tunnels":
      case "groups":
        return table(
          [
            {
              title: "设备组",
              render: (_: unknown, r: Group) => (
                <div>
                  <span className="data-title">{r.name}</span>
                  <span className="data-secondary">#{r.id}{r.owner ? " · 用户 UID " + r.owner : ""}</span>
                  {r.folder && <div className="muted">{r.folder}</div>}
                </div>
              ),
            },
            {
              title: "类型",
              dataIndex: "kind",
              render: (kind: string) => groupKindLabel(kind),
            },
            {
              title: "连接地址 / 端口池",
              key: "ports",
              render: (_: unknown, r: Group) =>
                r.kind !== "entry" && r.kind !== "both" ? "—" : <div>
                  <div className="address-lines">{r.connectHost || "自动"}</div><span className="mono muted">{r.portRanges || r.firstPort + " – " + r.lastPort}</span>
                </div>,
            },
            {
              title: "协议",
              render: (_: unknown, r: Group) => {
                const entry = r.kind === "entry" || r.kind === "both";
                const relay = ["exit", "relay", "both"].includes(r.kind);
                const network = r.defaultNetwork === "both" ? "TCP + UDP" : (r.defaultNetwork || "tcp").toUpperCase();
                return <Space size={[4, 4]} wrap>
                  {entry && <span className="protocol-label">{network}</span>}
                  {relay && <span className="protocol-label">{relayModeLabel(r.relayMode)}</span>}
                  {!entry && !relay && <span className="muted">—</span>}
                </Space>;
              },
            },
            {
              title: "流量倍率",
              dataIndex: "ratio",
              render: (v: number) => v / 1000 + "×",
            },
            {
              title: "授权用户组",
              render: (_: unknown, r: Group) => {
                const ids = authorizedUserGroups(r);
                const known = Array.isArray(groupUsers.value) ? groupUsers.value : [];
                return ids.map((id) => known.find((g) => g.id === id)?.name ?? "#" + id).join("、") || "未授权";
              },
            },
            {
              title: "在线设备", render: (_: unknown, row: Group) => {
                const count = groupTotals.value[row.id];
                return row.kind === "chain" || !count ? "—" : count.online + " / " + count.devices;
              },
            },
            ...(isGroupEditor ? [
              { title: "已用流量", responsive: narrow ? undefined : ["lg"], render: (_: unknown, row: Group) => groupTotals.value[row.id] ? bytes(groupTotals.value[row.id].traffic) : "—" },
              { title: "备注", dataIndex: "note", responsive: narrow ? undefined : ["xl"], render: (note?: string) => note?.split("\n")[0] || "—" },
            ] : []),
            {
              title: "操作",
              key: "action",
              width: narrow ? 172 : 204,
              render: (_: unknown, r: Group) => (
                <Space className="row-actions" size={3}>
                  {r.kind !== "chain" && (
                    <Button size="small" onClick={() => void enlist(r)}>接入</Button>
                  )}
                  {r.kind !== "chain" && (
                    <IconAction label="查看节点" icon={<Server size={15} />} onClick={() => void groupNodes(r)} />
                  )}
                  <IconAction
                    label={isTunnel ? "编辑单端隧道" : "编辑设备组"}
                    icon={<Pencil size={15} />}
                    onClick={() =>
                      edit(
                        isTunnel ? "编辑单端隧道" : "编辑设备组",
                        groupAPI + "/" + r.id,
                        "PUT",
                        isTunnel
                          ? tunnelFields
                          : chainFields.map(field => field.options && ["allowedFrom", "allowedTo", "reverseGroups", "fallbackGroup"].includes(field.name)
                            ? { ...field, options: field.options.filter(option => option.value !== r.id) } : field),
                        {
                          ...r,
                          routing: { ...r.routing, statusVisibility: r.routing?.statusVisibility || (r.hideStatus ? "admin" : "all"),
                            ingressMode: r.routing?.ingressMode || "" },
                          userGroups: authorizedUserGroups(r),
                        },
                      )
                    }
                  />
                  {!narrow && <IconAction label="高级编辑 JSON" icon={<FileJson size={15} />} onClick={() => setJsonGroup(r)} />}
                  <Dropdown trigger={["click"]} menu={{ items: [
                    ...(narrow ? [{ key: "json", icon: <FileJson size={14} />, label: "高级编辑 JSON", onClick: () => setJsonGroup(r) }] : []),
                    ...(r.kind !== "chain" ? [
                      { key: "config", label: "查看节点配置", onClick: () => void inspectGroup(r) },
                      { key: "revoke", label: "撤销安装命令", onClick: () => confirmAction({
                        title: "撤销此设备组的安装命令？",
                        content: "已接入节点可继续运行。下次打开接入窗口时会生成新凭据。",
                        onOk: () => action("/groups/" + r.id + "/operations", "POST", { action: "revoke-enrollments" }),
                      }) },
                      { key: "reset", label: "重置整组接入凭据", danger: true, onClick: () => confirmAction({
                        title: `重置 ${r.name} 的接入凭据？`,
                        content: "此组已接入的节点会断开，转发可能中断。等待节点收到凭据失效通知后，使用新安装命令重新接入。",
                        okText: "重置凭据", cancelText: "取消", okButtonProps: { danger: true },
                        onOk: () => action("/groups/" + r.id + "/operations", "POST", { action: "reset-credentials" }),
                      }) },
                    ] : []),
                    ...(r.kind === "entry" || r.kind === "both" ? [{ key: "clear", label: "清空设备组规则统计", onClick: () => confirm("清空此设备组规则统计？", "/groups/" + r.id + "/operations", "POST", { action: "clear-traffic" }) }] : []),
                    { key: "delete", label: "删除设备组", danger: true, onClick: () => confirm("删除设备组？", groupAPI + "/" + r.id) },
                  ] }}><IconAction label="设备组更多操作" icon={<Ellipsis size={17} />} /></Dropdown>
                </Space>
              ),
            },
          ],
          <Button
            type="primary"
            icon={<Plus size={15} />}
            onClick={() =>
              edit(
                isTunnel ? "添加单端隧道" : "添加设备组",
                groupAPI,
                "POST",
                isTunnel ? tunnelFields : chainFields,
                {
                  kind: isTunnel ? "exit" : "entry",
                  firstPort: 10000,
                  lastPort: 65525,
                  ratio: 1000,
                  offlineSeconds: 30,
                  userGroup: 0,
                  defaultNetwork: "tcp",
                  relayMode: "tls",
                  tlsIngress: 0,
                  routing: { ingressMode: "", statusVisibility: "all" },
                },
              )
            }
          >
            {isTunnel ? "添加单端隧道" : "添加设备组"}
          </Button>,
        );
      default:
        return (
          <section className="empty-state">
            <a href="#/">
              返回主页 <ChevronRight size={15} />
            </a>
          </section>
        );
    }
  }

  const quote = (v: string) => "'" + v.replaceAll("'", "'\\''") + "'";
  const instance = nodeInstance.trim();
  const validInstance = instance === "" || /^[a-z][a-z0-9-]{0,19}$/.test(instance);
  const customPanelURL = customPanel.trim();
  const panelAddress = panelOrigin(customPanelURL || window.location.origin);
  const canCopy = !!enroll && validInstance && !!panelAddress;
  const instanceOption = instance ? " --instance " + quote(instance) : "";
  const relayOptions = reverseOnly ? " --reverse-only" : enroll?.relay
    ? `${relayAddress ? " --relay-address " + quote(relayAddress) : " --prompt-relay-address"} --relay-transport ${quote(relayTransport)}`
    : "";
  const reverseOption=reverseAddress?" --reverse-address "+quote(reverseAddress):"";
  const bindOption = bindAddresses.trim() ? " --bind " + quote(bindAddresses.trim()) : "";
  const udpOption = udpSmartBind ? " --udp-smart-bind" : "";
  const groupOption = enroll?.groupName ? " --group-name " + quote(enroll.groupName) : "";
  const commandArgs = canCopy && enroll && panelAddress
    ? `${quote(panelAddress)} ${quote(enroll.token)}${instanceOption}${groupOption}${relayOptions}${reverseOption}${bindOption}${udpOption}`
    : "";
  const command = commandArgs && panelAddress
    ? offlineInstall
      ? `sudo env HOPX_OFFLINE_DIR="$PWD" bash ./node-install.sh ${commandArgs}`
      : `curl -fsSLo hopx-node-install.sh ${quote(panelAddress + "/releases/node-install.sh")} && sudo bash hopx-node-install.sh ${commandArgs}`
    : "";

  const routingMode = Form.useWatch(["routing", "addressMode"], form);
  const groupTransport = Form.useWatch("relayMode", form);
  const editorFields = editor?.fields.filter((f) => {
    if (editingPlan && f.name === "duration") return planUsesPeriod;
    if (editor.path.endsWith("/referral")) return f.name === "custom" || customReferral;
    if (f.name === "chain") return editingKind === "chain";
    if (f.path?.[0] === "routing") {
      if (f.name === "statusVisibility") return editingKind !== "chain";
      if (f.name === "ingressMode" || f.name === "allowPrivateTargets") return editingKind === "entry" || editingKind === "both";
      if (f.name === "staticAddress") return routingMode === "static";
      if (["addressMode", "nativeUDP", "applyRelayMode"].includes(f.name)) return ["exit", "relay", "both"].includes(editingKind);
      return ["entry", "relay", "both"].includes(editingKind);
    }
    if (f.name === "relayMode") return isTunnel || ["exit", "relay", "both"].includes(editingKind);
    if (f.name === "fallbackGroup") return ["exit", "both", "chain"].includes(editingKind);
    if (["firstPort", "lastPort", "portRanges", "defaultNetwork", "connectHost", "reverseGroups", "tlsIngress"].includes(f.name) || f.path?.[0] === "ingress") {
      return editingKind === "entry" || editingKind === "both";
    }
    return true;
  }) || [];
  const basicFieldNames = ["name", "kind", "ratio", "userGroups"];
  const connectionFieldNames = ["firstPort", "lastPort", "connectHost", "defaultNetwork", "ingressMode", "relayMode", "chain"];
  const visibilityFieldNames = ["statusVisibility", "note"];
  const orderedFields = (names: string[]) => names.flatMap(name => editorFields.filter(field => field.name === name));
  const connectionFields = orderedFields(connectionFieldNames);
  const visibilityFields = orderedFields(visibilityFieldNames);
  const commonFields = new Set([...basicFieldNames, ...connectionFieldNames, ...visibilityFieldNames]);
  if (["entry", "both"].includes(editingKind)) {
    const allowedTo = editorFields.find(field => field.name === "allowedTo");
    if (allowedTo) connectionFields.push(allowedTo);
    commonFields.add("allowedTo");
  }
  const advancedFields = editorFields.filter(field => !commonFields.has(field.name));
  const originalKind = editor?.value.kind;
  const legacyKind = originalKind === "relay" || originalKind === "both";
  const editingGroup = isGroupEditor && Boolean(editor?.value.id);
  const renderFields = (fields: Field[]) => fields.map((f) => (
    <Form.Item
      key={f.name}
      className={f.kind === "area" || ["portRanges", "chain", "allowedTo"].includes(f.name) ? "field-wide" : undefined}
      name={f.path ?? f.name}
      label={f.kind === "checkbox" ? undefined : f.label}
      tooltip={f.kind === "checkbox" ? undefined : f.help}
      extra={f.kind === "checkbox" ? f.help
        : f.name === "quotaGiB" && !unlimitedTraffic ? "填 0 时，配额为 0 B。"
        : f.name === "relayMode" ? relayModeHelp(groupTransport) : undefined}
      valuePropName={f.kind === "switch" || f.kind === "checkbox" ? "checked" : "value"}
      {...(f.name === "ratio" && {
        getValueProps: (ratio: number | undefined) => ({ value: ratio == null ? undefined : ratio / 1000 }),
        normalize: (multiplier: number | null) => multiplier == null ? undefined : Math.round(multiplier * 1000),
      })}
      rules={[{ required: f.required && !(f.name === "quotaGiB" && unlimitedTraffic) }]}
    >
      <FieldInput disabled={(f.name === "quotaGiB" && Boolean(unlimitedTraffic)) || (editingUserPlan && f.kind === "checkbox" && !assignedPlan)}
        field={f.name === "kind" && editingGroup ? {
        ...f,
        options: legacyKind
          ? [...groupKinds.filter(option => option.value !== "chain"), { value: originalKind, label: groupKindLabel(originalKind) + "（历史配置）", disabled: true }]
          : groupKinds.filter(option => (option.value === "chain") === (originalKind === "chain")),
      } : (editingPlan && f.name === "groupId") || (editingUser && f.name === "group") ? {
        ...f, options: groupUsers.value.map(group => ({ value: group.id, label: group.name })),
      } : editingPlan && f.name === "duration" ? { ...f, unit: editingKind === "month" ? "个月" : "天" } : f} />
    </Form.Item>
  ));
  const quotaFields = orderedFields(["quotaGiB", "unlimitedTraffic"]);
  const userLimits = ["maxRules", "rateOverride", "ipsOverride", "connectionsOverride"];

  return (
    <>
      {spec && page === "shop" && (
        <header className="page-head">
          <h1>{spec.title}</h1>
        </header>
      )}
      {data.error && spec?.path && (
        <Alert
          type="error"
          showIcon
          message={data.error}
          className="alert-gap"
        />
      )}
      {render()}
      {page === "notifications" && <section className="panel-table">
        <header className="page-head"><h1>设备离线通知</h1></header>
        {(offlineNotice.error || noticeGroups.error) && <Alert type="error" showIcon message={offlineNotice.error || noticeGroups.error} className="alert-gap" />}
        <p className="muted alert-gap">设备在宽限期内恢复时保持静默。离线设备会保留在节点状态列表中，可手动移除。</p>
        <Space wrap={!narrow} className="list-toolbar">
          <label htmlFor="offline-notice-default">默认宽限期（秒）</label>
          <InputNumber id="offline-notice-default" min={0} max={2592000} precision={0} value={noticeConfig.default}
            disabled={working || offlineNotice.busy} onChange={value => setNoticeDraft({ ...noticeConfig, default: value ?? 0 })} />
        </Space>
        <Table<Group> rowKey="id" size="small" loading={noticeGroups.busy} dataSource={noticeGroups.value.filter(group => group.kind !== "chain")}
          scroll={narrow ? { x: 390 } : undefined}
          pagination={{ pageSize: 10, hideOnSinglePage: true }} columns={[
            { title: "设备组", dataIndex: "name" },
            { title: "自定义宽限期（秒）", render: (_, group) => <InputNumber
              aria-label={group.name + " 离线宽限期"} min={0} max={2592000} precision={0}
              placeholder="使用默认值" value={noticeConfig.groups?.[group.id] ?? null} disabled={working || offlineNotice.busy}
              onChange={value => {
                const groups = { ...noticeConfig.groups };
                if (value === null) delete groups[group.id];
                else groups[group.id] = value;
                setNoticeDraft({ ...noticeConfig, groups });
              }} /> },
          ]} />
        <Space wrap className="table-footer">
          <Button type="primary" onClick={() => void saveOfflineNotice()} disabled={!noticeDraft} loading={working}>保存离线通知配置</Button>
          <Button href="#/settings">Telegram 通道设置</Button>
        </Space>
      </section>}
      <Modal
        open={!!editor}
        title={editor?.title}
        onCancel={() => { setEditor(undefined); setAccounting(undefined); }}
        onOk={() => form.submit()}
        confirmLoading={working}
        forceRender
        okText={accounting ? "确认记账" : editor?.path.endsWith("/credit") ? "预览记账" : "保存"}
        okButtonProps={{
          "aria-label": accounting ? "确认记账" : editor?.path.endsWith("/credit") ? "预览记账" : "保存",
          disabled: accounting !== undefined && accounting.after < 0,
        }}
        width={editingUserPlan || pushingPlan ? 482 : page === "groups" || page === "plans" || page === "users" || page === "settings" ? 680 : 520}
      >
        <Form name="management-editor" layout="vertical" form={form} onFinish={submit}>
          {editor?.path.endsWith("/password") && <p className="dialog-note">保存后，此账号的现有登录会失效。</p>}
          {editor?.path.endsWith("/referral") && editor.value.inviter > 0 && <p className="dialog-note">邀请人 UID {editor.value.inviter}</p>}
          {isGroupEditor && editor && editor.path !== "/admin/groups/folders" ? (
            <>
              <div className="equipment-editor">
                {renderFields(orderedFields(basicFieldNames))}
              </div>
              {connectionFields.length > 0 && <div className="editor-section">
                <h3>{editingKind === "chain" ? "转发链路" : "连接设置"}</h3>
                <div className="equipment-editor">
                  {renderFields(connectionFields)}
                </div>
              </div>}
              {visibilityFields.length > 0 && <div className="equipment-editor editor-section">
                {renderFields(visibilityFields)}
              </div>}
              {advancedFields.length > 0 && <><Button
                className="editor-disclosure"
                type="text"
                icon={<ChevronDown size={15} className={advancedGroup ? "rotate" : undefined} />}
                aria-expanded={advancedGroup}
                aria-controls="equipment-advanced"
                onClick={() => setAdvancedGroup(!advancedGroup)}
              >
                {advancedGroup ? "收起高级设置" : "设备组高级设置"}
              </Button>
              <div id="equipment-advanced" hidden={!advancedGroup}>
                <div className="equipment-editor group-editor-advanced">
                  {renderFields(advancedFields)}
                </div>
              </div></>}
            </>
          ) : editingPlan ? (
            <>
              <div className="equipment-editor">
                {renderFields(editorFields.filter(field => !planLimitFields.has(field.name) && !quotaFields.includes(field)))}
              </div>
              <div className="quota-editor">
                {renderFields(quotaFields)}
              </div>
              <section className="editor-section">
                <h3>使用限制</h3>
                <div className="equipment-editor">
                  {renderFields(editorFields.filter(field => planLimitFields.has(field.name)))}
                </div>
              </section>
            </>
          ) : editingUser ? (
            <>
              <div className="equipment-editor">{renderFields(orderedFields(["group", "expiresAt", "usedGiB", "balanceAmount"]))}</div>
              <div className="quota-editor">{renderFields(quotaFields)}</div>
              <section className="editor-section">
                <h3>使用限制</h3>
                <div className="equipment-editor">{renderFields(orderedFields(userLimits))}</div>
              </section>
              <section className="editor-section">
                <h3>账户权限</h3>
                <div className="equipment-editor editor-toggle-grid">{renderFields(orderedFields(["admin", "allowDevice", "banned"]))}</div>
              </section>
              {renderFields(orderedFields(["note"]))}
            </>
          ) : editingUserPlan || pushingPlan ? (
            <>
              {renderFields(orderedFields(["planId"]))}
              <div className="plan-sync-options">{renderFields(editorFields.filter(field => field.kind === "checkbox"))}</div>
            </>
          ) : (
            <div hidden={!!accounting} className={["plans", "users", "settings"].includes(page) ? "equipment-editor" : undefined}>
              {renderFields(editorFields)}
            </div>
          )}
          {accounting && <>
            <Descriptions size="small" column={1} items={[
              { key: "user", label: "用户", children: `${accounting.name} (#${accounting.values.userId})` },
              { key: "amount", label: "记账金额", children: currency(accounting.values.amount) },
              { key: "before", label: "操作前余额", children: currency(accounting.balance) },
              { key: "after", label: "操作后余额", children: currency(accounting.after) },
            ]} />
            {accounting.after < 0 && <Alert type="error" showIcon message="余额不足以扣除该金额" className="alert-gap" />}
            <Button onClick={() => setAccounting(undefined)} disabled={working}>返回编辑</Button>
          </>}
        </Form>
      </Modal>
      <Modal
        open={!!enroll}
        title={<div className="enroll-title">
          <span className="dialog-title-icon"><Server size={19} aria-hidden="true" /></span>
          <div><strong>接入节点</strong><span>{enroll?.groupName}</span></div>
        </div>}
        width={620}
        onCancel={() => setEnroll(undefined)}
        footer={<Button
          type="primary"
          icon={<Copy size={15} aria-hidden="true" />}
          disabled={!command}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(command);
              message.success("安装命令已复制");
            } catch {
              message.error("请选择命令文本手动复制");
            }
          }}
        >复制安装命令</Button>}
      >
        <div className="enroll-content">
          <Segmented aria-label="部署方式" block
            value={offlineInstall ? "offline" : "online"}
            onChange={value => setOfflineInstall(value === "offline")}
            options={[
              { value: "online", label: "在线部署", icon: <Globe size={15} aria-hidden="true" /> },
              { value: "offline", label: "离线部署", icon: <Download size={15} aria-hidden="true" /> },
            ]} />
          {offlineInstall && <div className="enroll-downloads">
            <Space wrap>
              <Button href="/api/node-package/amd64" icon={<Download size={14} aria-hidden="true" />}>Linux x86_64</Button>
              <Button href="/api/node-package/arm64" icon={<Download size={14} aria-hidden="true" />}>Linux ARM64</Button>
            </Space>
            <p>解压后在发行包目录执行命令。注册时节点需要能访问面板。</p>
          </div>}
          <div className="enroll-panel-address">
            <Globe size={16} aria-hidden="true" />
            <div><span>面板地址</span><code>{panelAddress || "地址无效"}</code></div>
            <Button size="small" type="text" onClick={() => {
              setEnrollAdvanced(true);
              requestAnimationFrame(() => document.getElementById("enroll-panel-address")?.focus());
            }}>自定义</Button>
          </div>
          {enroll?.relay && !reverseOnly && <div className="enroll-connection">
            <label htmlFor="enroll-address">节点连接地址</label>
            <label id="enroll-transport-label">传输协议</label>
            <Input id="enroll-address" value={relayAddress} onChange={event => setRelayAddress(event.target.value.trim())}
              placeholder="留空，在节点安装时填写" />
            <Select aria-labelledby="enroll-transport-label" value={relayTransport} options={relayModes}
              onChange={setRelayTransport} />
            <p>{relayModeHelp(relayTransport)}</p>
          </div>}
          {enroll && <details className="enroll-options" open={enrollAdvanced}
            onToggle={event => setEnrollAdvanced(event.currentTarget.open)}>
            <summary><Settings2 size={15} aria-hidden="true" />接入选项<ChevronDown size={15} aria-hidden="true" /></summary>
            <div className="enroll-options-fields">
              <div className="enroll-field">
                <label htmlFor="enroll-panel-address">自定义面板地址</label>
                <Input id="enroll-panel-address" type="url" value={customPanel} placeholder={window.location.origin}
                  status={panelAddress ? undefined : "error"} onChange={event => setCustomPanel(event.target.value)} />
                {panelAddress
                  ? <p>留空使用当前面板地址。节点需要能访问此地址。</p>
                  : <p className="enroll-error" role="alert">请输入完整的 HTTP 或 HTTPS 站点地址。</p>}
              </div>
              <div className="enroll-field">
                <label htmlFor="enroll-instance">节点实例</label>
                <Input id="enroll-instance" value={nodeInstance} placeholder="留空使用默认实例"
                  status={validInstance ? undefined : "error"} onChange={event => setNodeInstance(event.target.value)} />
                <p className={validInstance ? undefined : "enroll-error"}>{validInstance ? "同一台机器接入多个节点时，给各实例填写不同名称。" :
                  "以小写字母开头，最多 20 位，可用小写字母、数字和连字符。"}</p>
              </div>
              {enroll.reverseIngress && <>
                <div className="enroll-field">
                  <label htmlFor="enroll-bind">监听绑定地址</label>
                  <Input id="enroll-bind" value={bindAddresses} onChange={event => setBindAddresses(event.target.value)}
                    placeholder="多个 IP 用逗号分隔" />
                </div>
                <div className="enroll-field">
                  <label htmlFor="enroll-reverse">反向入口地址</label>
                  <Input id="enroll-reverse" value={reverseAddress} onChange={event => setReverseAddress(event.target.value.trim())}
                    placeholder="entry.example.com:38473" />
                </div>
              </>}
              {(enroll.reverseIngress || enroll.reverseEgress) && <Space wrap size={16}>
                {enroll.reverseIngress && <Space>
                  <Switch size="small" checked={udpSmartBind} onChange={setUDPSmartBind} aria-label="UDP 智能绑定" />
                  <span>UDP 智能绑定</span>
                </Space>}
                {enroll.reverseEgress && <Space>
                  <Switch size="small" checked={reverseOnly} onChange={setReverseOnly} aria-label="反向出口" />
                  <span>反向出口</span>
                </Space>}
              </Space>}
            </div>
          </details>}
          <div className="enroll-command">
            <label htmlFor="enroll-command"><Terminal size={16} aria-hidden="true" />安装命令</label>
            <Input.TextArea id="enroll-command" readOnly value={command} spellCheck={false} rows={4}
              placeholder="修正接入选项后生成命令" onFocus={event => event.target.select()} />
          </div>
        </div>
      </Modal>
      {jsonGroup && <JsonEditor title={"设备组 JSON · " + jsonGroup.name} value={jsonGroup}
        onClose={() => setJsonGroup(undefined)}
        onSave={(values) => action(groupAPI + "/" + jsonGroup.id, "PUT", values)} />}
      <Drawer open={!!configSummary} title={configSummary?.groupName + " · 节点配置"} onClose={() => setConfigSummary(undefined)} width="min(870px, 100vw)">
        {configSummary && <>
          <p className="mono alert-gap">配置版本 {configSummary.revision}</p>
          <Table size="small" rowKey="id" dataSource={configSummary.rules} pagination={{ pageSize: 15 }} scroll={{ x: 620 }}
            columns={[
              { title: "规则", dataIndex: "name", render: (name, row) => `${name} (#${row.id})` },
              { title: "端口", dataIndex: "port" },
              { title: "协议", dataIndex: "network" },
              { title: "目标地址", dataIndex: "targets", render: (targets?: string[]) => <span className="address-lines mono">{targets?.join("\n") || "—"}</span> },
              { title: "主链", render: (_, row) => row.path?.length ? `${row.path.map(id => "#" + id).join(" → ")} (${row.routes})` : "直出" },
              { title: "备用链", render: (_, row) => row.backupPath?.length ? `${row.backupPath.map(id => "#" + id).join(" → ")} (${row.backup})` : "—" },
            ]} />
        </>}
      </Drawer>
      <Drawer
        open={!!groupDetail}
        title={groupDetail?.name + " · 节点"}
        onClose={() => setGroupDetail(undefined)}
        width="min(760px, 100vw)"
      >
        <Table<Node>
          rowKey="id"
          size="small"
          scroll={narrow && nodes.length ? { x: 600 } : undefined}
          pagination={false}
          dataSource={nodes}
          columns={[
            { title: "节点", key: "name", render: (_, node) => <span className="node-name" title={node.name}>
              <NodeFlag node={node} /><span>{nodeDisplayName(node)}</span>
            </span> },
            { title: "传输", dataIndex: "relayTransport", render: (value: string, node) => <Space size={4} wrap>
              {value ? relayModeLabel(value) : "—"}
              {node.nativeUDP && <Tag color="success">原生 UDP</Tag>}
              {node.nativeUDPError && <Tag color="error" title={node.nativeUDPError}>UDP 监听失败</Tag>}
              {node.relayModeError && <Tag color="error" title={node.relayModeError}>协议切换失败</Tag>}
            </Space> },
            { title: "版本", dataIndex: "version" },
            { title: "状态", render: (_, node) => <Tag color={node.revoked ? "warning" : node.online ? "green" : "default"}>{node.revoked ? "待重新接入" : node.online ? "在线" : "离线"}</Tag> },
            {
              title: "操作",
              key: "action",
              render: (_, n) => (
                <Space className={narrow ? "row-actions" : undefined} wrap={!narrow}>
                <Button size="small" onClick={() => {
                  setGroupDetail(undefined);
                  edit("编辑设备", "/nodes/" + n.id, "PATCH", [
                    { name: "name", label: "设备名称", required: true },
                    { name: "region", label: "地区" },
                    { name: "address", label: "展示地址" },
                  ], { name: n.name, region: n.region, address: n.address });
                }}>编辑</Button>
                {user.admin && <Button
                  danger
                  size="small"
                  onClick={() =>
                    confirmAction({
                      title: "移除 " + n.name + "？",
                      content: "将删除该节点的接入记录。重新使用时需再次接入。",
                      onOk: async () => {
                        const saved = await action("/nodes/" + n.id, "DELETE");
                        if (saved) setNodes((v) => v.filter((x) => x.id !== n.id));
                        return saved;
                      },
                    })
                  }
                >
                  移除
                </Button>}
                </Space>
              ),
            },
          ]}
        />
      </Drawer>
    </>
  );
}
