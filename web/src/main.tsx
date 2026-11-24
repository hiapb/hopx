import { Component, lazy, startTransition, Suspense, useEffect, useState } from "react";
import type { ComponentType, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import {
  Alert,
  App as AntApp,
  Button,
  ConfigProvider,
  Form,
  Input,
  InputNumber,
  Spin,
  theme,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  Activity,
  ArrowRight,
  Bell,
  Cable,
  ChevronDown,
  ArrowUpRight,
  CircleUserRound,
  Gauge,
  Gift,
  Home,
  Layers3,
  LockKeyhole,
  LogOut,
  Menu,
  Moon,
  Megaphone,
  ReceiptText,
  Settings,
  ShoppingBag,
  Sun,
  Ticket,
  Users,
  UserRoundPlus,
  Workflow,
} from "lucide-react";
import { api, useData } from "./api";
import type { Site, User } from "./api";
import Turnstile from "./turnstile";
import "./styles.css";

class PageModuleError extends Error {
  constructor(cause: unknown) {
    super("页面模块加载失败", { cause });
  }
}

function lazyPage<Props>(load: () => Promise<{ default: ComponentType<Props> }>) {
  return lazy(() => load().catch(error => { throw new PageModuleError(error); }));
}

const AdminDashboard = lazyPage(() => import("./admin-dashboard"));
const Rules = lazyPage(() => import("./rules"));
const Nodes = lazyPage(() => import("./nodes"));
const Management = lazyPage(() => import("./management"));
const Profile = lazyPage(() => import("./profile"));
const SiteSettings = lazyPage(() => import("./settings"));

class PageBoundary extends Component<{ children: ReactNode }, { failed: boolean; checkingUpdate: boolean }> {
  state = { failed: false, checkingUpdate: false };
  private updateCheck?: AbortController;

  static getDerivedStateFromError(error: Error) {
    return { failed: true, checkingUpdate: error instanceof PageModuleError };
  }

  componentDidCatch(error: Error) {
    if (error instanceof PageModuleError) void this.reloadAfterUpdate();
  }

  componentWillUnmount() {
    this.updateCheck?.abort();
    this.updateCheck = undefined;
  }

  private async reloadAfterUpdate() {
    const check = new AbortController();
    this.updateCheck = check;
    const url = location.href;
    const reloadKey = "hopx-reloaded-entry";
    const currentEntry = import.meta.url;
    const timeout = window.setTimeout(() => check.abort(), 3000);

    try {
      if (sessionStorage.getItem(reloadKey) === currentEntry) return;
      const response = await fetch(location.pathname, { cache: "no-store", signal: check.signal });
      if (!response.ok) return;
      const html = new DOMParser().parseFromString(await response.text(), "text/html");
      const entry = html.querySelector('script[type="module"][src]')?.getAttribute("src");
      if (check.signal.aborted || url !== location.href || !entry ||
          new URL(entry, response.url).href === currentEntry) return;
      sessionStorage.setItem(reloadKey, currentEntry);
      location.reload();
      this.updateCheck = undefined;
    } catch {
      // Keep the retry button available if the update check fails.
    } finally {
      window.clearTimeout(timeout);
      if (this.updateCheck === check) {
        this.updateCheck = undefined;
        this.setState({ checkingUpdate: false });
      }
    }
  }

  render() {
    if (!this.state.failed) return this.props.children;
    if (this.state.checkingUpdate) return <div className="loading-screen"><Spin /></div>;
    return <Alert type="error" showIcon message="页面加载失败"
      action={<Button size="small" onClick={() => location.reload()}>重新加载</Button>} />;
  }
}

const legacyPages: Record<string, string> = {
  userinfo: "profile",
  forward_rules: "rules",
  device_group: "tunnels",
  looking_glass: "nodes",
  afflog: "my-invites",
  "admin/main": "dashboard",
  "admin/settings": "settings",
  "admin/push_settings": "notifications",
  "admin/users": "users",
  "admin/user_group": "user-groups",
  "admin/orders": "admin-orders",
  "admin/plans": "plans",
  "admin/redeem": "redeem",
  "admin/device_group": "groups",
  "admin/afflog": "invites",
};

const primary = [
  ["", "主页", Home],
  ["profile", "个人中心", CircleUserRound],
  ["rules", "转发规则", Cable],
  ["shop", "商城", ShoppingBag],
  ["orders", "我的订单", ReceiptText],
  ["nodes", "节点状态", Activity],
] as const;
const administration = [
  ["dashboard", "仪表盘", Gauge],
  ["settings", "站点设置", Settings],
  ["notifications", "推送通知", Bell],
  ["users", "用户管理", CircleUserRound],
  ["user-groups", "用户组管理", Users],
  ["admin-orders", "订单管理", ReceiptText],
  ["plans", "套餐管理", ShoppingBag],
  ["redeem", "兑换码管理", Ticket],
  ["groups", "设备组管理", Layers3],
  ["invites", "邀请记录", Gift],
] as const;

function Brand() {
  return (
    <a className="brand" href="#/">
      <span className="brand-mark"><Workflow size={17} strokeWidth={2} /></span>
      <span>HopX</span>
    </a>
  );
}

function HomePage({ site, admin }: { site: Site; admin: boolean }) {
  const links = site.homeLinks ?? [];
  return (
    <div className="home-page">
      <section className="home-notice" aria-labelledby="home-notice-title">
        <header className="home-notice-heading">
          <h1 id="home-notice-title"><Megaphone size={21} aria-hidden="true" />站点公告</h1>
          {admin && <Button size="small" href="#/settings?section=announcement">编辑主页</Button>}
        </header>
        <p className={site.announcement.trim() ? "home-notice-text" : "home-notice-text muted"}>
          {site.announcement.trim() || "暂无站点公告"}
        </p>
      </section>
      {links.length > 0 && (
        <section className="home-promotions" aria-labelledby="home-promotions-title">
          <h2 id="home-promotions-title">推广链接</h2>
          <ul>
            {links.map(({ title, url }, index) => (
              <li key={index}>
                <a href={url} target="_blank" rel="noreferrer">
                  <span>
                    <strong>{title}</strong>
                    <small>{url}</small>
                  </span>
                  <ArrowUpRight size={17} aria-hidden="true" />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

type ArithmeticChallenge = { id: string; left: number; right: number };

function Login({ site, done, invite }: { site: Site; done: () => Promise<void>; invite?: string }) {
  const canRegister = site.registration !== "closed";
  const [showRegister, setShowRegister] = useState(Boolean(invite));
  const register = canRegister && showRegister;
  const verification = site.registrationVerification ?? (site.registrationChallenge === "true" ? "arithmetic" : "off");
  const arithmetic = register && verification === "arithmetic";
  const turnstile = register && verification === "turnstile";
  const [turnstileAttempt, setTurnstileAttempt] = useState(0);
  const challenge = useData<ArithmeticChallenge | null>(arithmetic ? "/register/challenge" : null, null);
  const [proof, setProof] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [form] = Form.useForm();

  function refreshArithmetic() {
    form.setFieldValue("answer", undefined);
    void challenge.reload();
  }

  function changeMode() {
    setShowRegister(!showRegister);
    setError("");
    setProof("");
    form.resetFields(["password", "answer"]);
  }

  async function submit(values: { name: string; password: string; invite?: string; answer?: number }) {
    if (busy || (arithmetic && (challenge.busy || !challenge.value || challenge.error)) ||
        (turnstile && !proof)) return;
    setBusy(true);
    setError("");
    let created = false;
    try {
      if (register) {
        await api("/register", "POST", {
          ...values,
          challengeId: arithmetic ? challenge.value?.id : undefined,
          turnstileToken: turnstile ? proof : undefined,
        });
        created = true;
      }
      await api("/login", "POST", { name: values.name, password: values.password });
      await done();
    } catch (e) {
      if (created) setShowRegister(false);
      setError(created ? `账号已创建，请重新登录。${(e as Error).message}` : (e as Error).message);
      if (!created && arithmetic) refreshArithmetic();
      if (!created && turnstile) {
        setProof("");
        setTurnstileAttempt(attempt => attempt + 1);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <div className="login-layout">
        <aside className="login-intro" aria-label="站点介绍">
          <div className="login-brand">
            <span className="login-brand-mark"><Workflow size={24} strokeWidth={1.9} aria-hidden="true" /></span>
            <strong>{site.name || "HopX"}</strong>
          </div>
          <div className="login-intro-copy">
            <h2>你的转发工作台</h2>
            <p>管理转发规则、链式出口和节点状态。</p>
          </div>
          <div className="login-route" aria-hidden="true">
            <div className="login-route-header">
              <span className="login-route-dots"><i /><i /><i /></span>
              <span>TCP / UDP</span>
            </div>
            <div className="login-route-track">
              <span><Cable size={19} />入口</span>
              <b></b>
              <span><Layers3 size={19} />中转</span>
              <b></b>
              <span><Activity size={19} />出口</span>
            </div>
          </div>
        </aside>
        <section className="login" aria-labelledby="login-title">
          <header className="login-heading">
            <span className="login-heading-icon">{register ? <UserRoundPlus size={22} aria-hidden="true" /> : <LockKeyhole size={22} aria-hidden="true" />}</span>
            <h1 id="login-title">{register ? "注册账号" : `登录 ${site.name || "HopX"}`}</h1>
            {register && <p>{site.registration === "invite" ? "填写账号、密码和邀请码。" : "创建账号以使用转发服务。"}</p>}
          </header>
          {error && <Alert message={error} type="error" showIcon />}
          <Form form={form} layout="vertical" onFinish={submit} autoComplete="on" initialValues={{ invite }}>
            <Form.Item name="name" label="账号" rules={[{ required: true, message: "请输入账号" }]}>
              <Input autoComplete="username" size="large" placeholder="输入账号" />
            </Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: "请输入密码" }]}>
              <Input.Password autoComplete={register ? "new-password" : "current-password"} size="large" placeholder="输入密码" />
            </Form.Item>
            {register && site.registration !== "no-invite" && (
              <Form.Item name="invite" label={site.registration === "invite" ? "邀请码" : "邀请码（选填）"}
                rules={[{ required: site.registration === "invite", message: "需要邀请码" }]}>
                <Input size="large" placeholder="输入邀请码" />
              </Form.Item>
            )}
            {arithmetic && (
              <div className="login-arithmetic">
                <Form.Item name="answer" label={challenge.value ? `注册验证 · ${challenge.value.left} + ${challenge.value.right}` : "注册验证"}
                  rules={[{ required: true, message: "请输入运算结果" }]}>
                  <InputNumber precision={0} min={0} size="large" placeholder="输入运算结果" disabled={challenge.busy || !challenge.value} />
                </Form.Item>
                <Button type="link" size="small" loading={challenge.busy} onClick={refreshArithmetic}>换一题</Button>
              </div>
            )}
            {arithmetic && challenge.error && <Alert message={challenge.error} type="warning" showIcon />}
            {turnstile && (site.registrationTurnstileSiteKey
              ? <Turnstile key={turnstileAttempt} siteKey={site.registrationTurnstileSiteKey} onToken={setProof} />
              : <Alert type="error" showIcon message="站点尚未配置 Turnstile 公钥" />)}
            <Button className="login-submit" block size="large" type="primary" htmlType="submit" loading={busy}
              icon={<ArrowRight size={17} aria-hidden="true" />} iconPosition="end"
              disabled={arithmetic && (challenge.busy || !challenge.value || !!challenge.error) || turnstile && !proof}>
              {register ? "注册并登录" : "登录"}
            </Button>
          </Form>
          {canRegister && (
            <div className="login-mode">
              <span>{register ? "已有账号？" : "没有账号？"}</span>
              <Button type="link" onClick={changeMode} disabled={busy}>{register ? "返回登录" : "注册账号"}</Button>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

const initialSite: Site = { name: "HopX", announcement: "", registration: "closed" };

function Shell({
  dark,
  setDark,
}: {
  dark: boolean;
  setDark: (value: boolean) => void;
}) {
  const session = useData<User | null>("/me", null);
  const site = useData<Site>("/site", initialSite);
  const [path, setPath] = useState(location.hash.slice(2));
  const [expanded, setExpanded] = useState(true);
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    const change = () => {
      const next = location.hash.slice(2);
      startTransition(() => setPath(next));
      setMobile(false);
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  if ((!session.value && session.busy) || (site.value === initialSite && site.busy))
    return (
      <div className="loading-screen">
        <Spin size="large" />
      </div>
    );
  const user = session.value;
  if (!user) {
    const invite = path.startsWith("register/") ? path.slice("register/".length) : undefined;
    return <Login key={path + site.value.registration} site={site.value} done={session.reload} invite={invite} />;
  }
  const disabledMenus = new Set(
    ([["shop", site.value.showShop], ["orders", site.value.showOrders], ["nodes", site.value.showNodeStatus]] as const)
      .filter(([, enabled]) => enabled === "false").map(([key]) => key),
  );
  const nav = primary.filter(([key]) => user.admin || !disabledMenus.has(key as "shop" | "orders" | "nodes"));
  const allowTunnels = user.allowDevice || site.value.personalTunnels === "true";
  const menus = allowTunnels ? [...nav.slice(0, 3), ["tunnels", "单端隧道", Layers3] as const, ...nav.slice(3)] : nav;
  const [route, query] = path.split("?", 2);
  const page = legacyPages[route] || route;
  const ruleQuery = new URLSearchParams(route === "forward_rules" ? location.search : undefined);
  new URLSearchParams(query).forEach((value, key) => ruleQuery.set(key, value));
  const accessible = (route !== "looking_glass" || site.value.lookingGlass === "true") && (
    menus.some(([key]) => key === page)
    || (user.admin && administration.some(([key]) => key === page))
    || (page === "my-invites" && site.value.invitesEnabled !== "false"));
  const refresh = async () => { await Promise.all([session.reload(), site.reload()]); };
  const renderNav = (
    items: readonly (readonly [string, string, typeof Home])[],
  ) =>
    items.map(([key, label, Icon]) => (
      <a
        key={key}
        href={"#/" + key}
        className={"nav-item " + (page === key ? "active" : "")}
        aria-current={page === key ? "page" : undefined}
      >
        <Icon size={18} strokeWidth={1.7} />
        <span>{label}</span>
      </a>
    ));
  return (
    <div className="app-shell">
      {mobile && (
        <button
          className="nav-backdrop"
          aria-label="关闭菜单"
          onClick={() => setMobile(false)}
        />
      )}
      <header className="topbar">
        <div className="topbar-brand">
          <button
            className="mobile-menu icon-button"
            aria-label="打开菜单"
            aria-expanded={mobile}
            onClick={() => setMobile(true)}
          >
            <Menu size={20} />
          </button>
          <Brand />
        </div>
        <div className="toolbar">
          <button
            className="icon-button"
            onClick={() => setDark(!dark)}
            aria-label={dark ? "切换浅色模式" : "切换深色模式"}
          >
            {dark ? <Sun size={19} /> : <Moon size={19} />}
          </button>
          <a href="#/profile" className="account">
            <span className="avatar">
              {user.name.slice(0, 1).toUpperCase()}
            </span>
            <span>{user.name}</span>
          </a>
          <button
            className="icon-button"
            aria-label="退出登录"
            onClick={() =>
              void api("/logout", "POST").finally(() => session.set(null))
            }
          >
            <LogOut size={17} />
          </button>
        </div>
      </header>
      <aside className={"sidebar " + (mobile ? "mobile-open" : "")}>
        <nav aria-label="主菜单" onClick={(event) => { if ((event.target as HTMLElement).closest("a")) setMobile(false); }}>
          {renderNav(menus)}
          {user.admin && (
            <>
              <button
                className="nav-section"
                onClick={() => setExpanded(!expanded)}
                aria-expanded={expanded}
              >
                管理{" "}
                <ChevronDown className={expanded ? "rotate" : ""} size={14} />
              </button>
              {expanded && renderNav(administration)}
            </>
          )}
        </nav>
      </aside>
      <main className="content">
        <Suspense
          fallback={
            <div className="loading-screen">
              <Spin />
            </div>
          }
        >
        <PageBoundary key={path}>
          {!accessible ? (
            <Alert type="info" showIcon message="此页面当前不可用" />
          ) : page === "" ? (
            <HomePage admin={user.admin} site={site.value} />
          ) : page === "dashboard" ? (
            <AdminDashboard />
          ) : page === "profile" ? (
            <Profile user={user} site={site.value} refresh={session.reload} />
          ) : page === "settings" ? (
            <SiteSettings key={path} refresh={refresh} initialSection={new URLSearchParams(query).get("section")} />
          ) : page === "rules" ? (
            <Rules key={path} user={user} initialQuery={ruleQuery.toString()} refreshUser={session.reload}
              siteProbeInterval={site.value.ruleProbeInterval === "60" ? 60 : 300} showShop={user.admin || !disabledMenus.has("shop")} />
          ) : page === "nodes" ? (
            <Nodes user={user} lookingGlass={site.value.lookingGlass === "true"} />
          ) : (
            <Management
              key={path}
              page={page}
              user={user}
              refresh={refresh}
            />
          )}
        </PageBoundary>
        </Suspense>
      </main>
    </div>
  );
}

function Root() {
  const [dark, setDark] = useState(
    localStorage.getItem("hopx-theme") === "dark",
  );
  useEffect(() => {
    localStorage.setItem("hopx-theme", dark ? "dark" : "light");
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  }, [dark]);
  return (
    <ConfigProvider
      locale={zhCN}
      button={{ autoInsertSpace: false }}
      modal={{ centered: true }}
      form={{ scrollToFirstError: { focus: true, block: "center" } }}
      theme={{
        algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: dark ? "#91b7ff" : "#5f8f76",
          colorLink: dark ? "#91b7ff" : "#5f8f76",
          colorLinkHover: dark ? "#bed4ff" : "#40554d",
          colorSuccess: dark ? "#80c8a0" : "#249467",
          colorWarning: dark ? "#e8bb76" : "#b47722",
          colorError: dark ? "#f6a3a1" : "#d35555",
          colorInfo: dark ? "#91b7ff" : "#5f8f76",
          colorBgContainer: dark ? "#15191f" : "rgba(250, 251, 247, 0.98)",
          colorBgElevated: dark ? "#1b2129" : "rgba(248, 250, 246, 0.98)",
          colorBorder: dark ? "#3b4858" : "rgba(145, 163, 150, 0.22)",
          colorBorderSecondary: dark ? "#2a333f" : "rgba(163, 178, 166, 0.22)",
          colorText: dark ? "#e8edf4" : "#23342d",
          colorTextSecondary: dark ? "#aab5c4" : "#637a71",
          colorTextPlaceholder: dark ? "#8593a5" : "#85978e",
          borderRadius: dark ? 6 : 8,
          controlHeight: 32,
          fontFamily: '"Inter", "PingFang SC", "Microsoft YaHei", sans-serif',
        },
        components: {
          Table: {
            colorBgContainer: dark ? "#15191f" : "transparent",
            headerBg: dark ? "#1c222a" : "rgba(248, 250, 246, 0.98)",
            headerColor: dark ? "#c9d3df" : "#637a71",
            headerSortActiveBg: dark ? "#26313e" : "rgba(235, 243, 232, 0.99)",
            headerSortHoverBg: dark ? "#26313e" : "rgba(242, 247, 239, 0.98)",
            bodySortBg: dark ? "#171d24" : "rgba(249, 251, 246, 0.98)",
            rowHoverBg: dark ? "#1c222a" : "rgba(242, 247, 239, 0.98)",
            rowSelectedBg: dark ? "#1c293c" : "rgba(143, 181, 157, 0.22)",
            rowSelectedHoverBg: dark ? "#233248" : "rgba(95, 143, 118, 0.18)",
            borderColor: dark ? "#2a333f" : "rgba(145, 163, 150, 0.22)",
            headerSplitColor: "transparent",
            headerBorderRadius: 7,
            cellPaddingBlockMD: 10,
            cellPaddingInlineMD: 12,
            cellFontSizeMD: 13,
          },
          Button: {
            defaultShadow: "none",
            primaryShadow: "none",
            primaryColor: dark ? "#131b29" : "#ffffff",
          },
        },
      }}
    >
      <AntApp>
        <Shell dark={dark} setDark={setDark} />
      </AntApp>
    </ConfigProvider>
  );
}
createRoot(document.getElementById("root")!).render(<Root />);
