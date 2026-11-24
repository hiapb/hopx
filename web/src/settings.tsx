import { useEffect, useState } from "react";
import { Alert, App, Button, Form, Grid, Input, InputNumber, Radio, Select, Space, Spin, Tabs } from "antd";
import { Activity, Plus, Trash2 } from "lucide-react";
import { api, useData } from "./api";
import type { HomeLink } from "./api";
import PaymentChannels from "./payment-channels";

type Field = {
  name: string;
  label: string;
  kind?: "area" | "secret" | "select" | "percent";
  required?: boolean;
  options?: {value: string; label: string}[];
};

const fields: Field[] = [
  { name: "name", label: "站点名称", required: true },
  { name: "announcement", label: "站点公告", kind: "area" },
  {
    name: "registration",
    label: "注册模式",
    kind: "select",
    options: [
      { value: "closed", label: "关闭" },
      { value: "open", label: "开放" },
      { value: "no-invite", label: "开放，禁用邀请" },
      { value: "invite", label: "仅邀请" },
    ],
  },
  { name: "epayGateway", label: "易支付网关 HTTPS 地址" },
  { name: "epayPID", label: "易支付商户 ID" },
  {name:"epusdtGateway",label:"EPUSDT 下单接口 URL"},
  {name:"epusdtPID",label:"EPUSDT 商户 PID（旧版留空）"},
  {name:"epusdtKey",label:"EPUSDT API 密钥",kind:"secret"},
  {name:"epusdtNetwork",label:"EPUSDT 链（可选）"},
  {name:"epusdtCurrency",label:"EPUSDT 币种（可选）"},
  {name:"epusdtSHA256",label:"EPUSDT 签名",kind:"select",options:[{value:"false",label:"MD5"},{value:"true",label:"HMAC-SHA256"}]},
  {name:"tokenpayGateway",label:"TokenPay CreateOrder URL"},
  {name:"tokenpayKey",label:"TokenPay API 密钥",kind:"secret"},
  {name:"tokenpayCurrency",label:"TokenPay 币种（默认 USDT_TRC20）"},
  {name:"tokenpaySHA256",label:"TokenPay 签名",kind:"select",options:[{value:"false",label:"MD5"},{value:"true",label:"HMAC-SHA256"}]},
  {name:"cryptomusGateway",label:"Cryptomus 下单接口 URL"},
  {name:"cryptomusPID",label:"Cryptomus 商户 ID"},
  {name:"cryptomusKey",label:"Cryptomus Payment Key",kind:"secret"},
  {name:"cryptomusCurrency",label:"Cryptomus 币种（默认 CNY）"},
  {name:"cryptomusNetwork",label:"Cryptomus 链（可选）"},

  { name: "minRecharge", label: "最低充值金额（分）" },
  {
    name: "epayKey",
    label: "易支付商户密钥",
    kind: "secret",
  },
  { name: "referralRate", label: "邀请返佣（1000 = 10%）" },
  { name: "referralFirstOnly", label: "邀请返佣周期", kind: "select", options: [
    {value: "true", label: "首次消费"},
    {value: "false", label: "每次消费"},
  ] },
  { name: "referralRequireBinding", label: "返佣要求邀请者绑定 Telegram", kind: "select", options: [
    {value: "false", label: "无需绑定"},
    {value: "true", label: "要求绑定"},
  ] },
  {
    name: "telegramUsername",
    label: "Telegram 机器人用户名",
  },
  {
    name: "telegramToken",
    label: "Telegram 机器人令牌",
    kind: "secret",
  },
  {
    name: "telegramWebhookSecret",
    label: "Telegram 回调密钥",
    kind: "secret",
  },
  {
    name: "registrationVerification",
    label: "验证码类型",
    kind: "select",
    options: [
      { value: "off", label: "关闭" },
      { value: "arithmetic", label: "算术验证" },
      { value: "turnstile", label: "Cloudflare Turnstile" },
    ],
  },
  { name: "registrationTurnstileSiteKey", label: "Turnstile 站点密钥", required: true },
  { name: "registrationTurnstileSecret", label: "Turnstile 服务端密钥", kind: "secret" },
  {
    name: "personalTunnels",
    label: "允许用户创建单端隧道",
    kind: "select",
    options: [
      { value: "false", label: "关闭" },
      { value: "true", label: "允许" },
    ],
  },
  {
    name: "hideIPs",
    label: "普通用户的站点节点地址显示",
    kind: "select",
    options: [
      { value: "false", label: "显示" },
      { value: "true", label: "隐藏" },
    ],
  },
  {
    name: "hideAdminIPs",
    label: "管理员的节点地址显示",
    kind: "select",
    options: [
      { value: "false", label: "显示" },
      { value: "true", label: "隐藏" },
    ],
  },
];

fields.push(
  { name: "lookingGlass", label: "Looking Glass 节点 Ping", kind: "select", options: [
    { value: "false", label: "关闭" }, { value: "true", label: "开启" },
  ] },
  { name: "diagnoseIPVisibility", label: "Ping 结果的 IP 显示", kind: "select", options: [
    { value: "admin", label: "仅管理员可见" }, { value: "all", label: "所有用户可见" }, { value: "none", label: "隐藏" },
  ] },
);

fields.push(...[
  ["showShop", "商城"],
  ["showOrders", "我的订单"],
  ["showNodeStatus", "节点状态"],
  ["invitesEnabled", "个人中心的邀请入口"],
].map(([name, label]): Field => ({
  name,
  label,
  kind: "select",
  options: [{ value: "true", label: "显示" }, { value: "false", label: "隐藏" }],
})));

for (const [kind, name] of [["epay", "易支付"], ["epusdt", "EPUSDT"], ["tokenpay", "TokenPay"], ["cryptomus", "Cryptomus"]]) {
  fields.push(
    { name: kind + "Enabled", label: name + "通道", kind: "select", options: [
      { value: "auto", label: "配置完成后启用" },
      { value: "true", label: "启用" },
      { value: "false", label: "停用" },
    ] },
    { name: kind + "Fee", label: "充值手续费率", kind: "percent" },
    { name: kind + "Callback", label: "HTTPS 回调站点（留空使用面板地址）" },
  );
}

const sections = [
  { key: "site", label: "基本与权限", match: /^(name|registration|personalTunnels|hide|show|lookingGlass|diagnoseIP)/ },
  { key: "diagnostics", label: "链路诊断", match: /^ruleProbeInterval$/ },
  { key: "announcement", label: "公告与推广", match: /^announcement$/ },
  { key: "payment", label: "支付", match: /^(minRecharge|epay)/ },
  { key: "epusdt", label: "EPUSDT", match: /^epusdt/ },
  { key: "tokenpay", label: "TokenPay", match: /^tokenpay/ },
  { key: "cryptomus", label: "Cryptomus", match: /^cryptomus/ },
  { key: "referral", label: "邀请", match: /^(referral|invitesEnabled)/ },
  { key: "telegram", label: "Telegram", match: /^telegram/ },
];

type SettingsValues = Record<string, string | HomeLink[] | undefined> & { name?: string; homeLinks?: HomeLink[] };

function restoreSettings(values: Record<string, string>): SettingsValues {
  return {
    ruleProbeInterval: "300",
    registrationVerification: values.registrationChallenge === "true" ? "arithmetic" : "off",
    ...values,
    homeLinks: JSON.parse(values.homeLinks || "[]") as HomeLink[],
  };
}

export default function Settings({ refresh, initialSection }: { refresh: () => Promise<void>; initialSection: string | null }) {
  const desktop = Grid.useBreakpoint().lg;
  const data = useData<Record<string, string> | null>("/admin/settings", null);
  const [form] = Form.useForm<SettingsValues>();
  const captchaType = Form.useWatch("registrationVerification", { form, preserve: true });
  const hasTurnstileSecret = data.value?.registrationTurnstileSecretConfigured === "true";
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [section, setSection] = useState(sections.find(item => item.key === initialSection)?.key ?? "site");
  const { message } = App.useApp();

  useEffect(() => {
    if (data.value) {
      form.setFieldsValue(restoreSettings(data.value));
      setDirty(false);
    }
  }, [data.value, form]);

  async function save() {
    const { homeLinks, registrationTurnstileSecretConfigured, ...values } = form.getFieldsValue(true);
    if (!values.name?.trim()) {
      setSection("site");
      message.error("请填写站点名称");
      return;
    }
    if (values.registrationVerification === "turnstile" &&
        (!values.registrationTurnstileSiteKey?.toString().trim() ||
          (!hasTurnstileSecret && !values.registrationTurnstileSecret?.toString().trim()))) {
      setSection("site");
      message.error("请填写 Turnstile 站点密钥和服务端密钥");
      return;
    }
    const next = { ...values, homeLinks: JSON.stringify(homeLinks ?? []) };
    const updated = Object.fromEntries(Object.entries(next).filter(([key, value]) => typeof value === "string" && value !== data.value?.[key]));
    setSaving(true);
    try {
      await api("/admin/settings", "PUT", updated);
      await Promise.all([data.reload({ throwOnError: true }), refresh()]);
      message.success("设置已保存");
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="panel-table">
      <header className="page-head"><h1>站点设置</h1></header>
      {data.error && <Alert type="error" showIcon message={data.error} />}
      {!data.value ? data.busy && <Spin /> : (
        <div className="settings-page">
          <Tabs tabPosition={desktop ? "left" : "top"} className="settings-sections" activeKey={section} onChange={setSection} items={[
            ...sections.map(({ key, label, match }) => ({
              key, label,
              children: section === key && <Form form={form} layout="vertical" onFinish={save} onValuesChange={() => setDirty(true)}>
                {key === "diagnostics" ? <section className="probe-settings" aria-labelledby="probe-settings-title">
                  <header className="probe-settings-heading">
                    <span className="probe-settings-icon"><Activity size={19} aria-hidden="true" /></span>
                    <div>
                      <h2 id="probe-settings-title">历史采样</h2>
                      <p>已启用的规则按设定间隔采样，历史保留 7 天。</p>
                    </div>
                  </header>
                  <Form.Item name="ruleProbeInterval" label="默认采样间隔">
                    <Radio.Group className="probe-interval-choices" aria-label="默认采样间隔">
                      <Radio value="300">每 5 分钟</Radio>
                      <Radio value="60">每 1 分钟</Radio>
                    </Radio.Group>
                  </Form.Item>
                </section> : <div className="settings-fields">
                  {fields.filter((field) => match.test(field.name) &&
                    (!field.name.startsWith("registrationTurnstile") || captchaType === "turnstile")).map((field) => (
                    <Form.Item key={field.name} name={field.name} label={field.label}
                      className={field.kind === "area" ? "field-wide" : undefined}
                      {...(field.kind === "percent" && {
                        getValueProps: (value: string) => ({ value: Number(value || 0) / 100 }),
                        normalize: (value: number | null) => String(Math.round((value || 0) * 100)),
                      })}
                      rules={field.required || (field.name === "registrationTurnstileSecret" && !hasTurnstileSecret)
                        ? [{ required: true, whitespace: true }] : undefined}>
                      {field.kind === "select" ? <Select options={field.options} />
                        : field.kind === "percent" ? <InputNumber min={0} max={100} precision={2} suffix="%" style={{ width: "100%" }} />
                        : field.kind === "secret" ? <Input.Password autoComplete="new-password" placeholder={
                          field.name === "registrationTurnstileSecret" && hasTurnstileSecret ? "已配置，留空保留" : undefined
                        } />
                        : field.kind === "area" ? <Input.TextArea rows={8} />
                        : <Input />}
                    </Form.Item>
                  ))}
                </div>}
                {key === "announcement" && <section className="home-link-settings" aria-labelledby="home-link-settings-title">
                  <h2 id="home-link-settings-title" className="section-title">推广链接</h2>
                  <Form.List name="homeLinks">
                    {(links, { add, remove }) => (
                      <>
                        {links.map(({ key, name }) => (
                          <div className="home-link-field" key={key}>
                            <Form.Item name={[name, "title"]} label="显示名称"
                              rules={[{ required: true, whitespace: true, message: "请填写显示名称" }]}>
                              <Input />
                            </Form.Item>
                            <Form.Item name={[name, "url"]} label="链接地址"
                              rules={[{ required: true, pattern: /^https?:\/\/[^\s]+$/i,
                                transform: value => value?.trim(), message: "请填写完整的 HTTP 或 HTTPS 地址" }]}>
                              <Input placeholder="https://" />
                            </Form.Item>
                            <Button type="text" danger icon={<Trash2 size={16} />}
                              aria-label={`删除推广链接 ${name + 1}`} onClick={() => remove(name)} />
                          </div>
                        ))}
                        <Button icon={<Plus size={15} />} onClick={() => add({ title: "", url: "" })}>添加推广链接</Button>
                      </>
                    )}
                  </Form.List>
                </section>}
                <div className="settings-footer">
                  <span role="status">{dirty ? "有未保存的修改" : ""}</span>
                  <Space>
                    <Button disabled={!dirty || saving} onClick={() => { form.setFieldsValue(restoreSettings(data.value!)); setDirty(false); }}>还原</Button>
                    <Button type="primary" loading={saving} disabled={!dirty} htmlType="submit">保存设置</Button>
                  </Space>
                </div>
              </Form>,
            })),
            { key: "payment-channels", label: "支付通道", children: <PaymentChannels /> },
          ]} />
        </div>
      )}
    </section>
  );
}
