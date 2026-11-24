import { useState } from "react";
import { Alert, App, Button, Descriptions, Form, Input, InputNumber, Modal, Progress, Space, Switch, Typography } from "antd";
import { Wallet } from "lucide-react";
import { api, bytes, currency, date, hasPlan, planExpiryLabel, ruleLimitLabel, useData } from "./api";
import type { Site, User } from "./api";
import RefreshButton from "./refresh-button";
import { useConfirmAction } from "./confirm-action";

type Renewal = { planId: number; name: string; price: number; expires: number; nextExpires: number; quota: number; unlimitedTraffic: boolean; balance: number; epoch: number };
const renewalDate = (expires: number) => expires >= 253402300799 ? "不限期" : expires > 0 ? date(expires) : "未设置";

export default function Profile({ user, site, refresh }: { user: User; site: Site; refresh: () => Promise<void> }) {
  const { message } = App.useApp();
  const confirmAction = useConfirmAction();
  const [working, setWorking] = useState(false);
  const [quoting, setQuoting] = useState(false);
  const [renewal, setRenewal] = useState<Renewal>();
  const [renewing, setRenewing] = useState(false);
  const [renewalError, setRenewalError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [password] = Form.useForm();
  const [telegramLink, setTelegramLink] = useState("");
  const telegram = useData<{ available: boolean; linked: boolean; enabled: boolean; income: boolean; updown: boolean }>("/telegram", { available: false, linked: false, enabled: false, income: false, updown: false });
  const plan = user.service;
  const subscribed = hasPlan(user);
  const showShop = user.admin || site.showShop !== "false";
  const shortfall = renewal ? Math.max(0, renewal.price - renewal.balance) : 0;
  const inviteLink = location.origin + location.pathname + "#/register/" + encodeURIComponent(user.invite);

  async function previewRenewal() {
    setQuoting(true);
    setRenewalError("");
    try {
      setRenewal(await api<Renewal>("/me/renew"));
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setQuoting(false);
    }
  }

  async function confirmRenewal() {
    if (!renewal || renewing || shortfall) return;
    setRenewing(true);
    setRenewalError("");
    try {
      await api("/me/renew", "POST", {
        expectedPlan: renewal.planId, expectedPrice: renewal.price, expectedEpoch: renewal.epoch,
        expectedQuota: renewal.quota, expectedUnlimitedTraffic: renewal.unlimitedTraffic,
      });
      setRenewal(undefined);
      await refresh();
      message.success("续费成功");
    } catch (error) {
      setRenewalError((error as Error).message);
    } finally {
      setRenewing(false);
    }
  }

  function transferCommission(amount: number) {
    const cents = Math.round(amount * 100);
    confirmAction({
      title: "佣金转入钱包",
      content: <p>将 {currency(cents)} 佣金转入钱包。转入后钱包余额为 {currency(user.balance + cents)}。</p>,
      okText: "确认转入",
      onOk: () => action("/me/affiliate-transfer", "POST", { amount: cents }),
    });
  }

  function confirmPassword(values: { password: string; newPassword: string }) {
    confirmAction({
      title: "重置密码",
      content: "保存后，此账号的现有登录会失效。",
      okText: "确认重置",
      onOk: async () => {
        if (!await action("/me", "PATCH", values)) return false;
        password.resetFields();
        window.location.reload();
        return true;
      },
    });
  }

  async function action(path: string, method: string, values?: unknown) {
    setWorking(true);
    try {
      await api(path, method, values);
      await (path === "/telegram" ? telegram.reload() : refresh());
      message.success("已保存");
      return true;
    } catch (error) {
      message.error((error as Error).message);
      return false;
    } finally {
      setWorking(false);
    }
  }

  const commissionForm = user.affiliateBalance > 0 && (
    <Form name="commission-transfer" layout="inline" className="profile-commission"
      onFinish={(values: { amount: number }) => transferCommission(values.amount)}>
      <Form.Item name="amount" label="转入金额" rules={[{ required: true }]}>
        <InputNumber prefix="¥" min={0.01} max={user.affiliateBalance / 100} step={0.01} precision={2} />
      </Form.Item>
      <Button htmlType="submit" loading={working}>佣金转入钱包</Button>
    </Form>
  );

  return (
    <div className="profile-page panel-table">
      <header className="page-head">
        <div>
          <h1>个人中心</h1>
          <p>{user.name} · {user.admin ? "管理员" : plan?.group || "个人账号"}</p>
        </div>
        <Space wrap>
          {(user.admin || site.showOrders !== "false") && <Button href="#/orders">我的订单</Button>}
          {showShop && <Button type="primary" href="#/shop">充值</Button>}
        </Space>
      </header>
      <div className="profile-grid">
        <section className="profile-section" aria-labelledby="profile-service">
          <h2 id="profile-service">套餐与流量</h2>
          {user.serviceBlock && <Alert className="alert-gap" type="info" showIcon message={user.serviceBlock} />}
          <div className="profile-usage">
            <div><span>已用流量</span><strong>{bytes(user.used)} / {subscribed && user.unlimitedTraffic ? "不限流量" : bytes(subscribed ? user.quota : 0)}</strong></div>
            {subscribed && !user.unlimitedTraffic && user.quota > 0 && <Progress percent={Math.min(100, Math.round(user.used / user.quota * 100))} />}
          </div>
          <Descriptions size="small" layout="vertical" column={{ xs: 2, sm: 3 }} colon={false} items={[
            { key: "plan", label: "当前套餐", children: subscribed ? plan?.plan || "#" + user.planId : "未订购套餐" },
            { key: "expires", label: "到期时间", children: planExpiryLabel(user) },
            { key: "limit", label: "规则上限", children: ruleLimitLabel(user) },
            ...(plan?.group ? [{ key: "group", label: "用户组", children: plan.group }] : []),
            ...(plan?.rateMbps ? [{ key: "rate", label: "用户限速", children: plan.rateMbps + " Mbps" }] : []),
            ...(plan?.maxIPs ? [{ key: "ips", label: "IP 数量上限", children: plan.maxIPs }] : []),
            ...(plan?.maxConnections ? [{ key: "connections", label: "连接数上限", children: plan.maxConnections }] : []),
            ...(subscribed && plan?.plan ? [{ key: "renewPrice", label: "续费价格", children: currency(plan.renewPrice) }] : []),
          ]} />
          {subscribed ? <Button className="profile-commission" loading={quoting} onClick={() => void previewRenewal()}>立即续费</Button>
            : showShop && <Button className="profile-commission" href="#/shop">选购套餐</Button>}
        </section>

        <section className="profile-section" aria-labelledby="profile-wallet">
          <h2 id="profile-wallet">钱包</h2>
          <dl className="wallet-summary">
            <div><dt>钱包余额</dt><dd>{currency(user.balance)}</dd></div>
            <div><dt>佣金余额</dt><dd>{currency(user.affiliateBalance)}</dd></div>
          </dl>
          <Form name="wallet-transfer" layout="vertical" className="profile-form"
            onFinish={(values: { recipient: string; amount: number }) =>
              action("/me/transfer", "POST", { recipient: values.recipient, amount: Math.round(values.amount * 100) })}>
            <h3>划转余额</h3>
            <div className="profile-fields">
              <Form.Item name="recipient" label="收款账号" rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
              <Form.Item name="amount" label="金额" rules={[{ required: true }]}>
                <InputNumber prefix="¥" min={0.01} step={0.01} precision={2} style={{ width: "100%" }} />
              </Form.Item>
            </div>
            <Button htmlType="submit" type="primary" loading={working}>划转</Button>
          </Form>
          {site.invitesEnabled === "false" && commissionForm}
        </section>

        <section className="profile-section" aria-labelledby="profile-security">
          <h2 id="profile-security">账户设置</h2>
          <div className="profile-setting">
            <div><strong>自动续费</strong><p className="muted">套餐到期或流量用完时，从钱包扣款续费。</p></div>
            <Switch checked={subscribed && user.autoRenew} disabled={working || !subscribed} aria-label="自动续费" onChange={(autoRenew) => void action("/me", "PATCH", { autoRenew })} />
          </div>
          <Form name="change-password" form={password} layout="vertical" className="profile-form" onFinish={confirmPassword}>
            <h3>修改密码</h3>
            <div className="profile-fields">
              <Form.Item name="password" label="当前密码" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item>
              <Form.Item name="newPassword" label="新密码" rules={[{ required: true, min: 10 }]}>
                <Input.Password autoComplete="new-password" visibilityToggle={{ visible: showPassword, onVisibleChange: setShowPassword }} />
              </Form.Item>
            </div>
            <Space wrap>
              <Button htmlType="submit" type="primary" loading={working}>重置密码</Button>
              <Button disabled={working} onClick={() => {
                const random = crypto.getRandomValues(new Uint8Array(16));
                password.setFieldValue("newPassword", Array.from(random, byte => byte.toString(16).padStart(2, "0")).join(""));
                setShowPassword(true);
              }}>生成随机密码</Button>
            </Space>
          </Form>
        </section>

        {site.invitesEnabled !== "false" && (
          <section className="profile-section" aria-labelledby="profile-invites">
            <h2 id="profile-invites">邀请</h2>
            <div className="profile-invite-content">
              {plan && <dl className="profile-referral">
                <div><dt>返佣比例</dt><dd>{(plan.referralRate / 100).toFixed(2)}%</dd></div>
                <div><dt>返佣周期</dt><dd>{plan.referralFirstOnly ? "首次消费" : "每次消费"}</dd></div>
              </dl>}
              {plan?.inviteRegistrationEnabled && user.invite && (
                <Typography.Paragraph copyable={{ text: inviteLink }} className="profile-invite">{inviteLink}</Typography.Paragraph>
              )}
              {plan && !plan.inviteRegistrationEnabled && <p className="muted">当前账号的邀请注册已停用。</p>}
              <Space wrap>
                <Button href="#/my-invites">邀请记录</Button>
                {plan?.inviteRegistrationEnabled && <Button onClick={() => confirmAction({ title: "更新邀请码？", onOk: () => action("/me", "PATCH", { resetInvite: true }) })}>更新邀请码</Button>}
              </Space>
              {commissionForm}
            </div>
          </section>
        )}

        {telegram.value.available && (
          <section className="profile-section profile-full-width" aria-labelledby="profile-telegram">
            <h2 id="profile-telegram">Telegram 通知</h2>
            {telegram.error && <Alert type="error" message={telegram.error} />}
            <Space wrap>
              {telegram.value.linked ? <>
                <Switch checkedChildren="已启用" unCheckedChildren="已停用" checked={telegram.value.enabled} disabled={working} aria-label="Telegram 通知" onChange={(enabled) => void action("/telegram", "PATCH", { enabled })} />
                <Button onClick={() => confirmAction({ title: "解除 Telegram 关联？", onOk: () => action("/telegram", "PATCH", { unlink: true }) })}>解除关联</Button>
              </> : <>
                <Button onClick={async () => {
                  try { setTelegramLink((await api<{ url: string }>("/telegram", "POST")).url); }
                  catch (error) { message.error((error as Error).message); }
                }}>关联 Telegram</Button>
                <RefreshButton reload={[telegram.reload]} label="刷新状态" />
              </>}
              {telegramLink && <a href={telegramLink} target="_blank" rel="noreferrer">打开 Telegram 机器人</a>}
            </Space>
            {telegram.value.linked && <Descriptions size="small" column={1} items={[
              { key: "income", label: "充值到账", children: <Switch checked={telegram.value.income} disabled={working || !telegram.value.enabled} aria-label="充值到账" onChange={(income) => void action("/telegram", "PATCH", { income })} /> },
              { key: "updown", label: "设备离线与恢复", children: <Switch checked={telegram.value.updown} disabled={working || !telegram.value.enabled} aria-label="设备离线与恢复" onChange={(updown) => void action("/telegram", "PATCH", { updown })} /> },
            ]} />}
          </section>
        )}
      </div>
      <Modal open={!!renewal} title="套餐续费" width={460} className="renewal-modal"
        onCancel={() => { if (!renewing) setRenewal(undefined); }}
        onOk={() => void confirmRenewal()} okText="确认续费" confirmLoading={renewing}
        closable={!renewing} maskClosable={false} cancelButtonProps={{ disabled: renewing }}
        okButtonProps={{ disabled: shortfall > 0 }}
        footer={shortfall > 0 && showShop ? (_, { CancelBtn }) => <><CancelBtn /><Button type="primary" href="#/shop">前往充值</Button></> : undefined}
      >
        {renewal && <>
          <div className="renewal-payment">
            <span className="renewal-icon"><Wallet size={20} aria-hidden="true" /></span>
            <div><span className="muted">当前套餐</span><strong>{renewal.name}</strong></div>
            <div className="renewal-price"><span className="muted">应付金额</span><strong>{currency(renewal.price)}</strong></div>
          </div>
          <dl className="renewal-details">
            <div><dt>钱包余额</dt><dd>{currency(renewal.balance)}</dd></div>
            <div><dt>当前到期时间</dt><dd>{renewalDate(renewal.expires)}</dd></div>
            <div><dt>续费后到期时间</dt><dd>{renewalDate(renewal.nextExpires)}</dd></div>
            <div><dt>续费后流量配额</dt><dd>{renewal.unlimitedTraffic ? "不限流量" : bytes(renewal.quota)}</dd></div>
          </dl>
          {shortfall > 0 && <Alert type="warning" showIcon message={`钱包余额不足，还差 ${currency(shortfall)}`} />}
          {renewalError && <Alert type="error" showIcon message={renewalError} />}
        </>}
      </Modal>
    </div>
  );
}
