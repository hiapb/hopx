import { useState } from "react";
import { Alert, App, Button, Form, Input, InputNumber, Select, Space, Switch, Table, Tag } from "antd";
import { api, useData } from "./api";
import { useConfirmAction } from "./confirm-action";

export const paymentKinds: Record<string, string> = {
  epay: "易支付",
  epusdt: "EPUSDT",
  tokenpay: "TokenPay",
  cryptomus: "Cryptomus",
};

export type PaymentOption = { id: string; kind: string; name?: string; fee: number };

type PaymentChannel = {
  id: string;
  revision?: string;
  kind: string;
  name: string;
  enabled: boolean;
  fee: number;
  callback: string;
  endpoint: string;
  merchant: string;
  secret: string;
  network: string;
  currency: string;
  sha256: boolean;
};

export default function PaymentChannels() {
  const channels = useData<PaymentChannel[]>("/admin/payment-channels", []);
  const { message } = App.useApp();
  const confirmAction = useConfirmAction();
  const [editor, setEditor] = useState<Partial<PaymentChannel>>();
  const [json, setJSON] = useState<string>();
  const [jsonError, setJSONError] = useState("");
  const [working, setWorking] = useState(false);

  async function save(values: PaymentChannel) {
    setWorking(true);
    try {
      const id = editor?.id;
      await api("/admin/payment-channels" + (id ? "/" + id : ""), id ? "PUT" : "POST", {
        ...editor, ...values, fee: Math.round((values.fee || 0) * 100),
      });
      setEditor(undefined);
      await channels.reload();
      message.success("支付通道已保存");
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setWorking(false);
    }
  }

  async function saveJSON() {
    setWorking(true);
    setJSONError("");
    try {
      const parsed: unknown = JSON.parse(json ?? "");
      if (!Array.isArray(parsed) || parsed.some(row => !row || typeof row !== "object" || Array.isArray(row))) {
        throw new Error("请输入支付通道的 JSON 数组");
      }
      await api("/admin/payment-channels", "PUT", { channels: parsed });
      setJSON(undefined);
      await channels.reload();
      message.success("支付通道已保存");
    } catch (error) {
      setJSONError(error instanceof SyntaxError ? "JSON 格式有误，请检查标点和括号" : (error as Error).message);
    } finally {
      setWorking(false);
    }
  }

  function archive(row: PaymentChannel) {
    confirmAction({
      title: "归档支付通道",
      content: row.name + " 将从收银台移除，已有订单仍可完成支付。",
      okText: "归档",
      onOk: async () => {
        try {
          await api("/admin/payment-channels/" + row.id, "DELETE");
          if (editor?.id === row.id) setEditor(undefined);
          await channels.reload();
          return true;
        } catch (error) {
          message.error((error as Error).message);
          return false;
        }
      },
    });
  }

  return <>
    {channels.error && <Alert className="alert-gap" type="error" showIcon message={channels.error} />}
    <Space wrap className="list-toolbar">
      <Button type="primary" disabled={working} onClick={() => { setJSON(undefined); setEditor({ kind: "epay", enabled: false, fee: 0 }); }}>添加支付通道</Button>
      <Button disabled={channels.busy || working || !!channels.error} onClick={() => {
        setEditor(undefined);
        setJSONError("");
        setJSON(JSON.stringify(channels.value, null, 2));
      }}>编辑支付设置 JSON</Button>
    </Space>
    <Table<PaymentChannel>
      rowKey="id"
      size="middle"
      dataSource={channels.value}
      loading={channels.busy}
      pagination={false}
      columns={[
        { title: "名称", dataIndex: "name" },
        { title: "类型", dataIndex: "kind", render: (kind: string) => paymentKinds[kind] || kind },
        { title: "费率", dataIndex: "fee", render: (fee: number) => (fee / 100) + "%" },
        { title: "状态", dataIndex: "enabled", render: (enabled: boolean) => <Tag color={enabled ? "success" : "default"}>{enabled ? "启用" : "停用"}</Tag> },
        { title: "操作", key: "action", render: (_, row) => <Space wrap>
          <Button size="small" disabled={json !== undefined || working} onClick={() => setEditor({ ...row, fee: row.fee / 100 })}>编辑</Button>
          <Button size="small" disabled={json !== undefined || working} onClick={() => archive(row)}>归档</Button>
        </Space> },
      ]}
    />
    {json !== undefined && <section className="channels-editor" aria-label="支付设置 JSON">
      <h3>编辑支付设置 JSON</h3>
      <p className="muted alert-gap">调整数组顺序可调整通道顺序。fee 以基点填写，100 表示 1%。通道移除使用归档操作。</p>
      {jsonError && <Alert className="alert-gap" type="error" showIcon message={jsonError} />}
      <Input.TextArea className="mono alert-gap" aria-label="支付通道 JSON" rows={14} spellCheck={false} value={json}
        onChange={event => setJSON(event.target.value)} disabled={working} />
      <Space>
        <Button type="primary" loading={working} onClick={() => void saveJSON()}>保存 JSON</Button>
        <Button disabled={working} onClick={() => setJSON(undefined)}>取消</Button>
      </Space>
    </section>}
    {editor && <Form<PaymentChannel> key={editor.id || "new"} layout="vertical" initialValues={editor} onFinish={save} className="channels-editor">
      <h3>{editor.id ? "编辑支付通道" : "添加支付通道"}</h3>
      <div className="settings-fields">
        <Form.Item name="name" label="通道名称" rules={[{ required: true, max: 100 }]}><Input /></Form.Item>
        <Form.Item name="kind" label="支付类型" rules={[{ required: true }]}>
          <Select disabled={!!editor.id} options={Object.entries(paymentKinds).map(([value, label]) => ({ value, label }))} />
        </Form.Item>
        <Form.Item name="endpoint" label="HTTPS 网关" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="callback" label="HTTPS 回调站点"><Input /></Form.Item>
        <Form.Item name="merchant" label="商户号"><Input /></Form.Item>
        <Form.Item name="secret" label="密钥" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Form.Item name="fee" label="充值手续费率"><InputNumber min={0} max={100} precision={2} suffix="%" style={{ width: "100%" }} /></Form.Item>
        <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        <Form.Item noStyle shouldUpdate={(before, after) => before.kind !== after.kind}>
          {({ getFieldValue }) => getFieldValue("kind") !== "epay" && <>
            <Form.Item name="currency" label="币种"><Input /></Form.Item>
            <Form.Item name="network" label="网络"><Input /></Form.Item>
            {getFieldValue("kind") !== "cryptomus" && <Form.Item name="sha256" label="HMAC-SHA256 签名" valuePropName="checked"><Switch /></Form.Item>}
          </>}
        </Form.Item>
      </div>
      <Space>
        <Button type="primary" htmlType="submit" loading={working}>保存通道</Button>
        <Button disabled={working} onClick={() => setEditor(undefined)}>取消</Button>
      </Space>
    </Form>}
  </>;
}
