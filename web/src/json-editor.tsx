import { useState } from "react";
import { Alert, Input, Modal } from "antd";

export default function JsonEditor({
  title, value, onClose, onSave,
}: {
  title: string;
  value: object;
  onClose: () => void;
  onSave: (value: Record<string, unknown>) => Promise<boolean>;
}) {
  const [text, setText] = useState(() => JSON.stringify(value, null, 2));
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function save() {
    setError("");
    setSaving(true);
    try {
      const config: unknown = JSON.parse(text);
      if (!config || typeof config !== "object" || Array.isArray(config)) {
        throw new Error("请输入一个 JSON 对象");
      }
      if (await onSave(config as Record<string, unknown>)) onClose();
    } catch (error) {
      setError(error instanceof SyntaxError ? "JSON 格式有误，请检查标点和括号" : (error as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return <Modal open title={title} onCancel={onClose} onOk={save} okText="保存" width={720} confirmLoading={saving}>
    {error && <Alert className="alert-gap" type="error" showIcon message={error} />}
    <Input.TextArea aria-label="JSON 配置" className="dialog-code" rows={17} spellCheck={false} value={text} onChange={(event) => setText(event.target.value)} />
  </Modal>;
}
