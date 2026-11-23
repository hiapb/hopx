import { useEffect, useRef, useState } from "react";
import { App, Button } from "antd";
import { Check, CircleAlert, RefreshCw } from "lucide-react";
import type { DataReload } from "./api";

type Phase = "idle" | "pending" | "done" | "failed";

export default function RefreshButton({ reload, label = "刷新" }: { reload: readonly DataReload[]; label?: string }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const active = useRef(false);
  const { message } = App.useApp();

  useEffect(() => {
    if (phase !== "done" && phase !== "failed") return;
    const timer = window.setTimeout(() => setPhase("idle"), 2400);
    return () => window.clearTimeout(timer);
  }, [phase]);

  async function refresh() {
    if (active.current) return;
    active.current = true;
    setPhase("pending");
    try {
      const results = await Promise.allSettled(reload.map(run => run({ throwOnError: true })));
      const failure = results.find(result => result.status === "rejected" && result.reason?.name !== "AbortError");
      if (failure?.status === "rejected") {
        setPhase("failed");
        message.error(failure.reason instanceof Error ? failure.reason.message : "刷新失败，请重试");
      } else {
        setPhase(results.every(result => result.status === "fulfilled") ? "done" : "idle");
      }
    } finally {
      active.current = false;
    }
  }

  const Icon = phase === "done" ? Check : phase === "failed" ? CircleAlert : RefreshCw;
  const status = phase === "pending" ? "刷新中" : phase === "done" ? "已刷新" : phase === "failed" ? "刷新失败" : "";
  return <Button className="refresh-button" data-phase={phase} disabled={phase === "pending"}
    aria-busy={phase === "pending"} onClick={() => void refresh()}
    icon={<Icon size={15} aria-hidden="true" className="refresh-button-icon" />}>
    <span aria-live="polite">{status || label}</span>
  </Button>;
}
