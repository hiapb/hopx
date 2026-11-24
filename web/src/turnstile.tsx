import { useEffect, useRef, useState } from "react";
import { Button } from "antd";

type Widget = {
  render: (container: HTMLElement, options: {
    sitekey: string;
    action: string;
    size: "compact" | "flexible";
    theme: "light" | "dark";
    callback: (token: string) => void;
    "expired-callback": () => void;
    "timeout-callback": () => void;
    "error-callback": () => void;
    "response-field": boolean;
    retry: "never";
  }) => string;
  remove: (id: string) => void;
};

const scriptURL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
let scriptLoad: Promise<Widget> | undefined;

function loadWidget() {
  const turnstile = () => (window as Window & { turnstile?: Widget }).turnstile;
  scriptLoad ??= new Promise<Widget>((resolve, reject) => {
    const script = document.createElement("script");
    const timeout = window.setTimeout(() => reject(new Error("验证码加载超时")), 15000);
    script.src = scriptURL;
    script.async = true;
    script.onload = () => {
      window.clearTimeout(timeout);
      const widget = turnstile();
      if (widget) resolve(widget);
      else reject(new Error("验证码未加载"));
    };
    script.onerror = () => {
      window.clearTimeout(timeout);
      reject(new Error("验证码未加载"));
    };
    document.head.append(script);
  }).catch(error => {
    document.querySelector(`script[src="${scriptURL}"]`)?.remove();
    scriptLoad = undefined;
    throw error;
  });
  return scriptLoad;
}

export default function Turnstile({ siteKey, onToken }: { siteKey: string; onToken: (token: string) => void }) {
  const container = useRef<HTMLDivElement>(null);
  const [attempt, setAttempt] = useState(0);
  const [status, setStatus] = useState<"loading" | "ready" | "expired" | "error">("loading");

  useEffect(() => {
    const host = container.current;
    if (!host) return;
    let disposed = false;
    let cleanup: (() => void) | undefined;
    onToken("");
    setStatus("loading");

    function invalidate(state: "expired" | "error") {
      if (disposed) return;
      onToken("");
      setStatus(state);
    }

    loadWidget().then(widget => {
      if (disposed) return;
      const id = widget.render(host, {
        sitekey: siteKey,
        action: "register",
        size: host.clientWidth < 300 ? "compact" : "flexible",
        theme: document.documentElement.dataset.theme === "dark" ? "dark" : "light",
        callback: token => {
          if (!disposed) onToken(token);
        },
        "expired-callback": () => invalidate("expired"),
        "timeout-callback": () => invalidate("expired"),
        "error-callback": () => invalidate("error"),
        "response-field": false,
        retry: "never",
      });
      cleanup = () => widget.remove(id);
      setStatus(value => value === "loading" ? "ready" : value);
    }).catch(() => invalidate("error"));

    return () => {
      disposed = true;
      cleanup?.();
    };
  }, [attempt, siteKey, onToken]);

  return (
    <div className="login-turnstile">
      <div ref={container} className="login-turnstile-widget" />
      {status === "loading" && <span role="status">正在加载安全验证…</span>}
      {(status === "expired" || status === "error") && <div className="login-verification-retry">
        <span role="status">{status === "expired" ? "安全验证已过期" : "安全验证加载失败"}</span>
        <Button type="link" onClick={() => setAttempt(attempt + 1)}>重新验证</Button>
      </div>}
    </div>
  );
}
