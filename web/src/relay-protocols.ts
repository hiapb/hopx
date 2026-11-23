export const relayModes = [
  { value: "tls", label: "TLS", encrypted: true },
  { value: "tls-mux", label: "TLS / MUX", encrypted: true },
  { value: "wss", label: "WSS", encrypted: true },
  { value: "wss-mux", label: "WSS / MUX", encrypted: true },
  { value: "ws", label: "WS", encrypted: false },
  { value: "https", label: "HTTPS", encrypted: true },
  { value: "http", label: "HTTP", encrypted: false },
];

export function relayModeLabel(value?: string) {
  return relayModes.find(mode => mode.value === value)?.label ?? (value || "TLS");
}

export function relayModeHelp(value?: string) {
  if (value === "tls-mux" || value === "wss-mux") return "使用 TLS 加密，并复用首跳连接。";
  return relayModes.find(mode => mode.value === value)?.encrypted === false
    ? "此连接未启用 TLS。"
    : "使用 TLS 加密连接。";
}
