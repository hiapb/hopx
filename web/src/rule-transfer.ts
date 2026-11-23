import type { Group, Rule } from "./api";

type Config = Record<string, unknown>;

function object(value: unknown): Config {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("需要 JSON 对象");
  return value as Config;
}

function onlyKeys(config: Config, supported: string[]) {
  const unknown = Object.keys(config).filter(key => !supported.includes(key));
  if (unknown.length) throw new Error("暂不支持字段 " + unknown.join("、"));
}

function number(value: unknown, name: string, fallback = 0) {
  if (value == null) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error(name + " 须为非负整数");
  return value;
}

function strings(value: unknown, name: string): string[] {
  if (value == null) return [];
  if (!Array.isArray(value) || value.some(item => typeof item !== "string")) throw new Error(name + " 须为字符串数组");
  return value;
}

const strategies: Record<string, string> = {
  random: "random", round: "round-robin", failover: "first", ip_hash: "ip-hash", least_load: "least-connections",
};

export function legacyRule(config: Config, entry: Group | undefined, path: number[], owner?: number): Partial<Rule> {
  if (!entry) throw new Error("请为 nyanpass 规则选择入口设备组");
  onlyKeys(config, ["name", "listen_port", "dest", "dest_policy", "accept_proxy_protocol", "proxy_protocol", "speed_limit", "ip_limit", "connection_limit", "tls"]);
  const targets = strings(config.dest, "dest");
  const strategy = strategies[String(config.dest_policy || "random")];
  if (typeof strategy !== "string") throw new Error("无法识别负载均衡策略 dest_policy");
  const proxyIn = number(config.accept_proxy_protocol, "accept_proxy_protocol");
  const proxyOut = number(config.proxy_protocol, "proxy_protocol");
  if (proxyIn > 2 || proxyOut > 3) throw new Error("无法识别 Proxy Protocol 设置");
  const speed = number(config.speed_limit, "speed_limit");
  if (speed % 125000) throw new Error("HopX 限速只接受整数 Mbps，请调整 speed_limit");
  const rule: Partial<Rule> = {
    owner, name: typeof config.name === "string" ? config.name : targets[0], enabled: true,
    entry: entry.id, port: number(config.listen_port, "listen_port"), targets, path, strategy,
    protocol: proxyIn || proxyOut === 1 || proxyOut === 3 ? "tcp" : "inherit",
    proxyIn: proxyIn !== 0, proxyInVersion: proxyIn, proxyOut: proxyOut !== 0, proxyOutVersion: Math.min(2, proxyOut),
    rateMbps: speed / 125000, maxIPs: number(config.ip_limit, "ip_limit"), maxConns: number(config.connection_limit, "connection_limit"),
  };
  if (config.tls == null) return rule;
  const tls = object(config.tls);
  onlyKeys(tls, ["shared_type", "shared_uid", "parent_port", "origin_fetch", "shaping", "sni", "empty_sni", "force_empty_sni", "alpn", "cert", "key"]);
  if (tls.shared_type === -1) return rule;
  const mode = number(tls.shared_type, "shared_type");
  if (mode > 2) throw new Error("无法识别 TLS 共享类型");
  const sharedPort = number(tls.parent_port, "parent_port");
  if (mode === 2 && !sharedPort) throw new Error("共享 TLS 子规则需要父端口");
  const certificate = strings(tls.cert, "cert").join("\n");
  const key = strings(tls.key, "key").join("\n");
  if (Boolean(certificate) !== Boolean(key)) throw new Error("TLS 证书和私钥须同时提供");
  const users = tls.shared_uid ?? [];
  const shaping = tls.shaping ?? [];
  if (!Array.isArray(users) || !Array.isArray(shaping)) throw new Error("TLS 用户 ID 与响应筛选须为数组");
  const names = mode === 1 || tls.empty_sni || tls.force_empty_sni || typeof tls.sni !== "string"
    ? [] : tls.sni.split(/[,，]/).map(value => value.trim()).filter(Boolean);
  const host = names[0] || entry.connectHost?.split(/\s+/).find(Boolean) || "localhost";
  return {
    ...rule, protocol: "tcp", tlsCert: certificate, tlsKey: key,
    tlsShared: mode === 1, tlsSharedPort: mode === 2 ? sharedPort : 0,
    tlsAllowedUsers: mode === 1 ? users.map(id => number(id, "shared_uid")) : undefined,
    tlsAllowedNames: mode === 1 ? entry.ingress?.allowedHosts : undefined,
    tlsOrigin: mode === 1 ? 0 : number(tls.origin_fetch, "origin_fetch"),
    tlsRequireEmpty: mode !== 1 && tls.force_empty_sni === true,
    tlsServerNames: names,
    tlsGenerateFor: mode !== 2 && !certificate ? host.replace(/^\[(.*)\]$/, "$1") : undefined,
    tlsALPN: mode === 1 ? [] : strings(tls.alpn, "alpn"),
    responseFilters: shaping.map(filter => number(filter, "shaping")),
    targets: mode === 1 ? [] : targets, path: mode === 1 ? [] : path,
  };
}

function numberedLines(input: string, parse: (line: string) => Config) {
  return input.split(/\r?\n/).flatMap((text, index) => {
    const line = text.trim();
    if (!line) return [];
    try { return [parse(line)]; }
    catch (error) { throw new Error(`第 ${index + 1} 行：${(error as Error).message}`); }
  });
}

function oldRule(line: string): Config {
  const [name, listen, host, target, ...extra] = line.split("#").map(part => part.trim());
  if (!name || listen === undefined || !host || !target || extra.length) {
    throw new Error("旧格式须为 名称#监听端口#目标地址#目标端口");
  }
  const listenPort = listen === "" ? 0 : Number(listen);
  const targetPort = Number(target);
  if ((listen !== "" && !/^\d+$/.test(listen)) || listenPort > 65535 ||
      !/^\d+$/.test(target) || targetPort < 1 || targetPort > 65535) {
    throw new Error("监听端口须为 0 至 65535，目标端口须为 1 至 65535");
  }
  const address = host.includes(":") && !host.startsWith("[") ? "[" + host + "]" : host;
  return { name, listen_port: listenPort, dest: [address + ":" + targetPort] };
}

export function clipboardNeedsGroups(input: string) {
  return /"(?:dest|listen_port)"\s*:/.test(input) ||
    input.split(/\r?\n/).some(line => !line.trim().startsWith("{") && line.includes("#"));
}

export function clipboardConfigs(input: string) {
  return input.trim().startsWith("[")
    ? (JSON.parse(input) as unknown[]).map(object)
    : numberedLines(input, line => line.startsWith("{") || !line.includes("#") ? object(JSON.parse(line)) : oldRule(line));
}

export function batchConfigs(input: string, options: string) {
  const { dest: _, ...overrides } = options.trim() ? object(JSON.parse(options)) : {};
  return numberedLines(input, line => {
    const row = line.startsWith("{") ? object(JSON.parse(line))
      : line.includes("#") ? oldRule(line) : { name: line, dest: [line], dest_policy: "round" };
    return { ...row, ...overrides };
  });
}

export function portChanges(input: string, entry?: Group) {
  return clipboardConfigs(input).map((row, index) => {
    try {
      const { listen_port, port: rawPort, ...fields } = row;
      const port = number(listen_port ?? rawPort, "监听端口");
      if (!port || port > 65535) throw new Error("必须指定已有规则的监听端口");
      if (listen_port === undefined) return { port, config: fields };
      const parsed = legacyRule(row, entry, []);
      const config: Partial<Rule> = {};
      if ("name" in fields) {
        if (typeof row.name !== "string") throw new Error("名称须为字符串");
        config.name = parsed.name;
      }
      if ("dest" in fields) config.targets = parsed.targets;
      if ("dest_policy" in fields) config.strategy = parsed.strategy;
      if ("speed_limit" in fields) config.rateMbps = parsed.rateMbps;
      if ("ip_limit" in fields) config.maxIPs = parsed.maxIPs;
      if ("connection_limit" in fields) config.maxConns = parsed.maxConns;
      if ("accept_proxy_protocol" in fields) {
        config.proxyIn = parsed.proxyIn;
        config.proxyInVersion = parsed.proxyInVersion;
      }
      if ("proxy_protocol" in fields) {
        config.proxyOut = parsed.proxyOut;
        config.proxyOutVersion = parsed.proxyOutVersion;
      }
      if (parsed.protocol === "tcp") config.protocol = "tcp";
      if ("tls" in fields) {
        Object.assign(config, {
          tlsCert: parsed.tlsCert || "", tlsKey: parsed.tlsKey || "", tlsGenerateFor: parsed.tlsGenerateFor || "",
          tlsShared: !!parsed.tlsShared, tlsSharedPort: parsed.tlsSharedPort || 0,
          tlsAllowedNames: parsed.tlsAllowedNames || [], tlsAllowedUsers: parsed.tlsAllowedUsers || [],
          tlsOrigin: parsed.tlsOrigin || 0, tlsRequireEmpty: !!parsed.tlsRequireEmpty,
          tlsServerNames: parsed.tlsServerNames || [], tlsALPN: parsed.tlsALPN || [], responseFilters: parsed.responseFilters || [],
        });
      }
      return { port, config };
    } catch (error) {
      throw new Error(`第 ${index + 1} 条规则：${(error as Error).message}`);
    }
  });
}

export function ruleExport(rows: Rule[]) {
  return [...rows].sort((a, b) => a.id - b.id).map(row => {
    const { in: _, out: __, runtime, reportedAt, effectiveNetwork, ownerName, ...rule } = row;
    return rule;
  });
}

export function nyanpassExport(rows: Rule[], groups: Group[]) {
  const entries = new Map(groups.map(group => [group.id, group]));
  return [...rows].sort((a, b) => a.id - b.id).map(rule => {
    if (rule.protocol === "haproxy-tcp" || rule.protocol === "haproxy-both") {
      throw new Error(rule.name + " 使用 HAProxy 转发，请使用 HopX 导出");
    }
    const { effectiveNetwork } = rule;
    const entry = entries.get(rule.entry);
    const expectedNetwork = rule.proxyIn || (rule.proxyOut && rule.proxyOutVersion !== 2) ||
        rule.tlsCert || rule.tlsShared || rule.tlsSharedPort ? "tcp" : entry?.defaultNetwork || "tcp";
    if (effectiveNetwork && effectiveNetwork !== expectedNetwork) {
      throw new Error(rule.name + " 使用单独指定的监听协议，请使用 HopX 导出");
    }
    if (rule.tlsShared && (rule.tlsAllowedNames || []).join(",") !== (entry?.ingress?.allowedHosts || []).join(",")) {
      throw new Error(rule.name + " 使用规则级 TLS 共享域名，请使用 HopX 导出");
    }
    const strategy = Object.keys(strategies).find(key => strategies[key] === rule.strategy);
    const tls = rule.tlsCert || rule.tlsShared || rule.tlsSharedPort ? {
      shared_type: rule.tlsShared ? 1 : rule.tlsSharedPort ? 2 : 0,
      shared_uid: rule.tlsAllowedUsers || [],
      parent_port: rule.tlsSharedPort || 0,
      origin_fetch: rule.tlsOrigin || 0,
      shaping: rule.responseFilters || [],
      sni: rule.tlsServerNames?.join(",") || "",
      empty_sni: !rule.tlsServerNames?.length,
      force_empty_sni: !!rule.tlsRequireEmpty,
      alpn: rule.tlsALPN || [],
      cert: rule.tlsCert ? rule.tlsCert.trim().split("\n") : [],
      key: rule.tlsKey ? rule.tlsKey.trim().split("\n") : [],
    } : undefined;
    return {
      name: rule.name,
      listen_port: rule.port,
      dest: rule.targets || [],
      dest_policy: strategy || "random",
      accept_proxy_protocol: rule.proxyIn ? rule.proxyInVersion || 1 : 0,
      proxy_protocol: rule.proxyOut ? (rule.proxyOutVersion === 2 && effectiveNetwork === "tcp" ? 3 : rule.proxyOutVersion || 1) : 0,
      speed_limit: rule.rateMbps * 125000,
      ip_limit: rule.maxIPs,
      connection_limit: rule.maxConns,
      tls,
    };
  });
}
