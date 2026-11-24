/// <reference types="vite/client" />

import type { Node } from "./api";

const flags = import.meta.glob("/node_modules/flag-icons/flags/4x3/*.svg", {
  eager: true,
  query: "?url&no-inline",
  import: "default",
}) as Record<string, string>;

const regions = new Intl.DisplayNames(["zh-CN"], { type: "region" });

export function nodeRegion(node: Node) {
  const code = node.countryCode;
  return code && /^[A-Z]{2}$/.test(code) ? regions.of(code) ?? "" : "";
}

export function nodeDisplayName(node: Node) {
  if (!/^localhost(?:\.localdomain|\.local)?\.?$/i.test(node.name)) return node.name;
  return node.region.trim() || nodeRegion(node) || `节点 #${node.id}`;
}

export function NodeFlag({ node }: { node: Node }) {
  const country = nodeRegion(node);
  const flag = node.countryCode && flags[`/node_modules/flag-icons/flags/4x3/${node.countryCode.toLowerCase()}.svg`];
  return flag ? <img className="node-country-flag" src={flag} alt={country} title={country} loading="lazy" decoding="async" /> : null;
}
