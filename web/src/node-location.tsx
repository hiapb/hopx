/// <reference types="vite/client" />

import type { Node } from "./api";
import DismissibleTooltip from "./dismissible-tooltip";

const flags = import.meta.glob("/node_modules/flag-icons/flags/4x3/*.svg", {
  eager: true,
  query: "?url&no-inline",
  import: "default",
}) as Record<string, string>;

const regions = new Intl.DisplayNames(["zh-CN"], { type: "region" });

export function nodeRegion(node: Pick<Node, "countryCode">) {
  const code = node.countryCode;
  return code && /^[A-Z]{2}$/.test(code) ? regions.of(code) ?? "" : "";
}

export function nodeDisplayName(node: Pick<Node, "name" | "countryCode"> & Partial<Pick<Node, "region" | "id">>, fallback = "节点") {
  const name = node.name.trim();
  if (name && !/^localhost(?:\.localdomain|\.local)?\.?$/i.test(name)) return name;
  return node.region?.trim() || nodeRegion(node) || (node.id ? `节点 #${node.id}` : fallback);
}

export function NodeFlag({ node }: { node: Pick<Node, "countryCode"> }) {
  const country = nodeRegion(node);
  const flag = node.countryCode && flags[`/node_modules/flag-icons/flags/4x3/${node.countryCode.toLowerCase()}.svg`];
  return flag ? <DismissibleTooltip title={country}>
    <img className="node-country-flag" src={flag} alt={country} loading="lazy" decoding="async" />
  </DismissibleTooltip> : null;
}
