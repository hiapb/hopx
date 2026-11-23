import { useState } from "react";
import type { ReactNode } from "react";
import { Alert, Segmented, Spin } from "antd";
import { ArrowDownUp, CalendarDays, Layers3, UsersRound, Wallet } from "lucide-react";
import { bytes, currency, useData } from "./api";
import RefreshButton from "./refresh-button";

type Rank = { id: number; name: string; bytes: number };
type Statistics = {
  incomeToday: number;
  incomeYesterday: number;
  incomeMonth: number;
  incomePrevious: number;
  trafficToday: number;
  trafficYesterday: number;
  users: number;
  pendingDiagnostics: number;
  usersToday: Rank[];
  usersYesterday: Rank[];
  groupsToday: Rank[];
  groupsYesterday: Rank[];
};

function Metric({ label, value, relatedLabel, relatedValue, icon }: {
  label: string; value: ReactNode; relatedLabel: string; relatedValue: ReactNode; icon: ReactNode;
}) {
  return <dl className="dashboard-metric">
    <div className="dashboard-metric-main">
      <dt><span className="dashboard-metric-icon" aria-hidden="true">{icon}</span>{label}</dt>
      <dd>{value}</dd>
    </div>
    <div className="dashboard-metric-related"><dt>{relatedLabel}</dt><dd>{relatedValue}</dd></div>
  </dl>;
}

function Ranking({ rows, users }: { rows: Rank[]; users: boolean }) {
  const max = rows[0]?.bytes || 1;
  if (!rows.length) return <p className="dashboard-ranking-empty">此时段暂无流量数据</p>;
  return <ol className="dashboard-ranking-list" role="list">
    {rows.map(row => <li key={row.id}>
      <div className="dashboard-ranking-row">
        <div className="dashboard-ranking-name">
          {users ? <a href={"#/rules?owner=" + row.id}>{row.name}</a> : <span>{row.name}</span>}
          <small>#{row.id}</small>
        </div>
        <strong>{bytes(row.bytes)}</strong>
      </div>
      <div className="dashboard-ranking-track" aria-hidden="true">
        <span style={{ width: Math.min(100, row.bytes / max * 100) + "%" }} />
      </div>
    </li>)}
  </ol>;
}

export default function AdminDashboard() {
  const stats = useData<Statistics | null>("/admin/statistics", null);
  const [period, setPeriod] = useState<"today" | "yesterday">("today");
  const s = stats.value;
  return <section className="admin-dashboard" aria-labelledby="dashboard-title">
    <header className="page-head dashboard-head">
      <div><h1 id="dashboard-title">仪表盘</h1><p>统计时区 UTC · 流量按节点上报时间计入</p></div>
      <RefreshButton reload={[stats.reload]} />
    </header>
    {stats.error && <Alert className="alert-gap" type="error" showIcon message={stats.error} />}
    {!s && stats.busy && <div className="dashboard-loading" role="status"><Spin size="small" />正在读取统计数据</div>}
    {s && <>
      <div className="dashboard-metrics">
        <Metric label="今日收入" value={currency(s.incomeToday)} relatedLabel="昨日收入" relatedValue={currency(s.incomeYesterday)} icon={<Wallet size={18} />} />
        <Metric label="本月收入" value={currency(s.incomeMonth)} relatedLabel="上月收入" relatedValue={currency(s.incomePrevious)} icon={<CalendarDays size={18} />} />
        <Metric label="今日流量" value={bytes(s.trafficToday)} relatedLabel="昨日流量" relatedValue={bytes(s.trafficYesterday)} icon={<ArrowDownUp size={18} />} />
        <Metric label="用户总数" value={s.users} relatedLabel="待处理诊断" relatedValue={s.pendingDiagnostics} icon={<UsersRound size={18} />} />
      </div>
      <section className="dashboard-rankings" aria-labelledby="dashboard-rankings-title">
        <header className="dashboard-rankings-head">
          <h2 id="dashboard-rankings-title">流量排行</h2>
          <Segmented<"today" | "yesterday"> aria-label="排行时段" value={period} onChange={setPeriod}
            options={[{ value: "today", label: "今日" }, { value: "yesterday", label: "昨日" }]} />
        </header>
        <div className="dashboard-ranking-grid">
          <section className="dashboard-ranking" aria-labelledby="dashboard-users-rank">
            <h3 id="dashboard-users-rank"><UsersRound size={17} aria-hidden="true" />用户流量</h3>
            <Ranking rows={period === "today" ? s.usersToday : s.usersYesterday} users />
          </section>
          <section className="dashboard-ranking" aria-labelledby="dashboard-groups-rank">
            <h3 id="dashboard-groups-rank"><Layers3 size={17} aria-hidden="true" />设备组流量</h3>
            <Ranking rows={period === "today" ? s.groupsToday : s.groupsYesterday} users={false} />
          </section>
        </div>
      </section>
    </>}
  </section>;
}
