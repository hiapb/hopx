package panel

import (
	"context"
	"net/http"
	"time"
)

type trafficRank struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

func (s *Server) rank(ctx context.Context, query string, day int64) ([]trafficRank, error) {
	rows, err := s.db.QueryContext(ctx, query, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ranking := []trafficRank{}
	for rows.Next() {
		var row trafficRank
		if err := rows.Scan(&row.ID, &row.Name, &row.Bytes); err != nil {
			return nil, err
		}
		ranking = append(ranking, row)
	}
	return ranking, rows.Err()
}

func (s *Server) adminStatistics(w http.ResponseWriter, r *http.Request, _ User) {
	ctx := r.Context()
	now := time.Now().UTC()
	today := now.Unix() / 86400
	trafficToday := trafficDay(now)
	trafficYesterday := trafficToday - 86400
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	out := map[string]any{}
	var incomeToday, incomeYesterday, incomeMonth, incomePrevious int64
	err := s.db.QueryRowContext(ctx, "WITH paid AS (SELECT amount,coalesce(nullif(paid_at,0),created) AS at FROM orders WHERE status='paid' AND (kind IN ('epay','epusdt','tokenpay','cryptomus') OR (credit>0 AND reference IS NOT NULL AND kind='payment'))) "+
		"SELECT coalesce(sum(CASE WHEN at>=? THEN amount END),0),coalesce(sum(CASE WHEN at>=? AND at<? THEN amount END),0),coalesce(sum(CASE WHEN at>=? THEN amount END),0),coalesce(sum(CASE WHEN at>=? AND at<? THEN amount END),0) FROM paid",
		today*86400, (today-1)*86400, today*86400, month.Unix(), month.AddDate(0, -1, 0).Unix(), month.Unix()).
		Scan(&incomeToday, &incomeYesterday, &incomeMonth, &incomePrevious)
	if err != nil {
		dbFailure(w, err)
		return
	}
	out["incomeToday"], out["incomeYesterday"], out["incomeMonth"], out["incomePrevious"] = incomeToday, incomeYesterday, incomeMonth, incomePrevious
	var todayTraffic, yesterdayTraffic, users int64
	err = s.db.QueryRowContext(ctx, "SELECT coalesce(sum(CASE WHEN day=? THEN inbound+outbound END),0),coalesce(sum(CASE WHEN day=? THEN inbound+outbound END),0),(SELECT count(*) FROM users) FROM daily_user_traffic WHERE day IN (?,?)", trafficToday, trafficYesterday, trafficToday, trafficYesterday).
		Scan(&todayTraffic, &yesterdayTraffic, &users)
	if err != nil {
		dbFailure(w, err)
		return
	}
	out["trafficToday"], out["trafficYesterday"], out["users"] = todayTraffic, yesterdayTraffic, users
	userQuery := "SELECT d.user_id,coalesce(u.name,'已移除用户'),d.inbound+d.outbound AS bytes FROM daily_user_traffic d LEFT JOIN users u ON u.id=d.user_id WHERE d.day=? AND bytes>0 ORDER BY bytes DESC,d.user_id LIMIT 20"
	groupQuery := "SELECT d.group_id,coalesce(g.name,'已移除设备组'),d.inbound+d.outbound AS bytes FROM daily_group_traffic d LEFT JOIN groups g ON g.id=d.group_id WHERE d.day=? AND bytes>0 ORDER BY bytes DESC,d.group_id LIMIT 20"
	for _, query := range []struct {
		key, sql string
		day      int64
	}{
		{"usersToday", userQuery, trafficToday}, {"usersYesterday", userQuery, trafficYesterday},
		{"groupsToday", groupQuery, trafficToday}, {"groupsYesterday", groupQuery, trafficYesterday},
	} {
		out[query.key], err = s.rank(ctx, query.sql, query.day)
		if err != nil {
			dbFailure(w, err)
			return
		}
	}
	pending := 0
	s.mu.RLock()
	for _, diagnostic := range s.diagnostics {
		if diagnostic.result == nil && now.Before(diagnostic.expires) {
			pending++
		}
	}
	s.mu.RUnlock()
	out["pendingDiagnostics"] = pending
	respond(w, 200, out)
}
