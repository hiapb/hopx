CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS user_groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL, show_order INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO user_groups(id,name) VALUES (0,'默认用户组');
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, password BLOB NOT NULL,
 billing_remainder INTEGER NOT NULL DEFAULT 0, quota_epoch INTEGER NOT NULL DEFAULT 0,
 admin INTEGER NOT NULL DEFAULT 0, banned INTEGER NOT NULL DEFAULT 0, group_id INTEGER NOT NULL DEFAULT 0 REFERENCES user_groups(id),
 quota INTEGER NOT NULL DEFAULT 0, unlimited_traffic INTEGER NOT NULL DEFAULT 0,
 used INTEGER NOT NULL DEFAULT 0, balance INTEGER NOT NULL DEFAULT 0,
 affiliate_balance INTEGER NOT NULL DEFAULT 0, allow_device INTEGER NOT NULL DEFAULT 0,
 expires INTEGER NOT NULL DEFAULT 0, max_rules INTEGER NOT NULL DEFAULT 0, plan_id INTEGER NOT NULL DEFAULT 0,
 rate_override INTEGER, ips_override INTEGER, connections_override INTEGER,
 invite TEXT NOT NULL UNIQUE, inviter INTEGER REFERENCES users(id), auto_renew INTEGER NOT NULL DEFAULT 0,
 auto_renew_configured INTEGER NOT NULL DEFAULT 0,
 note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS users_auto_renew ON users(id) WHERE auto_renew=1 AND banned=0 AND plan_id>0;
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS user_referral_settings (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 rate INTEGER NOT NULL, first_only INTEGER NOT NULL, require_binding INTEGER NOT NULL,
 registration_enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS groups (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, first_port INTEGER NOT NULL, last_port INTEGER NOT NULL,
 ratio INTEGER NOT NULL, user_group INTEGER NOT NULL REFERENCES user_groups(id), offline_seconds INTEGER NOT NULL,
 owner INTEGER NOT NULL DEFAULT 0, allowed_from TEXT NOT NULL DEFAULT '[]', allowed_to TEXT NOT NULL DEFAULT '[]', user_groups TEXT NOT NULL DEFAULT '[]',
 chain TEXT NOT NULL DEFAULT '[]', port_ranges TEXT NOT NULL DEFAULT '', reverse_groups TEXT NOT NULL DEFAULT '[]', tls_ingress INTEGER NOT NULL DEFAULT 0,
 ingress TEXT NOT NULL DEFAULT 'null', folder TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
 show_order INTEGER NOT NULL DEFAULT 0, hide_status INTEGER NOT NULL DEFAULT 0,
 relay_mode TEXT NOT NULL DEFAULT '', default_network TEXT NOT NULL DEFAULT 'tcp',
 connect_host TEXT NOT NULL DEFAULT '', fallback_group INTEGER NOT NULL DEFAULT 0, routing TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS invitations (
 token TEXT PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_enrollments (
 group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE, token TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS devices (
 id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL REFERENCES groups(id), token TEXT NOT NULL UNIQUE, registration TEXT NOT NULL,
 created INTEGER NOT NULL DEFAULT (unixepoch()), last_seen INTEGER NOT NULL DEFAULT 0,
 status_hidden_at INTEGER NOT NULL DEFAULT 0, in_bytes INTEGER, out_bytes INTEGER
);
CREATE TABLE IF NOT EXISTS rules (
 id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, entry INTEGER NOT NULL REFERENCES groups(id),
 port INTEGER NOT NULL, json TEXT NOT NULL, UNIQUE(entry,port)
);
CREATE INDEX IF NOT EXISTS rules_owner ON rules(owner,id);
CREATE TABLE IF NOT EXISTS rule_folders (
 owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, PRIMARY KEY(owner,name)
);
CREATE TABLE IF NOT EXISTS device_folders (name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS traffic (
 rule_id INTEGER PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE, inbound INTEGER NOT NULL DEFAULT 0, outbound INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS traffic_batch (
 node INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, report TEXT NOT NULL, received INTEGER NOT NULL DEFAULT (unixepoch()),
 PRIMARY KEY(node,report)
);
CREATE TABLE IF NOT EXISTS plans (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, price INTEGER NOT NULL,
 duration INTEGER NOT NULL, quota INTEGER NOT NULL, unlimited_traffic INTEGER NOT NULL DEFAULT 0, rules INTEGER NOT NULL,
 group_id INTEGER NOT NULL REFERENCES user_groups(id), enabled INTEGER NOT NULL DEFAULT 1,
 rate_mbps INTEGER NOT NULL DEFAULT 0, max_ips INTEGER NOT NULL DEFAULT 0, max_connections INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'day', show_order INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS payment_channels (
 id TEXT PRIMARY KEY, config TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0, show_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), amount INTEGER NOT NULL,
 credit INTEGER NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, reference TEXT UNIQUE, description TEXT NOT NULL,
 checkout_channel TEXT NOT NULL DEFAULT '', checkout_url TEXT NOT NULL DEFAULT '', checkout_fee INTEGER NOT NULL DEFAULT 0, checkout_qr INTEGER NOT NULL DEFAULT 0, paid_at INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0,
 created INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS orders_user ON orders(user_id,id);
CREATE TABLE IF NOT EXISTS redeem (
 code TEXT PRIMARY KEY COLLATE NOCASE, plan_id INTEGER NOT NULL REFERENCES plans(id), remaining INTEGER NOT NULL,
 discount INTEGER NOT NULL, expiry INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, topic TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS migrations (source TEXT PRIMARY KEY, checksum TEXT NOT NULL, created INTEGER NOT NULL DEFAULT (unixepoch()));
CREATE TABLE IF NOT EXISTS migration_reports (source TEXT PRIMARY KEY REFERENCES migrations(source), report TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS migration_rules (rule_id INTEGER PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE, source TEXT NOT NULL REFERENCES migrations(source), was_enabled INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS migration_rule_issues (
 source TEXT NOT NULL REFERENCES migrations(source), rule_id INTEGER NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(source,rule_id)
);
CREATE TABLE IF NOT EXISTS migration_order_issues (
 source TEXT NOT NULL REFERENCES migrations(source), order_id INTEGER NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(source,order_id)
);
CREATE TABLE IF NOT EXISTS migration_devices (source TEXT NOT NULL REFERENCES migrations(source), id INTEGER NOT NULL, group_id INTEGER NOT NULL REFERENCES groups(id), name TEXT NOT NULL, address TEXT NOT NULL, PRIMARY KEY(source,id));
CREATE TABLE IF NOT EXISTS probe_samples (
 node INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, bucket INTEGER NOT NULL,
 cpu REAL NOT NULL, ram REAL NOT NULL, disk REAL NOT NULL, inbound REAL NOT NULL, outbound REAL NOT NULL,
 PRIMARY KEY(node,bucket)
);
CREATE TABLE IF NOT EXISTS node_rollout (
 id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS probe_bucket ON probe_samples(bucket);
CREATE TABLE IF NOT EXISTS rule_probe_samples (
 rule INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
 bucket INTEGER NOT NULL, sampled INTEGER NOT NULL, links TEXT NOT NULL,
 PRIMARY KEY(rule,bucket)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rule_probe_sampled ON rule_probe_samples(sampled);
CREATE INDEX IF NOT EXISTS rule_probe_history ON rule_probe_samples(rule,sampled);
CREATE INDEX IF NOT EXISTS rule_probe_enabled ON rules(id)
 WHERE json_extract(json,'$.enabled')=1 AND coalesce(json_extract(json,'$.tlsShared'),0)=0;
CREATE TABLE IF NOT EXISTS telegram_links (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, chat_id INTEGER NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
 income INTEGER NOT NULL DEFAULT 0, updown INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS telegram_tokens (
 token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expiry INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notification_deliveries (
 notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 state TEXT NOT NULL DEFAULT 'queued', tries INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(notification_id,user_id)
);
CREATE INDEX IF NOT EXISTS delivery_queue ON notification_deliveries(state,next_try);
CREATE TABLE IF NOT EXISTS quota_grants (
 id TEXT PRIMARY KEY, node INTEGER NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id),
 epoch INTEGER NOT NULL, generation TEXT NOT NULL, allocated INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0,
 expires INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS quota_account_grants ON quota_grants(user_id,epoch,closed);
CREATE UNIQUE INDEX IF NOT EXISTS quota_node_generation ON quota_grants(node,user_id,epoch,generation) WHERE closed=0;
CREATE TABLE IF NOT EXISTS daily_user_traffic (
 day INTEGER NOT NULL, user_id INTEGER NOT NULL,
 inbound INTEGER NOT NULL, outbound INTEGER NOT NULL,
 PRIMARY KEY(day,user_id)
);
CREATE TABLE IF NOT EXISTS daily_group_traffic (
 day INTEGER NOT NULL, group_id INTEGER NOT NULL,
 inbound INTEGER NOT NULL, outbound INTEGER NOT NULL,
 PRIMARY KEY(day,group_id)
);
CREATE INDEX IF NOT EXISTS traffic_batch_received ON traffic_batch(received);

CREATE TABLE IF NOT EXISTS traffic_meter_key (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), seed BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS exit_group_traffic (
 group_id INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
 inbound INTEGER NOT NULL, outbound INTEGER NOT NULL
);
