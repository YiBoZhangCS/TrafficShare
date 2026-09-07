package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	SQL *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{SQL: db}, nil
}

func (d *DB) Close() error { return d.SQL.Close() }

func migrate(ctx context.Context, db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('provider','consumer')),
  lan_ip TEXT NOT NULL,
  tunnel_public_key TEXT NOT NULL,
  online INTEGER NOT NULL DEFAULT 0,
  last_heartbeat INTEGER NOT NULL,
  UNIQUE(user_id, device_name)
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  receiver_user_id TEXT NOT NULL REFERENCES users(id),
  quota_bytes INTEGER NOT NULL CHECK(quota_bytes > 0),
  used_bytes INTEGER NOT NULL DEFAULT 0 CHECK(used_bytes >= 0),
  status TEXT NOT NULL CHECK(status IN ('active','stopped','expired','exhausted')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  CHECK(owner_user_id <> receiver_user_id)
);
CREATE INDEX IF NOT EXISTS idx_shares_receiver ON shares(receiver_user_id, status);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id),
  provider_device_id TEXT NOT NULL REFERENCES devices(id),
  consumer_device_id TEXT NOT NULL REFERENCES devices(id),
  consumer_tunnel_ip TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  last_heartbeat INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','active','disconnecting','disconnected','revoked','failed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_consumer ON sessions(consumer_device_id) WHERE status IN ('pending','active','disconnecting');
CREATE TABLE IF NOT EXISTS traffic_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  reporter_device_id TEXT NOT NULL REFERENCES devices(id),
  rx_bytes INTEGER NOT NULL,
  tx_bytes INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  reported_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_session ON traffic_reports(session_id, id);
`
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	if err := ensureColumn(ctx, db, "sessions", "consumer_tunnel_ip", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_one_active_provider;
UPDATE sessions SET consumer_tunnel_ip='10.66.0.2/24' WHERE consumer_tunnel_ip='' AND status IN ('pending','active','disconnecting');
CREATE UNIQUE INDEX IF NOT EXISTS idx_active_provider_tunnel_ip ON sessions(provider_device_id,consumer_tunnel_ip) WHERE status IN ('pending','active','disconnecting') AND consumer_tunnel_ip<>'';`); err != nil {
		return fmt.Errorf("migrate session capacity: %w", err)
	}
	return nil
}

func ensureColumn(ctx context.Context, db *sql.DB, table, column, definition string) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect %s schema: %w", table, err)
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}
