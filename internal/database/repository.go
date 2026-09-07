package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"trafficshare/internal/id"
)

var (
	ErrNotFound         = errors.New("not found")
	ErrReceiverNotFound = errors.New("receiver account not found")
	ErrForbidden        = errors.New("forbidden")
	ErrConflict         = errors.New("conflict")
	ErrUnavailable      = errors.New("provider unavailable")
	ErrQuota            = errors.New("quota exhausted")
)

type Repository struct{ DB *DB }

func unix(t time.Time) int64     { return t.UTC().Unix() }
func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func (r Repository) CreateUser(ctx context.Context, username, passwordHash string, now time.Time) (User, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 || passwordHash == "" {
		return User{}, errors.New("username must be 3-64 characters")
	}
	uid, err := id.New()
	if err != nil {
		return User{}, err
	}
	_, err = r.DB.SQL.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at) VALUES(?,?,?,?)`, uid, username, passwordHash, unix(now))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	return User{ID: uid, Username: username, PasswordHash: passwordHash, CreatedAt: now.UTC()}, nil
}

func (r Repository) UserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	var created int64
	err := r.DB.SQL.QueryRowContext(ctx, `SELECT id,username,password_hash,created_at FROM users WHERE username=?`, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt = fromUnix(created)
	return u, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (r Repository) SaveToken(ctx context.Context, token, userID string, expiresAt, now time.Time) error {
	_, err := r.DB.SQL.ExecContext(ctx, `INSERT INTO tokens(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)`, hashToken(token), userID, unix(expiresAt), unix(now))
	return err
}

func (r Repository) UserByToken(ctx context.Context, token string, now time.Time) (User, error) {
	var u User
	var created int64
	err := r.DB.SQL.QueryRowContext(ctx, `SELECT u.id,u.username,u.password_hash,u.created_at FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.expires_at>?`, hashToken(token), unix(now)).Scan(&u.ID, &u.Username, &u.PasswordHash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrForbidden
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt = fromUnix(created)
	return u, nil
}

func (r Repository) UpsertDevice(ctx context.Context, userID string, d Device, now time.Time) (Device, error) {
	if d.Role != "provider" && d.Role != "consumer" {
		return Device{}, errors.New("invalid device role")
	}
	if net.ParseIP(d.LANIP) == nil || strings.Contains(d.LANIP, ":") {
		return Device{}, errors.New("valid IPv4 LAN address required")
	}
	if d.DeviceName == "" || d.TunnelPublicKey == "" {
		return Device{}, errors.New("device name and public key required")
	}
	if d.ID == "" {
		var err error
		d.ID, err = id.New()
		if err != nil {
			return Device{}, err
		}
	}
	_, err := r.DB.SQL.ExecContext(ctx, `INSERT INTO devices(id,user_id,device_name,role,lan_ip,tunnel_public_key,online,last_heartbeat) VALUES(?,?,?,?,?,?,1,?)
ON CONFLICT(user_id,device_name) DO UPDATE SET role=excluded.role,lan_ip=excluded.lan_ip,tunnel_public_key=excluded.tunnel_public_key,online=1,last_heartbeat=excluded.last_heartbeat`, d.ID, userID, d.DeviceName, d.Role, d.LANIP, d.TunnelPublicKey, unix(now))
	if err != nil {
		return Device{}, err
	}
	err = r.DB.SQL.QueryRowContext(ctx, `SELECT id FROM devices WHERE user_id=? AND device_name=?`, userID, d.DeviceName).Scan(&d.ID)
	if err != nil {
		return Device{}, err
	}
	d.UserID, d.Online, d.LastHeartbeat = userID, true, now.UTC()
	return d, nil
}

func (r Repository) HeartbeatDevice(ctx context.Context, userID, deviceID, lanIP string, now time.Time) error {
	if lanIP != "" && (net.ParseIP(lanIP) == nil || strings.Contains(lanIP, ":")) {
		return errors.New("invalid IPv4 LAN address")
	}
	result, err := r.DB.SQL.ExecContext(ctx, `UPDATE devices SET online=1,last_heartbeat=?,lan_ip=CASE WHEN ?='' THEN lan_ip ELSE ? END WHERE id=? AND user_id=?`, unix(now), lanIP, lanIP, deviceID, userID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrForbidden
	}
	_, _ = r.DB.SQL.ExecContext(ctx, `UPDATE sessions SET last_heartbeat=? WHERE status='active' AND (provider_device_id=? OR consumer_device_id=?)`, unix(now), deviceID, deviceID)
	return nil
}

func (r Repository) CreateShare(ctx context.Context, ownerID, receiverUsername string, quotaBytes int64, expiresAt, now time.Time) (Share, error) {
	if quotaBytes <= 0 || !expiresAt.After(now) {
		return Share{}, errors.New("positive quota and future expiry required")
	}
	var receiverID string
	if err := r.DB.SQL.QueryRowContext(ctx, `SELECT id FROM users WHERE username=?`, receiverUsername).Scan(&receiverID); errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrReceiverNotFound
	} else if err != nil {
		return Share{}, err
	}
	if receiverID == ownerID {
		return Share{}, errors.New("share receiver must be another user")
	}
	sid, err := id.New()
	if err != nil {
		return Share{}, err
	}
	_, err = r.DB.SQL.ExecContext(ctx, `INSERT INTO shares(id,owner_user_id,receiver_user_id,quota_bytes,used_bytes,status,created_at,expires_at) VALUES(?,?,?,?,0,'active',?,?)`, sid, ownerID, receiverID, quotaBytes, unix(now), unix(expiresAt))
	if err != nil {
		return Share{}, err
	}
	return Share{ID: sid, OwnerUserID: ownerID, ReceiverUserID: receiverID, QuotaBytes: quotaBytes, Status: "active", CreatedAt: now.UTC(), ExpiresAt: expiresAt.UTC()}, nil
}

func (r Repository) StopShare(ctx context.Context, ownerID, shareID string) error {
	result, err := r.DB.SQL.ExecContext(ctx, `UPDATE shares SET status='stopped' WHERE id=? AND owner_user_id=? AND status='active'`, shareID, ownerID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrForbidden
	}
	_, _ = r.DB.SQL.ExecContext(ctx, `UPDATE sessions SET status='revoked' WHERE share_id=? AND status IN ('pending','active')`, shareID)
	return nil
}

func (r Repository) AvailableShares(ctx context.Context, receiverID string, now time.Time, heartbeatTTL time.Duration) ([]Share, error) {
	rows, err := r.DB.SQL.QueryContext(ctx, `SELECT s.id,s.owner_user_id,s.receiver_user_id,u.username,s.quota_bytes,s.used_bytes,s.status,s.created_at,s.expires_at,
EXISTS(SELECT 1 FROM devices d WHERE d.user_id=s.owner_user_id AND d.role='provider' AND d.online=1 AND d.last_heartbeat>?)
FROM shares s JOIN users u ON u.id=s.owner_user_id WHERE s.receiver_user_id=? AND s.status='active' AND s.expires_at>? ORDER BY s.created_at DESC`, unix(now.Add(-heartbeatTTL)), receiverID, unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Share
	for rows.Next() {
		var s Share
		var created, expires int64
		if err := rows.Scan(&s.ID, &s.OwnerUserID, &s.ReceiverUserID, &s.ProviderName, &s.QuotaBytes, &s.UsedBytes, &s.Status, &created, &expires, &s.ProviderOnline); err != nil {
			return nil, err
		}
		s.CreatedAt, s.ExpiresAt = fromUnix(created), fromUnix(expires)
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r Repository) CreateSession(ctx context.Context, receiverID, shareID, consumerDeviceID string, now time.Time, heartbeatTTL time.Duration, pool TunnelPool) (Session, TunnelConfig, error) {
	tx, err := r.DB.SQL.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, TunnelConfig{}, err
	}
	defer tx.Rollback()
	candidate, err := prepareSession(ctx, tx, receiverID, shareID, consumerDeviceID, now, heartbeatTTL, pool)
	if err != nil {
		return Session{}, TunnelConfig{}, err
	}
	sessionID, err := id.New()
	if err != nil {
		return Session{}, TunnelConfig{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sessions(id,share_id,provider_device_id,consumer_device_id,consumer_tunnel_ip,started_at,last_heartbeat,status) VALUES(?,?,?,?,?,?,?,'active')`, sessionID, shareID, candidate.providerID, consumerDeviceID, candidate.config.ConsumerTunnelIP, unix(now), unix(now))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Session{}, TunnelConfig{}, ErrConflict
		}
		return Session{}, TunnelConfig{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, TunnelConfig{}, err
	}
	s := Session{ID: sessionID, ShareID: shareID, ProviderDeviceID: candidate.providerID, ConsumerDeviceID: consumerDeviceID, StartedAt: now.UTC(), LastHeartbeat: now.UTC(), Status: "active"}
	candidate.config.SessionID = sessionID
	return s, candidate.config, nil
}

func (r Repository) PreviewSession(ctx context.Context, receiverID, shareID, consumerDeviceID string, now time.Time, heartbeatTTL time.Duration, pool TunnelPool) (TunnelConfig, error) {
	candidate, err := prepareSession(ctx, r.DB.SQL, receiverID, shareID, consumerDeviceID, now, heartbeatTTL, pool)
	if err != nil {
		return TunnelConfig{}, err
	}
	candidate.config.SessionID = "preview"
	return candidate.config, nil
}

type sessionQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type sessionCandidate struct {
	providerID string
	config     TunnelConfig
}

func prepareSession(ctx context.Context, q sessionQuerier, receiverID, shareID, consumerDeviceID string, now time.Time, heartbeatTTL time.Duration, pool TunnelPool) (sessionCandidate, error) {
	var ownerID, actualReceiver, shareStatus string
	var quotaBytes, usedBytes, expires int64
	err := q.QueryRowContext(ctx, `SELECT owner_user_id,receiver_user_id,quota_bytes,used_bytes,status,expires_at FROM shares WHERE id=?`, shareID).Scan(&ownerID, &actualReceiver, &quotaBytes, &usedBytes, &shareStatus, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return sessionCandidate{}, ErrNotFound
	}
	if err != nil {
		return sessionCandidate{}, err
	}
	if actualReceiver != receiverID {
		return sessionCandidate{}, ErrForbidden
	}
	if shareStatus != "active" || expires <= unix(now) {
		return sessionCandidate{}, ErrUnavailable
	}
	if usedBytes >= quotaBytes {
		return sessionCandidate{}, ErrQuota
	}
	var consumerKey string
	err = q.QueryRowContext(ctx, `SELECT tunnel_public_key FROM devices WHERE id=? AND user_id=? AND role='consumer'`, consumerDeviceID, receiverID).Scan(&consumerKey)
	if errors.Is(err, sql.ErrNoRows) {
		return sessionCandidate{}, ErrForbidden
	}
	if err != nil {
		return sessionCandidate{}, err
	}
	var activeConsumer int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE consumer_device_id=? AND status IN ('pending','active','disconnecting')`, consumerDeviceID).Scan(&activeConsumer); err != nil {
		return sessionCandidate{}, err
	}
	if activeConsumer > 0 {
		return sessionCandidate{}, ErrConflict
	}
	var providerID, providerIP, providerKey string
	err = q.QueryRowContext(ctx, `SELECT d.id,d.lan_ip,d.tunnel_public_key FROM devices d WHERE d.user_id=? AND d.role='provider' AND d.online=1 AND d.last_heartbeat>? ORDER BY (SELECT COUNT(*) FROM sessions x WHERE x.provider_device_id=d.id AND x.status IN ('pending','active','disconnecting')) ASC,d.last_heartbeat DESC LIMIT 1`, ownerID, unix(now.Add(-heartbeatTTL))).Scan(&providerID, &providerIP, &providerKey)
	if errors.Is(err, sql.ErrNoRows) {
		return sessionCandidate{}, ErrUnavailable
	}
	if err != nil {
		return sessionCandidate{}, err
	}
	consumerTunnelIP, prefix, providerTunnelIP, port, err := allocateTunnelIP(ctx, q, providerID, pool)
	if err != nil {
		return sessionCandidate{}, err
	}
	return sessionCandidate{providerID: providerID, config: TunnelConfig{ProviderLANIP: providerIP, ProviderPublicKey: providerKey, ConsumerPublicKey: consumerKey, ProviderTunnelIP: providerTunnelIP, ConsumerTunnelIP: consumerTunnelIP, TunnelPrefix: prefix, Port: port}}, nil
}

func allocateTunnelIP(ctx context.Context, q sessionQuerier, providerID string, pool TunnelPool) (string, string, string, int, error) {
	if pool.Prefix == "" {
		pool.Prefix = "10.66.0.0/24"
	}
	if pool.ProviderIP == "" {
		pool.ProviderIP = "10.66.0.1/24"
	}
	if pool.ConsumerIP == "" {
		pool.ConsumerIP = "10.66.0.2/24"
	}
	if pool.Port == 0 {
		pool.Port = 51820
	}
	_, network, err := net.ParseCIDR(pool.Prefix)
	if err != nil || network.IP.To4() == nil {
		return "", "", "", 0, errors.New("invalid IPv4 tunnel pool")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 16 || ones > 30 {
		return "", "", "", 0, errors.New("tunnel pool prefix must be between /16 and /30")
	}
	provider := net.ParseIP(strings.Split(pool.ProviderIP, "/")[0]).To4()
	preferred := net.ParseIP(strings.Split(pool.ConsumerIP, "/")[0]).To4()
	if provider == nil || preferred == nil || !network.Contains(provider) || !network.Contains(preferred) {
		return "", "", "", 0, errors.New("provider and consumer tunnel addresses must belong to the tunnel pool")
	}
	rows, err := q.QueryContext(ctx, `SELECT consumer_tunnel_ip FROM sessions WHERE provider_device_id=? AND status IN ('pending','active','disconnecting')`, providerID)
	if err != nil {
		return "", "", "", 0, err
	}
	used := map[uint32]bool{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			return "", "", "", 0, err
		}
		if ip := net.ParseIP(strings.Split(value, "/")[0]).To4(); ip != nil {
			used[binary.BigEndian.Uint32(ip)] = true
		}
	}
	if err := rows.Close(); err != nil {
		return "", "", "", 0, err
	}
	base := binary.BigEndian.Uint32(network.IP.To4())
	hosts := uint32(1) << uint32(32-ones)
	last := base + hosts - 1
	providerValue := binary.BigEndian.Uint32(provider)
	start := binary.BigEndian.Uint32(preferred)
	if start <= base || start >= last {
		start = base + 1
	}
	for offset := uint32(0); offset < hosts-2; offset++ {
		candidate := base + 1 + ((start - base - 1 + offset) % (hosts - 2))
		if candidate == providerValue || used[candidate] {
			continue
		}
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, candidate)
		return fmt.Sprintf("%s/%d", ip.String(), ones), pool.Prefix, fmt.Sprintf("%s/%d", provider.String(), ones), pool.Port, nil
	}
	return "", "", "", 0, ErrUnavailable
}

func (r Repository) SessionConfig(ctx context.Context, userID, sessionID string) (TunnelConfig, error) {
	var cfg TunnelConfig
	cfg.SessionID = sessionID
	var ownerID, receiverID string
	err := r.DB.SQL.QueryRowContext(ctx, `SELECT s.owner_user_id,s.receiver_user_id,p.lan_ip,p.tunnel_public_key,c.tunnel_public_key,x.consumer_tunnel_ip FROM sessions x JOIN shares s ON s.id=x.share_id JOIN devices p ON p.id=x.provider_device_id JOIN devices c ON c.id=x.consumer_device_id WHERE x.id=?`, sessionID).Scan(&ownerID, &receiverID, &cfg.ProviderLANIP, &cfg.ProviderPublicKey, &cfg.ConsumerPublicKey, &cfg.ConsumerTunnelIP)
	if errors.Is(err, sql.ErrNoRows) {
		return TunnelConfig{}, ErrNotFound
	}
	if err != nil {
		return TunnelConfig{}, err
	}
	if userID != ownerID && userID != receiverID {
		return TunnelConfig{}, ErrForbidden
	}
	cfg.ProviderTunnelIP, cfg.TunnelPrefix, cfg.Port = "10.66.0.1/24", "10.66.0.0/24", 51820
	if cfg.ConsumerTunnelIP == "" {
		cfg.ConsumerTunnelIP = "10.66.0.2/24"
	}
	return cfg, nil
}

func (r Repository) SessionView(ctx context.Context, userID, sessionID string) (SessionView, error) {
	var v SessionView
	var started, last, expires int64
	var owner, receiver string
	err := r.DB.SQL.QueryRowContext(ctx, `SELECT x.id,x.share_id,x.provider_device_id,x.consumer_device_id,x.started_at,x.last_heartbeat,x.status,s.owner_user_id,s.receiver_user_id,s.quota_bytes,s.used_bytes,s.expires_at FROM sessions x JOIN shares s ON s.id=x.share_id WHERE x.id=?`, sessionID).Scan(&v.Session.ID, &v.Session.ShareID, &v.Session.ProviderDeviceID, &v.Session.ConsumerDeviceID, &started, &last, &v.Session.Status, &owner, &receiver, &v.QuotaBytes, &v.UsedBytes, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionView{}, ErrNotFound
	}
	if err != nil {
		return SessionView{}, err
	}
	if userID != owner && userID != receiver {
		return SessionView{}, ErrForbidden
	}
	v.Session.StartedAt, v.Session.LastHeartbeat, v.ExpiresAt = fromUnix(started), fromUnix(last), fromUnix(expires)
	v.RemainingBytes = v.QuotaBytes - v.UsedBytes
	if v.RemainingBytes < 0 {
		v.RemainingBytes = 0
	}
	return v, nil
}

func (r Repository) OwnedShares(ctx context.Context, ownerID string) ([]Share, error) {
	rows, err := r.DB.SQL.QueryContext(ctx, `SELECT id,owner_user_id,receiver_user_id,quota_bytes,used_bytes,status,created_at,expires_at FROM shares WHERE owner_user_id=? ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Share
	for rows.Next() {
		var s Share
		var created, expires int64
		if err := rows.Scan(&s.ID, &s.OwnerUserID, &s.ReceiverUserID, &s.QuotaBytes, &s.UsedBytes, &s.Status, &created, &expires); err != nil {
			return nil, err
		}
		s.CreatedAt, s.ExpiresAt = fromUnix(created), fromUnix(expires)
		result = append(result, s)
	}
	return result, rows.Err()
}

func (r Repository) DisconnectSession(ctx context.Context, userID, sessionID string) error {
	result, err := r.DB.SQL.ExecContext(ctx, `UPDATE sessions SET status='disconnected' WHERE id=? AND status IN ('pending','active','disconnecting','revoked','failed') AND EXISTS(SELECT 1 FROM shares s WHERE s.id=sessions.share_id AND (s.owner_user_id=? OR s.receiver_user_id=?))`, sessionID, userID, userID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrForbidden
	}
	return nil
}

func (r Repository) RevokeSession(ctx context.Context, ownerID, sessionID string) error {
	result, err := r.DB.SQL.ExecContext(ctx, `UPDATE sessions SET status='revoked' WHERE id=? AND status IN ('pending','active') AND EXISTS(SELECT 1 FROM shares s WHERE s.id=sessions.share_id AND s.owner_user_id=?)`, sessionID, ownerID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrForbidden
	}
	return nil
}

func (r Repository) ReportTraffic(ctx context.Context, ownerID, providerDeviceID string, report TrafficReport, now time.Time) (bool, error) {
	if report.RXBytes < 0 || report.TXBytes < 0 || report.TotalBytes < 0 || report.TotalBytes != report.RXBytes+report.TXBytes {
		return false, errors.New("invalid traffic counters")
	}
	tx, err := r.DB.SQL.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var shareID, actualProvider, actualOwner, status string
	var quotaBytes, usedBytes, lastTotal int64
	err = tx.QueryRowContext(ctx, `SELECT x.share_id,x.provider_device_id,s.owner_user_id,x.status,s.quota_bytes,s.used_bytes,COALESCE((SELECT total_bytes FROM traffic_reports WHERE session_id=x.id ORDER BY id DESC LIMIT 1),0) FROM sessions x JOIN shares s ON s.id=x.share_id WHERE x.id=?`, report.SessionID).Scan(&shareID, &actualProvider, &actualOwner, &status, &quotaBytes, &usedBytes, &lastTotal)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if actualOwner != ownerID || actualProvider != providerDeviceID {
		return false, ErrForbidden
	}
	if status != "active" && status != "revoked" {
		return false, ErrConflict
	}
	delta := report.TotalBytes - lastTotal
	if delta < 0 {
		delta = report.TotalBytes
	}
	newUsed := usedBytes + delta
	_, err = tx.ExecContext(ctx, `INSERT INTO traffic_reports(session_id,reporter_device_id,rx_bytes,tx_bytes,total_bytes,reported_at) VALUES(?,?,?,?,?,?)`, report.SessionID, providerDeviceID, report.RXBytes, report.TXBytes, report.TotalBytes, unix(now))
	if err != nil {
		return false, err
	}
	exhausted := newUsed >= quotaBytes
	shareStatus := "active"
	sessionStatus := status
	if exhausted {
		newUsed = quotaBytes
		shareStatus = "exhausted"
		sessionStatus = "revoked"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE shares SET used_bytes=?,status=? WHERE id=?`, newUsed, shareStatus, shareID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET status=?,last_heartbeat=? WHERE id=?`, sessionStatus, unix(now), report.SessionID); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return exhausted, nil
}

func (r Repository) MustDisconnect(ctx context.Context, userID, deviceID string, now time.Time) ([]string, error) {
	rows, err := r.DB.SQL.QueryContext(ctx, `SELECT x.id FROM sessions x JOIN shares s ON s.id=x.share_id WHERE (x.provider_device_id=? OR x.consumer_device_id=?) AND (x.status='revoked' OR s.status<>'active' OR s.expires_at<=?) AND EXISTS(SELECT 1 FROM devices d WHERE d.id=? AND d.user_id=?)`, deviceID, deviceID, unix(now), deviceID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		ids = append(ids, v)
	}
	return ids, rows.Err()
}

func (r Repository) ProviderSessions(ctx context.Context, userID, deviceID string) ([]ProviderSession, error) {
	var owned int
	if err := r.DB.SQL.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE id=? AND user_id=? AND role='provider'`, deviceID, userID).Scan(&owned); err != nil {
		return nil, err
	}
	if owned == 0 {
		return nil, ErrForbidden
	}
	rows, err := r.DB.SQL.QueryContext(ctx, `SELECT x.id,x.share_id,x.provider_device_id,x.consumer_device_id,x.started_at,x.last_heartbeat,x.status,p.lan_ip,p.tunnel_public_key,c.tunnel_public_key,x.consumer_tunnel_ip FROM sessions x JOIN shares s ON s.id=x.share_id JOIN devices p ON p.id=x.provider_device_id JOIN devices c ON c.id=x.consumer_device_id WHERE x.provider_device_id=? AND s.owner_user_id=? ORDER BY x.started_at`, deviceID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ProviderSession
	for rows.Next() {
		var v ProviderSession
		var started, last int64
		if err := rows.Scan(&v.Session.ID, &v.Session.ShareID, &v.Session.ProviderDeviceID, &v.Session.ConsumerDeviceID, &started, &last, &v.Session.Status, &v.Tunnel.ProviderLANIP, &v.Tunnel.ProviderPublicKey, &v.Tunnel.ConsumerPublicKey, &v.Tunnel.ConsumerTunnelIP); err != nil {
			return nil, err
		}
		v.Session.StartedAt, v.Session.LastHeartbeat = fromUnix(started), fromUnix(last)
		v.Tunnel.SessionID = v.Session.ID
		v.Tunnel.ProviderTunnelIP, v.Tunnel.TunnelPrefix, v.Tunnel.Port = "10.66.0.1/24", "10.66.0.0/24", 51820
		if v.Tunnel.ConsumerTunnelIP == "" {
			v.Tunnel.ConsumerTunnelIP = "10.66.0.2/24"
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

func (r Repository) ExpireStale(ctx context.Context, now time.Time, heartbeatTTL time.Duration) error {
	if _, err := r.DB.SQL.ExecContext(ctx, `UPDATE devices SET online=0 WHERE last_heartbeat<=?`, unix(now.Add(-heartbeatTTL))); err != nil {
		return err
	}
	if _, err := r.DB.SQL.ExecContext(ctx, `UPDATE shares SET status='expired' WHERE status='active' AND expires_at<=?`, unix(now)); err != nil {
		return err
	}
	_, err := r.DB.SQL.ExecContext(ctx, `UPDATE sessions SET status='revoked' WHERE status='active' AND (last_heartbeat<=? OR EXISTS(SELECT 1 FROM shares s WHERE s.id=sessions.share_id AND s.status<>'active') OR EXISTS(SELECT 1 FROM devices p JOIN devices c ON c.id=sessions.consumer_device_id WHERE p.id=sessions.provider_device_id AND (p.online=0 OR c.online=0)))`, unix(now.Add(-heartbeatTTL)))
	return err
}

func (r Repository) DebugCounts(ctx context.Context) (map[string]int, error) {
	result := map[string]int{}
	for _, table := range []string{"users", "devices", "shares", "sessions", "traffic_reports"} {
		var n int
		if err := r.DB.SQL.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&n); err != nil {
			return nil, err
		}
		result[table] = n
	}
	return result, nil
}
