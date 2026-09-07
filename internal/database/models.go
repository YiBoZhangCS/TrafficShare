package database

import "time"

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Device struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	DeviceName      string    `json:"device_name"`
	Role            string    `json:"role"`
	LANIP           string    `json:"lan_ip"`
	TunnelPublicKey string    `json:"tunnel_public_key"`
	Online          bool      `json:"online"`
	LastHeartbeat   time.Time `json:"last_heartbeat"`
}

type Share struct {
	ID             string    `json:"id"`
	OwnerUserID    string    `json:"owner_user_id"`
	ReceiverUserID string    `json:"receiver_user_id"`
	ProviderName   string    `json:"provider_username,omitempty"`
	QuotaBytes     int64     `json:"quota_bytes"`
	UsedBytes      int64     `json:"used_bytes"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	ProviderOnline bool      `json:"provider_online"`
}

type Session struct {
	ID               string    `json:"id"`
	ShareID          string    `json:"share_id"`
	ProviderDeviceID string    `json:"provider_device_id"`
	ConsumerDeviceID string    `json:"consumer_device_id"`
	StartedAt        time.Time `json:"started_at"`
	LastHeartbeat    time.Time `json:"last_heartbeat"`
	Status           string    `json:"status"`
}

type TunnelConfig struct {
	SessionID         string `json:"session_id"`
	ProviderLANIP     string `json:"provider_lan_ip"`
	ProviderPublicKey string `json:"provider_public_key"`
	ConsumerPublicKey string `json:"consumer_public_key"`
	ProviderTunnelIP  string `json:"provider_tunnel_ip"`
	ConsumerTunnelIP  string `json:"consumer_tunnel_ip"`
	TunnelPrefix      string `json:"tunnel_prefix"`
	Port              int    `json:"port"`
}

type TunnelPool struct {
	Prefix     string
	ProviderIP string
	ConsumerIP string
	Port       int
}

type TrafficReport struct {
	SessionID  string `json:"session_id"`
	RXBytes    int64  `json:"rx_bytes"`
	TXBytes    int64  `json:"tx_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

type ProviderSession struct {
	Session Session      `json:"session"`
	Tunnel  TunnelConfig `json:"tunnel"`
}

type SessionView struct {
	Session        Session   `json:"session"`
	QuotaBytes     int64     `json:"quota_bytes"`
	UsedBytes      int64     `json:"used_bytes"`
	RemainingBytes int64     `json:"remaining_bytes"`
	ExpiresAt      time.Time `json:"expires_at"`
}
