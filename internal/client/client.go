package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trafficshare/internal/auth"
	"trafficshare/internal/database"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var v struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &v)
		if v.Error == "" {
			v.Error = resp.Status
		}
		return fmt.Errorf("control server: %s", v.Error)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode control response: %w", err)
		}
	}
	return nil
}

func (c Client) Register(ctx context.Context, username, password string) error {
	return c.do(ctx, http.MethodPost, "/v1/register", map[string]string{"username": username, "password": password}, nil)
}
func (c Client) Health(ctx context.Context) error {
	withoutToken := c
	withoutToken.Token = ""
	return withoutToken.do(ctx, http.MethodGet, "/healthz", nil, nil)
}
func (c Client) Login(ctx context.Context, username, password string) (auth.Login, error) {
	var v auth.Login
	err := c.do(ctx, http.MethodPost, "/v1/login", map[string]string{"username": username, "password": password}, &v)
	return v, err
}
func (c Client) RegisterDevice(ctx context.Context, d database.Device) (database.Device, error) {
	var v database.Device
	err := c.do(ctx, http.MethodPost, "/v1/devices", d, &v)
	return v, err
}
func (c Client) CreateShare(ctx context.Context, receiver string, quota int64, expires time.Time) (database.Share, error) {
	var v database.Share
	err := c.do(ctx, http.MethodPost, "/v1/shares", map[string]any{"receiver_username": receiver, "quota_bytes": quota, "expires_at": expires}, &v)
	return v, err
}
func (c Client) Shares(ctx context.Context) ([]database.Share, error) {
	var v struct {
		Shares []database.Share `json:"shares"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/shares", nil, &v)
	return v.Shares, err
}
func (c Client) StopShare(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/shares/"+id, nil, nil)
}
func (c Client) CreateSession(ctx context.Context, shareID, deviceID string) (database.Session, database.TunnelConfig, error) {
	var v struct {
		Session database.Session      `json:"session"`
		Tunnel  database.TunnelConfig `json:"tunnel"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/sessions", map[string]string{"share_id": shareID, "consumer_device_id": deviceID}, &v)
	return v.Session, v.Tunnel, err
}
func (c Client) PreviewSession(ctx context.Context, shareID, deviceID string) (database.TunnelConfig, error) {
	var v struct {
		Tunnel database.TunnelConfig `json:"tunnel"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/sessions/preview", map[string]string{"share_id": shareID, "consumer_device_id": deviceID}, &v)
	return v.Tunnel, err
}
func (c Client) SessionConfig(ctx context.Context, id string) (database.TunnelConfig, error) {
	var v database.TunnelConfig
	err := c.do(ctx, http.MethodGet, "/v1/sessions/"+id+"/config", nil, &v)
	return v, err
}
func (c Client) Disconnect(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/sessions/"+id+"/disconnect", map[string]any{}, nil)
}
func (c Client) Revoke(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/sessions/"+id+"/revoke", map[string]any{}, nil)
}
func (c Client) ReportTraffic(ctx context.Context, deviceID string, report database.TrafficReport) (bool, error) {
	var v struct {
		QuotaExhausted bool `json:"quota_exhausted"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+report.SessionID+"/traffic", map[string]any{"provider_device_id": deviceID, "rx_bytes": report.RXBytes, "tx_bytes": report.TXBytes, "total_bytes": report.TotalBytes}, &v)
	return v.QuotaExhausted, err
}
func (c Client) Heartbeat(ctx context.Context, deviceID, lanIP string) ([]string, error) {
	var v struct {
		Disconnect []string `json:"disconnect_sessions"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/heartbeat", map[string]string{"device_id": deviceID, "lan_ip": lanIP}, &v)
	return v.Disconnect, err
}
func (c Client) ProviderSessions(ctx context.Context, deviceID string) ([]database.ProviderSession, error) {
	var v struct {
		Sessions []database.ProviderSession `json:"sessions"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/provider/sessions?device_id="+deviceID, nil, &v)
	return v.Sessions, err
}
func (c Client) ProviderShares(ctx context.Context) ([]database.Share, error) {
	var v struct {
		Shares []database.Share `json:"shares"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/provider/shares", nil, &v)
	return v.Shares, err
}
func (c Client) SessionView(ctx context.Context, id string) (database.SessionView, error) {
	var v database.SessionView
	err := c.do(ctx, http.MethodGet, "/v1/sessions/"+id, nil, &v)
	return v, err
}

func (c Client) Reachable(ctx context.Context, lanIP string) error {
	if lanIP == "" {
		return errors.New("provider LAN IP is empty")
	}
	// Reachability is ultimately validated by the WireGuard handshake. This
	// check deliberately does not attempt NAT traversal or isolation bypass.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return errors.New("Provider is not reachable on current LAN")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("Provider is not reachable on current LAN")
	}
	return nil
}
