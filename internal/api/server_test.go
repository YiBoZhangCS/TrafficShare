package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"trafficshare/internal/auth"
	"trafficshare/internal/database"
)

func testServer(t *testing.T) (*Server, *database.DB) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := database.Repository{DB: db}
	authSvc := auth.Service{Repo: repo, TokenTTL: time.Hour, BcryptCost: bcrypt.MinCost, Now: func() time.Time { return now }}
	return &Server{Repo: repo, Auth: authSvc, HeartbeatTTL: 20 * time.Second, Now: func() time.Time { return now }}, db
}

func request(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&data).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &data)
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func registerLogin(t *testing.T, s *Server, username string) string {
	t.Helper()
	h := s.Handler()
	w := request(t, h, http.MethodPost, "/v1/register", "", map[string]any{"username": username, "password": "strong-password"})
	if w.Code != http.StatusCreated {
		t.Fatalf("register %s: %d %s", username, w.Code, w.Body.String())
	}
	w = request(t, h, http.MethodPost, "/v1/login", "", map[string]any{"username": username, "password": "strong-password"})
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var v struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v.Token
}

func TestPrivateShareAuthorizationAndProviderTraffic(t *testing.T) {
	s, db := testServer(t)
	defer db.Close()
	h := s.Handler()
	owner := registerLogin(t, s, "owner")
	receiver := registerLogin(t, s, "receiver")
	other := registerLogin(t, s, "other")
	registerDevice := func(token, name, role, ip, key string) string {
		w := request(t, h, http.MethodPost, "/v1/devices", token, map[string]any{"device_name": name, "role": role, "lan_ip": ip, "tunnel_public_key": key})
		if w.Code != http.StatusCreated {
			t.Fatalf("device: %d %s", w.Code, w.Body.String())
		}
		var d database.Device
		json.Unmarshal(w.Body.Bytes(), &d)
		return d.ID
	}
	providerID := registerDevice(owner, "provider-pc", "provider", "192.168.1.10", "provider-public-key")
	consumerID := registerDevice(receiver, "consumer-pc", "consumer", "192.168.1.11", "consumer-public-key")
	w := request(t, h, http.MethodPost, "/v1/shares", owner, map[string]any{"receiver_username": "receiver", "quota_bytes": int64(1000), "expires_at": s.now().Add(time.Hour)})
	if w.Code != http.StatusCreated {
		t.Fatalf("share: %d %s", w.Code, w.Body.String())
	}
	var share database.Share
	json.Unmarshal(w.Body.Bytes(), &share)
	if w = request(t, h, http.MethodGet, "/v1/shares", other, nil); w.Code != http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte(share.ID)) {
		t.Fatalf("private share leaked: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, http.MethodPost, "/v1/sessions", receiver, map[string]any{"share_id": share.ID, "consumer_device_id": consumerID})
	if w.Code != http.StatusCreated {
		t.Fatalf("session: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Session database.Session `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	if w = request(t, h, http.MethodGet, "/v1/sessions/"+created.Session.ID+"/config", other, nil); w.Code != http.StatusForbidden {
		t.Fatalf("other user read config: %d %s", w.Code, w.Body.String())
	}
	if w = request(t, h, http.MethodPost, "/v1/sessions/"+created.Session.ID+"/traffic", receiver, map[string]any{"provider_device_id": providerID, "rx_bytes": 600, "tx_bytes": 500, "total_bytes": 1100}); w.Code != http.StatusForbidden {
		t.Fatalf("consumer reported provider traffic: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, http.MethodPost, "/v1/sessions/"+created.Session.ID+"/traffic", owner, map[string]any{"provider_device_id": providerID, "rx_bytes": 600, "tx_bytes": 500, "total_bytes": 1100})
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"quota_exhausted":true`)) {
		t.Fatalf("provider report: %d %s", w.Code, w.Body.String())
	}
}

func TestPreviewIsReadOnlyAndConcurrentConsumersGetUniqueAddresses(t *testing.T) {
	s, db := testServer(t)
	defer db.Close()
	h := s.Handler()
	owner := registerLogin(t, s, "multi-owner")
	receiver1 := registerLogin(t, s, "receiver-one")
	receiver2 := registerLogin(t, s, "receiver-two")

	device := func(token, name, role, key string) string {
		w := request(t, h, http.MethodPost, "/v1/devices", token, map[string]any{"device_name": name, "role": role, "lan_ip": "10.15.1.10", "tunnel_public_key": key})
		if w.Code != http.StatusCreated {
			t.Fatalf("register device: %d %s", w.Code, w.Body.String())
		}
		var d database.Device
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d.ID
	}
	device(owner, "gateway", "provider", "provider-key")
	consumer1 := device(receiver1, "laptop-one", "consumer", "consumer-key-1")
	consumer2 := device(receiver2, "laptop-two", "consumer", "consumer-key-2")
	share := func(receiver, token string) database.Share {
		w := request(t, h, http.MethodPost, "/v1/shares", owner, map[string]any{"receiver_username": receiver, "quota_bytes": int64(1 << 30), "expires_at": s.now().Add(time.Hour)})
		if w.Code != http.StatusCreated {
			t.Fatalf("create share: %d %s", w.Code, w.Body.String())
		}
		var v database.Share
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	share1, share2 := share("receiver-one", receiver1), share("receiver-two", receiver2)

	before, err := s.Repo.DebugCounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	w := request(t, h, http.MethodPost, "/v1/sessions/preview", receiver1, map[string]any{"share_id": share1.ID, "consumer_device_id": consumer1})
	if w.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	after, err := s.Repo.DebugCounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if before["sessions"] != after["sessions"] {
		t.Fatalf("preview mutated sessions: before=%d after=%d", before["sessions"], after["sessions"])
	}

	create := func(token, shareID, consumerID string) database.TunnelConfig {
		w := request(t, h, http.MethodPost, "/v1/sessions", token, map[string]any{"share_id": shareID, "consumer_device_id": consumerID})
		if w.Code != http.StatusCreated {
			t.Fatalf("create session: %d %s", w.Code, w.Body.String())
		}
		var v struct {
			Tunnel database.TunnelConfig `json:"tunnel"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v.Tunnel
	}
	tunnel1 := create(receiver1, share1.ID, consumer1)
	tunnel2 := create(receiver2, share2.ID, consumer2)
	if tunnel1.ConsumerTunnelIP == tunnel2.ConsumerTunnelIP {
		t.Fatalf("concurrent consumers received duplicate address %q", tunnel1.ConsumerTunnelIP)
	}
	if tunnel1.ProviderPublicKey != tunnel2.ProviderPublicKey {
		t.Fatalf("sessions were not assigned to the same available provider")
	}
}
