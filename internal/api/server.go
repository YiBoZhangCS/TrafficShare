package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trafficshare/internal/auth"
	"trafficshare/internal/config"
	"trafficshare/internal/database"
)

type Server struct {
	Repo         database.Repository
	Auth         auth.Service
	HeartbeatTTL time.Duration
	Tunnel       config.TunnelConfig
	Now          func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("POST /v1/login", s.login)
	mux.HandleFunc("POST /v1/devices", s.withUser(s.registerDevice))
	mux.HandleFunc("POST /v1/heartbeat", s.withUser(s.heartbeat))
	mux.HandleFunc("POST /v1/shares", s.withUser(s.createShare))
	mux.HandleFunc("GET /v1/shares", s.withUser(s.listShares))
	mux.HandleFunc("DELETE /v1/shares/{id}", s.withUser(s.stopShare))
	mux.HandleFunc("POST /v1/sessions/preview", s.withUser(s.previewSession))
	mux.HandleFunc("POST /v1/sessions", s.withUser(s.createSession))
	mux.HandleFunc("GET /v1/provider/sessions", s.withUser(s.providerSessions))
	mux.HandleFunc("GET /v1/provider/shares", s.withUser(s.providerShares))
	mux.HandleFunc("GET /v1/sessions/{id}", s.withUser(s.sessionView))
	mux.HandleFunc("GET /v1/sessions/{id}/config", s.withUser(s.sessionConfig))
	mux.HandleFunc("POST /v1/sessions/{id}/disconnect", s.withUser(s.disconnectSession))
	mux.HandleFunc("POST /v1/sessions/{id}/traffic", s.withUser(s.reportTraffic))
	mux.HandleFunc("POST /v1/sessions/{id}/revoke", s.withUser(s.revokeSession))
	return securityHeaders(mux)
}

type userHandler func(http.ResponseWriter, *http.Request, database.User)

func (s *Server) withUser(next userHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		u, err := s.Auth.Authenticate(r.Context(), strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		next(w, r, u)
	}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, err := s.Auth.Register(r.Context(), req.Username, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	login, err := s.Auth.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, login)
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request, u database.User) {
	var req database.Device
	if !decode(w, r, &req) {
		return
	}
	d, err := s.Repo.UpsertDevice(r.Context(), u.ID, req, s.now())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, u database.User) {
	var req struct {
		DeviceID string `json:"device_id"`
		LANIP    string `json:"lan_ip"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.Repo.HeartbeatDevice(r.Context(), u.ID, req.DeviceID, req.LANIP, s.now()); err != nil {
		writeDomainError(w, err)
		return
	}
	disconnect, err := s.Repo.MustDisconnect(r.Context(), u.ID, req.DeviceID, s.now())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "disconnect_sessions": disconnect})
}

func (s *Server) createShare(w http.ResponseWriter, r *http.Request, u database.User) {
	var req struct {
		ReceiverUsername string    `json:"receiver_username"`
		QuotaBytes       int64     `json:"quota_bytes"`
		ExpiresAt        time.Time `json:"expires_at"`
	}
	if !decode(w, r, &req) {
		return
	}
	share, err := s.Repo.CreateShare(r.Context(), u.ID, req.ReceiverUsername, req.QuotaBytes, req.ExpiresAt, s.now())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, share)
}

func (s *Server) listShares(w http.ResponseWriter, r *http.Request, u database.User) {
	shares, err := s.Repo.AvailableShares(r.Context(), u.ID, s.now(), s.heartbeatTTL())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": shares})
}

func (s *Server) stopShare(w http.ResponseWriter, r *http.Request, u database.User) {
	if err := s.Repo.StopShare(r.Context(), u.ID, r.PathValue("id")); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, u database.User) {
	var req struct {
		ShareID          string `json:"share_id"`
		ConsumerDeviceID string `json:"consumer_device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	session, cfg, err := s.Repo.CreateSession(r.Context(), u.ID, req.ShareID, req.ConsumerDeviceID, s.now(), s.heartbeatTTL(), s.tunnelPool())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	cfg = s.tunnelConfig(cfg)
	writeJSON(w, http.StatusCreated, map[string]any{"session": session, "tunnel": cfg})
}

func (s *Server) previewSession(w http.ResponseWriter, r *http.Request, u database.User) {
	var req struct {
		ShareID          string `json:"share_id"`
		ConsumerDeviceID string `json:"consumer_device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	cfg, err := s.Repo.PreviewSession(r.Context(), u.ID, req.ShareID, req.ConsumerDeviceID, s.now(), s.heartbeatTTL(), s.tunnelPool())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnel": s.tunnelConfig(cfg)})
}

func (s *Server) providerSessions(w http.ResponseWriter, r *http.Request, u database.User) {
	deviceID := r.URL.Query().Get("device_id")
	items, err := s.Repo.ProviderSessions(r.Context(), u.ID, deviceID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	for i := range items {
		items[i].Tunnel = s.tunnelConfig(items[i].Tunnel)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": items})
}

func (s *Server) providerShares(w http.ResponseWriter, r *http.Request, u database.User) {
	items, err := s.Repo.OwnedShares(r.Context(), u.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": items})
}
func (s *Server) sessionView(w http.ResponseWriter, r *http.Request, u database.User) {
	v, err := s.Repo.SessionView(r.Context(), u.ID, r.PathValue("id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) sessionConfig(w http.ResponseWriter, r *http.Request, u database.User) {
	cfg, err := s.Repo.SessionConfig(r.Context(), u.ID, r.PathValue("id"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.tunnelConfig(cfg))
}

func (s *Server) tunnelConfig(v database.TunnelConfig) database.TunnelConfig {
	prefix := s.Tunnel.Prefix
	if prefix == "" {
		prefix = "10.66.0.0/24"
	}
	provider := s.Tunnel.ProviderIP
	if provider == "" {
		provider = "10.66.0.1/24"
	}
	consumer := s.Tunnel.ConsumerIP
	if consumer == "" {
		consumer = "10.66.0.2/24"
	}
	port := s.Tunnel.Port
	if port == 0 {
		port = 51820
	}
	v.TunnelPrefix, v.ProviderTunnelIP, v.Port = prefix, provider, port
	if v.ConsumerTunnelIP == "" {
		v.ConsumerTunnelIP = consumer
	}
	return v
}

func (s *Server) tunnelPool() database.TunnelPool {
	return database.TunnelPool{Prefix: s.Tunnel.Prefix, ProviderIP: s.Tunnel.ProviderIP, ConsumerIP: s.Tunnel.ConsumerIP, Port: s.Tunnel.Port}
}

func (s *Server) disconnectSession(w http.ResponseWriter, r *http.Request, u database.User) {
	if err := s.Repo.DisconnectSession(r.Context(), u.ID, r.PathValue("id")); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request, u database.User) {
	if err := s.Repo.RevokeSession(r.Context(), u.ID, r.PathValue("id")); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reportTraffic(w http.ResponseWriter, r *http.Request, u database.User) {
	var req struct {
		ProviderDeviceID string `json:"provider_device_id"`
		RXBytes          int64  `json:"rx_bytes"`
		TXBytes          int64  `json:"tx_bytes"`
		TotalBytes       int64  `json:"total_bytes"`
	}
	if !decode(w, r, &req) {
		return
	}
	exhausted, err := s.Repo.ReportTraffic(r.Context(), u.ID, req.ProviderDeviceID, database.TrafficReport{SessionID: r.PathValue("id"), RXBytes: req.RXBytes, TXBytes: req.TXBytes, TotalBytes: req.TotalBytes}, s.now())
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"quota_exhausted": exhausted, "disconnect": exhausted})
}

func (s *Server) heartbeatTTL() time.Duration {
	if s.HeartbeatTTL <= 0 {
		return 20 * time.Second
	}
	return s.HeartbeatTTL
}

func (s *Server) Sweep(ctx context.Context) error {
	return s.Repo.ExpireStale(ctx, s.now(), s.heartbeatTTL())
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain one JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, database.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, database.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	case errors.Is(err, database.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "Provider is not reachable on current LAN")
	case errors.Is(err, database.ErrQuota):
		writeError(w, http.StatusConflict, "quota exhausted")
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func ListenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	return ListenAndServeTLS(ctx, addr, handler, "", "")
}

func ListenAndServeTLS(ctx context.Context, addr string, handler http.Handler, certPath, keyPath string) error {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		if certPath != "" && keyPath != "" {
			errCh <- server.ListenAndServeTLS(certPath, keyPath)
			return
		}
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("control server: %w", err)
	}
}
