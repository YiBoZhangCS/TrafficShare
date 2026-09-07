package webui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"trafficshare/internal/database"
	"trafficshare/internal/windowsnet"
)

//go:embed assets/*
var assets embed.FS

type Backend interface {
	Settings(context.Context) (Settings, error)
	UpdateSettings(context.Context, string, string, string) (Settings, error)
	ControlHealth(context.Context) error
	Doctor(context.Context) (windowsnet.DoctorReport, error)
	Status(context.Context) (map[string]any, error)
	Login(context.Context, string, string, bool) error
	RegisterDevice(context.Context) (database.Device, error)
	ProviderInit(context.Context, bool) (any, error)
	CreateShare(context.Context, string, int64, time.Duration) (database.Share, error)
	ProviderShares(context.Context) ([]database.Share, error)
	StopShare(context.Context, string) error
	Shares(context.Context) ([]database.Share, error)
	Connect(context.Context, string, bool) (database.Session, any, error)
	Disconnect(context.Context, string, bool) error
	Logs() string
}

type Settings struct {
	Role           string `json:"role"`
	RoleLocked     bool   `json:"role_locked"`
	ServerURL      string `json:"server_url"`
	DeviceName     string `json:"device_name"`
	Username       string `json:"username,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	Authenticated  bool   `json:"authenticated"`
	EmbeddedServer bool   `json:"embedded_server"`
	ConfigPath     string `json:"config_path"`
}

type Server struct {
	Backend Backend
	csrf    string
}

func New(backend Backend) (*Server, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{Backend: backend, csrf: base64.RawURLEncoding.EncodeToString(b)}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	sub, _ := fs.Sub(assets, "assets")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /api/doctor", s.wrap(s.doctor))
	mux.HandleFunc("GET /api/settings", s.wrap(s.settings))
	mux.HandleFunc("POST /api/settings", s.wrap(s.updateSettings))
	mux.HandleFunc("GET /api/control-health", s.wrap(s.controlHealth))
	mux.HandleFunc("GET /api/status", s.wrap(s.status))
	mux.HandleFunc("GET /api/shares", s.wrap(s.shares))
	mux.HandleFunc("GET /api/provider/shares", s.wrap(s.providerShares))
	mux.HandleFunc("GET /api/logs", s.wrap(s.logs))
	mux.HandleFunc("POST /api/login", s.wrap(s.login))
	mux.HandleFunc("POST /api/device", s.wrap(s.device))
	mux.HandleFunc("POST /api/provider/init", s.wrap(s.providerInit))
	mux.HandleFunc("POST /api/share", s.wrap(s.createShare))
	mux.HandleFunc("POST /api/share/stop", s.wrap(s.stopShare))
	mux.HandleFunc("POST /api/connect", s.wrap(s.connect))
	mux.HandleFunc("POST /api/disconnect", s.wrap(s.disconnect))
	return localOnly(securityHeaders(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Backend.Settings(r.Context())
	if err == nil {
		writeJSON(w, v)
	}
	return err
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		Role       string `json:"role"`
		ServerURL  string `json:"server_url"`
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}
	settings, err := s.Backend.UpdateSettings(r.Context(), v.Role, v.ServerURL, v.DeviceName)
	if err == nil {
		writeJSON(w, settings)
	}
	return err
}

func (s *Server) controlHealth(w http.ResponseWriter, r *http.Request) error {
	if err := s.Backend.ControlHealth(r.Context()); err != nil {
		return err
	}
	writeJSON(w, map[string]bool{"online": true})
	return nil
}

func (s *Server) index(w http.ResponseWriter, _ *http.Request) {
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(string(b), "__CSRF__", s.csrf)))
}

type endpoint func(http.ResponseWriter, *http.Request) error

func (s *Server) wrap(next endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method != "GET" && r.Header.Get("X-CSRF-Token") != s.csrf {
			writeError(w, http.StatusForbidden, errors.New("invalid CSRF token"))
			return
		}
		if err := next(w, r); err != nil {
			writeError(w, http.StatusBadRequest, err)
		}
	}
}
func (s *Server) doctor(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Backend.Doctor(r.Context())
	if err == nil {
		writeJSON(w, v)
	}
	return err
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Backend.Status(r.Context())
	if err == nil {
		writeJSON(w, v)
	}
	return err
}
func (s *Server) shares(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Backend.Shares(r.Context())
	if err == nil {
		writeJSON(w, map[string]any{"shares": v})
	}
	return err
}
func (s *Server) providerShares(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Backend.ProviderShares(r.Context())
	if err == nil {
		writeJSON(w, map[string]any{"shares": v})
	}
	return err
}
func (s *Server) logs(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, map[string]string{"logs": s.Backend.Logs()})
	return nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Register bool   `json:"register"`
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}
	if err := s.Backend.Login(r.Context(), v.Username, v.Password, v.Register); err != nil {
		return err
	}
	writeJSON(w, map[string]string{"status": "ok"})
	return nil
}
func (s *Server) device(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Backend.RegisterDevice(r.Context())
	if err == nil {
		writeJSON(w, v)
	}
	return err
}
func (s *Server) providerInit(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		Apply bool `json:"apply"`
	}
	_ = json.NewDecoder(r.Body).Decode(&v)
	result, err := s.Backend.ProviderInit(r.Context(), v.Apply)
	if err == nil {
		writeJSON(w, result)
	}
	return err
}
func (s *Server) createShare(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		Receiver   string `json:"receiver"`
		QuotaBytes int64  `json:"quota_bytes"`
		Hours      int    `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}
	share, err := s.Backend.CreateShare(r.Context(), v.Receiver, v.QuotaBytes, time.Duration(v.Hours)*time.Hour)
	if err == nil {
		writeJSON(w, share)
	}
	return err
}
func (s *Server) stopShare(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		ShareID string `json:"share_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}
	if err := s.Backend.StopShare(r.Context(), v.ShareID); err != nil {
		return err
	}
	writeJSON(w, map[string]string{"status": "stopped"})
	return nil
}
func (s *Server) connect(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		ShareID string `json:"share_id"`
		Apply   bool   `json:"apply"`
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}
	session, plan, err := s.Backend.Connect(r.Context(), v.ShareID, v.Apply)
	if err == nil {
		writeJSON(w, map[string]any{"session": session, "plan": plan, "applied": v.Apply})
	}
	return err
}
func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) error {
	var v struct {
		SessionID string `json:"session_id"`
		Apply     bool   `json:"apply"`
	}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}
	if err := s.Backend.Disconnect(r.Context(), v.SessionID, v.Apply); err != nil {
		return err
	}
	writeJSON(w, map[string]bool{"applied": v.Apply})
	return nil
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "local access only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ListenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return errors.New("local UI must bind to 127.0.0.1")
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("local UI: %w", err)
	}
}
