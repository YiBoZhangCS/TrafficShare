package webui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trafficshare/internal/database"
	"trafficshare/internal/windowsnet"
)

type fakeBackend struct{}

func (fakeBackend) Settings(context.Context) (Settings, error) { return Settings{}, nil }
func (fakeBackend) UpdateSettings(context.Context, string, string, string) (Settings, error) {
	return Settings{}, nil
}
func (fakeBackend) ControlHealth(context.Context) error { return nil }
func (fakeBackend) Doctor(context.Context) (windowsnet.DoctorReport, error) {
	return windowsnet.DoctorReport{}, nil
}
func (fakeBackend) Status(context.Context) (map[string]any, error) {
	return map[string]any{"status": "ok"}, nil
}
func (fakeBackend) Login(context.Context, string, string, bool) error { return nil }
func (fakeBackend) RegisterDevice(context.Context) (database.Device, error) {
	return database.Device{}, nil
}
func (fakeBackend) ProviderInit(context.Context, bool) (any, error) { return map[string]any{}, nil }
func (fakeBackend) CreateShare(context.Context, string, int64, time.Duration) (database.Share, error) {
	return database.Share{}, nil
}
func (fakeBackend) ProviderShares(context.Context) ([]database.Share, error) { return nil, nil }
func (fakeBackend) StopShare(context.Context, string) error                  { return nil }
func (fakeBackend) Shares(context.Context) ([]database.Share, error)         { return nil, nil }
func (fakeBackend) Connect(context.Context, string, bool) (database.Session, any, error) {
	return database.Session{}, nil, nil
}
func (fakeBackend) Disconnect(context.Context, string, bool) error { return nil }
func (fakeBackend) Logs() string                                   { return "" }

func TestLocalHostAndCSRFProtection(t *testing.T) {
	s, err := New(fakeBackend{})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9080/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("local index: %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`id="primaryAction"`)) || !bytes.Contains(w.Body.Bytes(), []byte("按顺序完成这些步骤")) {
		t.Fatal("guided first-run UI is missing")
	}
	r = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9080/assets/guided.css", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("guided stylesheet: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "http://evil.example/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-local host accepted: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9080/api/device", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("write without CSRF accepted: %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9080/api/device", nil)
	r.Header.Set("X-CSRF-Token", s.csrf)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid local write rejected: %d %s", w.Code, w.Body.String())
	}
}
