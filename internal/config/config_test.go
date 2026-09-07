package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.Agent.StateDir = filepath.Join(t.TempDir(), "state")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, got) {
		t.Fatalf("round trip mismatch\nwant: %#v\ngot:  %#v", cfg, got)
	}
}

func TestRejectsExposedUI(t *testing.T) {
	cfg := Default()
	cfg.Agent.UIListen = "0.0.0.0:9080"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected exposed UI validation failure")
	}
}
