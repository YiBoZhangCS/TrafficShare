package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"trafficshare/internal/database"
)

func TestPasswordsAreHashedAndTokensExpire(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := Service{Repo: database.Repository{DB: db}, TokenTTL: time.Hour, BcryptCost: bcrypt.MinCost, Now: func() time.Time { return now }}
	u, err := s.Register(context.Background(), "alice", "strong-password")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash == "strong-password" {
		t.Fatal("password stored in plaintext")
	}
	login, err := s.Login(context.Background(), "alice", "strong-password")
	if err != nil {
		t.Fatal(err)
	}
	if login.Token == "" {
		t.Fatal("missing token")
	}
	if _, err := s.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := s.Authenticate(context.Background(), login.Token); err == nil {
		t.Fatal("expired token accepted")
	}
}
