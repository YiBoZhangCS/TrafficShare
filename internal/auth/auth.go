package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"trafficshare/internal/database"
)

type Service struct {
	Repo       database.Repository
	TokenTTL   time.Duration
	BcryptCost int
	Now        func() time.Time
}

type Login struct {
	User      database.User `json:"user"`
	Token     string        `json:"token"`
	ExpiresAt time.Time     `json:"expires_at"`
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Service) cost() int {
	if s.BcryptCost != 0 {
		return s.BcryptCost
	}
	return bcrypt.DefaultCost
}

func (s Service) Register(ctx context.Context, username, password string) (database.User, error) {
	if len(password) < 10 || len(password) > 1024 {
		return database.User{}, errors.New("password must be 10-1024 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cost())
	if err != nil {
		return database.User{}, err
	}
	return s.Repo.CreateUser(ctx, username, string(hash), s.now())
}

func (s Service) Login(ctx context.Context, username, password string) (Login, error) {
	u, err := s.Repo.UserByUsername(ctx, username)
	if err != nil {
		return Login{}, errors.New("invalid username or password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return Login{}, errors.New("invalid username or password")
	}
	token, err := randomToken()
	if err != nil {
		return Login{}, err
	}
	ttl := s.TokenTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	expires := s.now().Add(ttl)
	if err := s.Repo.SaveToken(ctx, token, u.ID, expires, s.now()); err != nil {
		return Login{}, err
	}
	return Login{User: u, Token: token, ExpiresAt: expires}, nil
}

func (s Service) Authenticate(ctx context.Context, token string) (database.User, error) {
	if token == "" {
		return database.User{}, database.ErrForbidden
	}
	return s.Repo.UserByToken(ctx, token, s.now())
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
