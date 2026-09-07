package session

import (
	"errors"
	"time"
)

type Status string

const (
	Pending       Status = "pending"
	Active        Status = "active"
	Disconnecting Status = "disconnecting"
	Disconnected  Status = "disconnected"
	Revoked       Status = "revoked"
	Failed        Status = "failed"
)

type Machine struct {
	Status    Status    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

var transitions = map[Status]map[Status]bool{
	Pending:       {Active: true, Failed: true, Revoked: true},
	Active:        {Disconnecting: true, Revoked: true, Failed: true},
	Disconnecting: {Disconnected: true, Failed: true},
	Failed:        {Disconnecting: true, Disconnected: true},
	Revoked:       {Disconnecting: true, Disconnected: true},
}

func (m *Machine) Transition(to Status, now time.Time) error {
	if m.Status == "" {
		m.Status = Pending
	}
	if !transitions[m.Status][to] {
		return errors.New("invalid session state transition from " + string(m.Status) + " to " + string(to))
	}
	m.Status = to
	m.UpdatedAt = now.UTC()
	return nil
}
