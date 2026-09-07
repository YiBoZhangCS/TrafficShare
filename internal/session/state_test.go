package session

import (
	"testing"
	"time"
)

func TestStateTransitions(t *testing.T) {
	m := Machine{Status: Pending}
	if err := m.Transition(Active, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.Transition(Pending, time.Now()); err == nil {
		t.Fatal("active session must not become pending")
	}
	if err := m.Transition(Revoked, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.Transition(Disconnected, time.Now()); err != nil {
		t.Fatal(err)
	}
}
