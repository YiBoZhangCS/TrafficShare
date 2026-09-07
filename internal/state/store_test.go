package state

import (
	"testing"
)

func TestStoreFindsIncompleteSnapshots(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	s := Snapshot{SessionID: "session-1", Role: "consumer", TunnelName: "TrafficShare-Tunnel", NATNames: []string{"TrafficShare-NAT"}}
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}
	items, err := store.Incomplete()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SessionID != s.SessionID {
		t.Fatalf("unexpected incomplete state: %#v", items)
	}
	if err := store.MarkCompleted(s.SessionID); err != nil {
		t.Fatal(err)
	}
	items, err = store.Incomplete()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("completed state still returned: %#v", items)
	}
}

func TestRejectsUntaggedResources(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	if err := store.Save(Snapshot{SessionID: "x", NATNames: []string{"SomeoneElsesNAT"}}); err == nil {
		t.Fatal("expected untagged resource rejection")
	}
}
