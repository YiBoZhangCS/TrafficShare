package windowsnet

import (
	"context"
	"testing"
)

func TestProviderReachable(t *testing.T) {
	fake := &FakeCommandRunner{Result: Result{Stdout: "true\r\n"}}
	ok, err := ProviderReachable(context.Background(), fake, "192.168.1.20")
	if err != nil || !ok {
		t.Fatalf("expected reachable: %v %v", ok, err)
	}
	if _, err := ProviderReachable(context.Background(), fake, "not-an-ip"); err == nil {
		t.Fatal("invalid IP accepted")
	}
}
