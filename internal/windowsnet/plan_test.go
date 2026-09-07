package windowsnet

import (
	"context"
	"strings"
	"testing"
)

type FakeCommandRunner struct {
	Calls  []string
	Result Result
	Err    error
}

func (f *FakeCommandRunner) Run(_ context.Context, program string, args ...string) (Result, error) {
	f.Calls = append(f.Calls, program+" "+strings.Join(args, " "))
	return f.Result, f.Err
}

func TestDryRunNeverExecutesCommands(t *testing.T) {
	plan, err := ProviderPlan(PlanOptions{SessionID: "abc", TunnelAlias: "TrafficShare-Tunnel", TunnelPrefix: "10.66.0.0/24", NATName: "TrafficShare-NAT", ListenPort: 51820})
	if err != nil {
		t.Fatal(err)
	}
	fake := &FakeCommandRunner{}
	if _, err := (Engine{Runner: fake}).Apply(context.Background(), plan, true); err != nil {
		t.Fatal(err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("dry-run executed %d commands", len(fake.Calls))
	}
}

func TestProviderPlanUsesActivePublicProfile(t *testing.T) {
	plan, err := ProviderPlan(PlanOptions{SessionID: "abc", TunnelAlias: "TrafficShare-Tunnel", TunnelPrefix: "10.66.0.0/24", NATName: "TrafficShare-NAT", ListenPort: 51820, FirewallProfile: "Public"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Actions[2].Script, "-Profile Public") {
		t.Fatalf("provider firewall did not use the active profile: %s", plan.Actions[2].Script)
	}
}

func TestConsumerPlanPinsEndpointAndBlocksIPv6(t *testing.T) {
	plan, err := ConsumerPlan(PlanOptions{SessionID: "abc", TunnelAlias: "TrafficShare-Tunnel", TunnelPrefix: "10.66.0.0/24", NATName: "TrafficShare-NAT", EndpointIP: "192.168.1.10", InterfaceIndex: 7, Gateway: "192.168.1.1", ListenPort: 51820})
	if err != nil {
		t.Fatal(err)
	}
	joined := plan.Actions[0].Script + plan.Actions[1].Script
	for _, want := range []string{"192.168.1.10/32", "InterfaceIndex 7", allIPv6AddressRange} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan missing %q", want)
		}
	}
}

func TestCleanupRefusesUntaggedResource(t *testing.T) {
	if _, err := CleanupPlan("s1", []string{"User-NAT"}, "TrafficShare-Tunnel"); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestCleanupIsIdempotentWhenResourcesAreAbsent(t *testing.T) {
	plan, err := CleanupPlan("s1", []string{"TrafficShare-WireGuard-UDP-s1", "TrafficShare-NAT"}, "TrafficShare-Tunnel")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range plan.Actions {
		if !strings.HasPrefix(action.Script, "if (Get-Net") {
			t.Fatalf("cleanup action is not guarded by an existence check: %s", action.Script)
		}
		if !strings.Contains(action.Script, "-ErrorAction Stop") {
			t.Fatalf("cleanup action does not fail when removal of an existing resource fails: %s", action.Script)
		}
	}
}
