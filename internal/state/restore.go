package state

import (
	"context"
	"fmt"

	"trafficshare/internal/windowsnet"
)

type Restorer struct {
	Runner windowsnet.CommandRunner
	Store  Store
}

// Plan only removes exact resources recorded in a validated snapshot.
func (r Restorer) Plan(snapshot Snapshot) (windowsnet.Plan, error) {
	if err := snapshot.Validate(); err != nil {
		return windowsnet.Plan{}, err
	}
	plan := windowsnet.Plan{SessionID: snapshot.SessionID, Role: "restore"}
	for _, route := range snapshot.AddedRoutes {
		plan.Actions = append(plan.Actions, windowsnet.Action{
			Description: "remove recorded TrafficShare route",
			Resource:    "TrafficShare-EndpointRoute-" + snapshot.SessionID,
			Script:      fmt.Sprintf("if (Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex %d -NextHop '%s' -ErrorAction SilentlyContinue) { Remove-NetRoute -DestinationPrefix '%s' -InterfaceIndex %d -NextHop '%s' -Confirm:$false -ErrorAction Stop }", route.DestinationPrefix, route.InterfaceIndex, route.NextHop, route.DestinationPrefix, route.InterfaceIndex, route.NextHop),
		})
	}
	for _, name := range snapshot.FirewallRules {
		plan.Actions = append(plan.Actions, windowsnet.Action{Description: "remove recorded TrafficShare firewall rule", Resource: name, Script: fmt.Sprintf("if (Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -DisplayName '%s' -ErrorAction Stop }", name, name)})
	}
	for _, name := range snapshot.NATNames {
		plan.Actions = append(plan.Actions, windowsnet.Action{Description: "remove recorded TrafficShare NAT", Resource: name, Script: fmt.Sprintf("if (Get-NetNat -Name '%s' -ErrorAction SilentlyContinue) { Remove-NetNat -Name '%s' -Confirm:$false -ErrorAction Stop }", name, name)})
	}
	return plan, nil
}

func (r Restorer) Restore(ctx context.Context, snapshot Snapshot, dryRun bool) (windowsnet.Plan, error) {
	plan, err := r.Plan(snapshot)
	if err != nil {
		return windowsnet.Plan{}, err
	}
	if _, err := (windowsnet.Engine{Runner: r.Runner}).Apply(ctx, plan, dryRun); err != nil {
		return plan, err
	}
	if !dryRun {
		if err := r.Store.MarkCompleted(snapshot.SessionID); err != nil {
			return plan, fmt.Errorf("network restored but state completion could not be recorded: %w", err)
		}
	}
	return plan, nil
}
