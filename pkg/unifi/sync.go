package unifi

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
)

type targetShard struct {
	Name       string
	GroupType  string
	URL        string
	IPVersion  string
	Family     string
	ShardIndex int
}

func buildTargetShards(baseURL string, ipv4Count, ipv6Count int) []targetShard {
	shards := make([]targetShard, 0, ipv4Count+ipv6Count)
	for i := 0; i < ipv4Count; i++ {
		shards = append(shards, targetShard{
			Name:       fmt.Sprintf("CrowdSec-EDL-IPv4-%d", i),
			GroupType:  "address-group",
			URL:        fmt.Sprintf("%s/ipv4-%d.txt", baseURL, i),
			IPVersion:  "IPV4",
			Family:     "ipv4",
			ShardIndex: i,
		})
	}
	for i := 0; i < ipv6Count; i++ {
		shards = append(shards, targetShard{
			Name:       fmt.Sprintf("CrowdSec-EDL-IPv6-%d", i),
			GroupType:  "ipv6-address-group",
			URL:        fmt.Sprintf("%s/ipv6-%d.txt", baseURL, i),
			IPVersion:  "IPV6",
			Family:     "ipv6",
			ShardIndex: i,
		})
	}
	return shards
}

// Reconcile synchronizes UniFi External Dynamic Lists and Zone-Based Firewall rules against the desired configuration.
func Reconcile(ctx context.Context, client *Client, cfg *Config) error {
	log.Printf("INFO: starting UniFi EDL reconciliation against %s (site: %s)", cfg.Host, cfg.Site)

	// 1. Discover Zones dynamically
	zones, err := client.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("list firewall zones: %w", err)
	}

	zoneMap := make(map[string]string, len(zones))
	for _, z := range zones {
		zoneMap[strings.ToLower(strings.TrimSpace(z.Name))] = z.ID
	}

	srcZoneIDs := make(map[string]string)
	for _, name := range cfg.ZoneSrc {
		if id, ok := zoneMap[strings.ToLower(name)]; ok {
			srcZoneIDs[name] = id
		} else {
			log.Printf("WARN: source zone %q not found on gateway", name)
		}
	}

	dstZoneIDs := make(map[string]string)
	for _, name := range cfg.ZoneDst {
		if id, ok := zoneMap[strings.ToLower(name)]; ok {
			dstZoneIDs[name] = id
		} else {
			log.Printf("WARN: destination zone %q not found on gateway", name)
		}
	}

	if len(srcZoneIDs) == 0 || len(dstZoneIDs) == 0 {
		return fmt.Errorf("no matching source or destination zones resolved")
	}

	// 2. Reconcile External Dynamic Lists (Firewall Groups)
	existingGroups, err := client.ListGroups(ctx)
	if err != nil {
		return fmt.Errorf("list firewall groups: %w", err)
	}

	groupByExactName := make(map[string]FirewallGroup, len(existingGroups))
	for _, g := range existingGroups {
		groupByExactName[g.Name] = g
	}

	targets := buildTargetShards(cfg.BaseURL, cfg.IPv4Shards, cfg.IPv6Shards)
	groupIDs := make(map[string]string, len(targets))

	for _, target := range targets {
		existing, ok := groupByExactName[target.Name]
		if ok {
			groupIDs[target.Name] = existing.ID
			if existing.URL != target.URL || existing.UpdateIntervalSeconds != cfg.UpdateIntervalSecs {
				log.Printf("INFO: updating group %s URL or interval", target.Name)
				updateGroup := &FirewallGroup{
					ID:                    existing.ID,
					Name:                  target.Name,
					GroupType:             target.GroupType,
					Source:                "dynamic",
					URL:                   target.URL,
					UpdateIntervalSeconds: cfg.UpdateIntervalSecs,
					GroupMembers:          []string{},
				}
				if err := client.UpdateGroup(ctx, existing.ID, updateGroup); err != nil {
					return fmt.Errorf("update firewall group %s: %w", target.Name, err)
				}
			}
		} else {
			log.Printf("INFO: creating dynamic firewall group %s -> %s", target.Name, target.URL)
			newGroup := &FirewallGroup{
				Name:                  target.Name,
				GroupType:             target.GroupType,
				Source:                "dynamic",
				URL:                   target.URL,
				UpdateIntervalSeconds: cfg.UpdateIntervalSecs,
				GroupMembers:          []string{},
			}
			created, err := client.CreateGroup(ctx, newGroup)
			if err != nil {
				return fmt.Errorf("create firewall group %s: %w", target.Name, err)
			}
			groupIDs[target.Name] = created.ID
		}
	}

	// 3. Reconcile Zone-Based Firewall Policies
	existingPolicies, err := client.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("list firewall policies: %w", err)
	}

	policyByName := make(map[string]FirewallZonePolicy, len(existingPolicies))
	for _, p := range existingPolicies {
		policyByName[p.Name] = p
	}

	for sName, sID := range srcZoneIDs {
		for dName, dID := range dstZoneIDs {
			for _, target := range targets {
				gID := groupIDs[target.Name]
				policyName := fmt.Sprintf("CrowdSec-EDL-%s-%s->%s-%d", target.Family, sName, dName, target.ShardIndex)

				desiredPolicy := &FirewallZonePolicy{
					Name:                policyName,
					Action:              cfg.RuleAction,
					Enabled:             true,
					CreateAllowRespond:  false,
					ConnectionStateType: "CUSTOM",
					ConnectionStates:    cfg.RuleStates,
					Protocol:            "all",
					IPVersion:           target.IPVersion,
					Logging:             false,
					Description:         "CrowdSec External Dynamic List",
					Source: FirewallZonePolicySource{
						ZoneID:             sID,
						MatchingTarget:     "IP",
						MatchingTargetType: "OBJECT",
						PortMatchingType:   "ANY",
						IPGroupID:          gID,
					},
					Destination: FirewallZonePolicyDestination{
						ZoneID:           dID,
						MatchingTarget:   "ANY",
						PortMatchingType: "ANY",
					},
					Schedule: FirewallZonePolicySchedule{
						Mode: "ALWAYS",
					},
				}

				existing, ok := policyByName[policyName]
				if !ok {
					log.Printf("INFO: creating firewall policy %s", policyName)
					if _, err := client.CreatePolicy(ctx, desiredPolicy); err != nil {
						return fmt.Errorf("create firewall policy %s: %w", policyName, err)
					}
				} else if policyDrifted(&existing, desiredPolicy, gID) {
					log.Printf("INFO: updating drifted firewall policy %s", policyName)
					desiredPolicy.ID = existing.ID
					if err := client.UpdatePolicy(ctx, existing.ID, desiredPolicy); err != nil {
						return fmt.Errorf("update firewall policy %s: %w", policyName, err)
					}
				}
			}
		}
	}

	// 4. Optional Legacy Pruning
	if cfg.PruneLegacy {
		log.Println("INFO: pruning legacy cs-unifi-bouncer policies and groups")
		currPolicies, _ := client.ListPolicies(ctx)
		for _, p := range currPolicies {
			if strings.HasPrefix(p.Name, "cs-unifi-bouncer") || p.ID == "797c809c-5e49-4a4b-9952-e3db1c462dd0" {
				log.Printf("INFO: deleting legacy policy %s (%s)", p.Name, p.ID)
				_ = client.DeletePolicy(ctx, p.ID)
			}
		}
		currGroups, _ := client.ListGroups(ctx)
		for _, g := range currGroups {
			if strings.HasPrefix(g.Name, "cs-unifi-bouncer") {
				log.Printf("INFO: deleting legacy group %s (%s)", g.Name, g.ID)
				_ = client.DeleteGroup(ctx, g.ID)
			}
		}
	}

	// 5. Ensure Optimal Policy Precedence (Batch Reordering)
	allPolicies, err := client.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("list policies for reordering: %w", err)
	}

	for sName, sID := range srcZoneIDs {
		for dName, dID := range dstZoneIDs {
			if err := reorderZonePair(ctx, client, allPolicies, sName, sID, dName, dID, cfg.IPv4Shards, cfg.IPv6Shards); err != nil {
				log.Printf("WARN: failed to reorder policies for %s -> %s: %v", sName, dName, err)
			}
		}
	}

	log.Println("INFO: UniFi EDL reconciliation completed successfully")
	return nil
}

func policyDrifted(curr, desired *FirewallZonePolicy, desiredGroupID string) bool {
	if curr.Action != desired.Action || !curr.Enabled || curr.CreateAllowRespond {
		return true
	}
	if curr.Source.IPGroupID != desiredGroupID {
		return true
	}
	if !slices.Equal(curr.ConnectionStates, desired.ConnectionStates) {
		return true
	}
	return false
}

func reorderZonePair(
	ctx context.Context,
	client *Client,
	allPolicies []FirewallZonePolicy,
	sName, sID, dName, dID string,
	ipv4Shards, ipv6Shards int,
) error {
	var relevant []FirewallZonePolicy
	for _, p := range allPolicies {
		if p.Source.ZoneID == sID && p.Destination.ZoneID == dID && !p.Predefined && (p.Index < 30000 || p.Index >= 40000) {
			relevant = append(relevant, p)
		}
	}

	if len(relevant) == 0 {
		return nil
	}

	var edlPols []FirewallZonePolicy
	var otherPols []FirewallZonePolicy
	for _, p := range relevant {
		if strings.HasPrefix(p.Name, "CrowdSec-EDL-") {
			edlPols = append(edlPols, p)
		} else {
			otherPols = append(otherPols, p)
		}
	}

	edlOrder := make([]string, 0, ipv4Shards+ipv6Shards)
	for i := 0; i < ipv4Shards; i++ {
		edlOrder = append(edlOrder, fmt.Sprintf("ipv4-%s->%s-%d", sName, dName, i))
	}
	for i := 0; i < ipv6Shards; i++ {
		edlOrder = append(edlOrder, fmt.Sprintf("ipv6-%s->%s-%d", sName, dName, i))
	}

	slices.SortFunc(edlPols, func(a, b FirewallZonePolicy) int {
		idxA := indexOfSuffix(a.Name, edlOrder)
		idxB := indexOfSuffix(b.Name, edlOrder)
		return idxA - idxB
	})

	slices.SortFunc(otherPols, func(a, b FirewallZonePolicy) int {
		return a.Index - b.Index
	})

	desiredIDs := make([]string, 0, len(edlPols)+len(otherPols))
	for _, p := range edlPols {
		desiredIDs = append(desiredIDs, p.ID)
	}
	for _, p := range otherPols {
		desiredIDs = append(desiredIDs, p.ID)
	}

	currentOrder := make([]FirewallZonePolicy, len(relevant))
	copy(currentOrder, relevant)
	slices.SortFunc(currentOrder, func(a, b FirewallZonePolicy) int {
		return a.Index - b.Index
	})
	currentIDs := make([]string, len(currentOrder))
	for i, p := range currentOrder {
		currentIDs[i] = p.ID
	}

	if slices.Equal(desiredIDs, currentIDs) {
		return nil
	}

	log.Printf("INFO: reordering %d policies for zone pair %s -> %s", len(desiredIDs), sName, dName)
	return client.BatchReorder(ctx, &BatchReorderRequest{
		SourceZoneID:        sID,
		DestinationZoneID:   dID,
		BeforePredefinedIDs: desiredIDs,
		AfterPredefinedIDs:  []string{},
	})
}

func indexOfSuffix(name string, patterns []string) int {
	for i, pat := range patterns {
		if strings.Contains(name, pat) {
			return i
		}
	}
	return 999
}

// RunSync loads configuration and executes UniFi reconciliation.
func RunSync(ctx context.Context) error {
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("load unifi config: %w", err)
	}
	client := NewClient(cfg, nil)
	return Reconcile(ctx, client, cfg)
}
