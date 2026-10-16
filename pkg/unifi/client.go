package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Zone represents a UniFi firewall zone.
type Zone struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
}

// FirewallGroup represents a UniFi firewall group or dynamic external list.
type FirewallGroup struct {
	ID                    string   `json:"_id,omitempty"`
	Name                  string   `json:"name"`
	GroupType             string   `json:"group_type"`
	Source                string   `json:"source,omitempty"`
	URL                   string   `json:"url,omitempty"`
	UpdateIntervalSeconds int      `json:"update_interval_seconds,omitempty"`
	GroupMembers          []string `json:"group_members"`
}

// FirewallZonePolicy represents a UniFi Zone-Based Firewall policy.
type FirewallZonePolicy struct {
	ID                  string                        `json:"_id,omitempty"`
	Name                string                        `json:"name"`
	Action              string                        `json:"action"`
	Enabled             bool                          `json:"enabled"`
	CreateAllowRespond  bool                          `json:"create_allow_respond"`
	ConnectionStateType string                        `json:"connection_state_type"`
	ConnectionStates    []string                      `json:"connection_states"`
	Protocol            string                        `json:"protocol"`
	IPVersion           string                        `json:"ip_version"`
	Logging             bool                          `json:"logging"`
	Description         string                        `json:"description"`
	Index               int                           `json:"index,omitempty"`
	Predefined          bool                          `json:"predefined"`
	Source              FirewallZonePolicySource      `json:"source"`
	Destination         FirewallZonePolicyDestination `json:"destination"`
	Schedule            FirewallZonePolicySchedule    `json:"schedule"`
}

// FirewallZonePolicySource defines the source parameters of a ZBF policy.
type FirewallZonePolicySource struct {
	ZoneID             string `json:"zone_id"`
	MatchingTarget     string `json:"matching_target"`
	MatchingTargetType string `json:"matching_target_type"`
	PortMatchingType   string `json:"port_matching_type"`
	IPGroupID          string `json:"ip_group_id,omitempty"`
}

// FirewallZonePolicyDestination defines the destination parameters of a ZBF policy.
type FirewallZonePolicyDestination struct {
	ZoneID           string `json:"zone_id"`
	MatchingTarget   string `json:"matching_target"`
	PortMatchingType string `json:"port_matching_type"`
}

// FirewallZonePolicySchedule defines the schedule mode of a policy.
type FirewallZonePolicySchedule struct {
	Mode string `json:"mode"`
}

// BatchReorderRequest defines the payload for batch policy reordering.
type BatchReorderRequest struct {
	SourceZoneID        string   `json:"source_zone_id"`
	DestinationZoneID   string   `json:"destination_zone_id"`
	BeforePredefinedIDs []string `json:"before_predefined_ids"`
	AfterPredefinedIDs  []string `json:"after_predefined_ids"`
}

type unifiResponse[T any] struct {
	Data []T `json:"data"`
}

// Client interacts with the UniFi Network Controller REST API.
type Client struct {
	httpClient *http.Client
	baseURLV1  string
	baseURLV2  string
	apiKey     string
}

// NewClient initializes a new UniFi API client.
func NewClient(cfg *Config, customTransport http.RoundTripper) *Client {
	transport := customTransport
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec // user configurable for self-signed internal gateways
			},
		}
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		baseURLV1: fmt.Sprintf("%s/proxy/network/api/s/%s", cfg.Host, cfg.Site),
		baseURLV2: fmt.Sprintf("%s/proxy/network/v2/api/site/%s", cfg.Host, cfg.Site),
		apiKey:    cfg.APIKey,
	}
}

func (c *Client) request(ctx context.Context, method, url string, in any, out any) error {
	var bodyReader io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	// Retry loop for transient network or gateway errors (500, 502, 503, 504)
	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 500 * time.Millisecond):
			}
		}

		// Reset reader if reading from bytes buffer
		if in != nil {
			raw, _ := json.Marshal(in)
			bodyReader = bytes.NewReader(raw)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("X-API-KEY", c.apiKey)
		req.Header.Set("Accept", "application/json")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("unmarshal response: %w", err)
			}
		}
		return nil
	}

	return fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
}

// ListZones fetches all configured UniFi firewall zones.
func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	var zones []Zone
	err := c.request(ctx, http.MethodGet, c.baseURLV2+"/firewall/zone", nil, &zones)
	return zones, err
}

// ListGroups fetches all firewall groups from UniFi v1 API.
func (c *Client) ListGroups(ctx context.Context) ([]FirewallGroup, error) {
	var resp unifiResponse[FirewallGroup]
	err := c.request(ctx, http.MethodGet, c.baseURLV1+"/rest/firewallgroup", nil, &resp)
	return resp.Data, err
}

// CreateGroup creates a new firewall group (or external dynamic list).
func (c *Client) CreateGroup(ctx context.Context, g *FirewallGroup) (*FirewallGroup, error) {
	var resp unifiResponse[FirewallGroup]
	err := c.request(ctx, http.MethodPost, c.baseURLV1+"/rest/firewallgroup", g, &resp)
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("empty group response from controller")
	}
	return &resp.Data[0], nil
}

// UpdateGroup updates an existing firewall group by ID.
func (c *Client) UpdateGroup(ctx context.Context, id string, g *FirewallGroup) error {
	return c.request(ctx, http.MethodPut, fmt.Sprintf("%s/rest/firewallgroup/%s", c.baseURLV1, id), g, nil)
}

// DeleteGroup deletes a firewall group by ID.
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, fmt.Sprintf("%s/rest/firewallgroup/%s", c.baseURLV1, id), nil, nil)
}

// ListPolicies fetches all Zone-Based Firewall policies.
func (c *Client) ListPolicies(ctx context.Context) ([]FirewallZonePolicy, error) {
	var policies []FirewallZonePolicy
	err := c.request(ctx, http.MethodGet, c.baseURLV2+"/firewall-policies", nil, &policies)
	return policies, err
}

// CreatePolicy creates a new Zone-Based Firewall policy.
func (c *Client) CreatePolicy(ctx context.Context, p *FirewallZonePolicy) (*FirewallZonePolicy, error) {
	var created FirewallZonePolicy
	err := c.request(ctx, http.MethodPost, c.baseURLV2+"/firewall-policies", p, &created)
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdatePolicy updates an existing Zone-Based Firewall policy by ID.
func (c *Client) UpdatePolicy(ctx context.Context, id string, p *FirewallZonePolicy) error {
	return c.request(ctx, http.MethodPut, fmt.Sprintf("%s/firewall-policies/%s", c.baseURLV2, id), p, nil)
}

// DeletePolicy deletes a firewall policy by ID.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, fmt.Sprintf("%s/firewall-policies/%s", c.baseURLV2, id), nil, nil)
}

// BatchReorder reorders policies for a given source and destination zone pair.
func (c *Client) BatchReorder(ctx context.Context, req *BatchReorderRequest) error {
	return c.request(ctx, http.MethodPut, c.baseURLV2+"/firewall-policies/batch-reorder", req, nil)
}
