package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hononeko/cs-edl-bouncer/pkg/version"
)

// Decision represents a single decision returned by the CrowdSec LAPI stream.
type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// StreamResponse represents the JSON response structure from /v1/decisions/stream.
type StreamResponse struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

// Client interacts with the CrowdSec Local API (LAPI).
type Client struct {
	baseURL    string
	apiKey     string
	origins    []string
	httpClient *http.Client
}

// NewClient creates a new CrowdSec LAPI client.
func NewClient(baseURL, apiKey string, origins []string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		origins:    origins,
		httpClient: httpClient,
	}
}

// GetStream fetches decisions from /v1/decisions/stream.
func (c *Client) GetStream(ctx context.Context, startup bool) (*StreamResponse, error) {
	parsedURL, err := url.Parse(c.baseURL + "/v1/decisions/stream")
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	q := parsedURL.Query()
	q.Set("startup", strconv.FormatBool(startup))
	q.Set("scopes", "ip,range")
	if len(c.origins) > 0 {
		q.Set("origins", strings.Join(c.origins, ","))
	}
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create stream request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "cs-edl-bouncer/"+version.Version)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute stream request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("crowdsec stream returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var streamResp StreamResponse
	if err := json.NewDecoder(resp.Body).Decode(&streamResp); err != nil {
		return nil, fmt.Errorf("decode decisions stream JSON: %w", err)
	}

	return &streamResp, nil
}
