package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type ReputationResult struct {
	ReputationScore      int
	AbuseConfidenceScore int
	ThreatCategories     []string
	DomainAgeDays        int
	IsNewlyRegistered    bool
}

type offlineAbuseEntry struct {
	AbuseConfidenceScore int   `json:"abuseConfidenceScore"`
	Categories           []int `json:"categories"`
	DomainAgeDays        int   `json:"domainAgeDays"`
}

type ReputationEnricher struct {
	offlineData map[string]offlineAbuseEntry
	apiKey      string
	endpoint    string
	online      bool
	client      *http.Client
	cache       map[string]*ReputationResult
	mu          sync.RWMutex
	logger      *zap.Logger
}

var abuseCategoryNames = map[int]string{
	3:  "Fraud Orders",
	4:  "DDoS Attack",
	5:  "FTP Brute-Force",
	9:  "Open Proxy",
	10: "Web Spam",
	11: "Email Spam",
	14: "Port Scan",
	15: "Hacking",
	16: "SQL Injection",
	18: "Brute-Force",
	19: "Bad Web Bot",
	20: "DDoS",
	21: "Web App Attack",
	22: "SSH",
	23: "IoT Targeted",
}

var knownBadCIDRs = []string{
	"45.9.148.0/24",
	"91.240.118.0/24",
	"185.220.101.0/24",
	"194.26.192.0/24",
	"198.98.51.0/24",
}

func NewReputationEnricher(cachePath, apiKey, endpoint string, online bool, logger *zap.Logger) *ReputationEnricher {
	if logger == nil {
		logger = zap.NewNop()
	}
	if endpoint == "" {
		endpoint = "https://api.abuseipdb.com/api/v2/check"
	}

	r := &ReputationEnricher{
		offlineData: make(map[string]offlineAbuseEntry),
		apiKey:      apiKey,
		endpoint:    endpoint,
		online:      online && apiKey != "",
		client:      &http.Client{Timeout: 1 * time.Second},
		cache:       make(map[string]*ReputationResult),
		logger:      logger,
	}

	if cachePath != "" {
		data, err := os.ReadFile(cachePath)
		if err == nil {
			_ = json.Unmarshal(data, &r.offlineData)
		}
	}

	return r
}

func (r *ReputationEnricher) Lookup(ctx context.Context, ip net.IP) (*ReputationResult, error) {
	if ip == nil {
		return &ReputationResult{}, fmt.Errorf("nil ip")
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return &ReputationResult{}, nil
	}

	key := ip.String()
	r.mu.RLock()
	if cached, ok := r.cache[key]; ok && cached != nil {
		clone := *cached
		r.mu.RUnlock()
		return &clone, nil
	}
	r.mu.RUnlock()

	out := &ReputationResult{}

	if r.isKnownBadNetwork(ip) {
		out.ReputationScore = 85
		out.AbuseConfidenceScore = 85
		out.ThreatCategories = []string{"Known Bad Network"}
	}

	if entry, ok := r.offlineData[key]; ok {
		out.AbuseConfidenceScore = maxInt(out.AbuseConfidenceScore, entry.AbuseConfidenceScore)
		out.ReputationScore = maxInt(out.ReputationScore, entry.AbuseConfidenceScore)
		out.DomainAgeDays = entry.DomainAgeDays
		out.IsNewlyRegistered = entry.DomainAgeDays > 0 && entry.DomainAgeDays < 30
		for _, id := range entry.Categories {
			if c, exists := abuseCategoryNames[id]; exists {
				out.ThreatCategories = append(out.ThreatCategories, c)
			}
		}
	}

	if r.online {
		onlineRes, err := r.lookupOnline(ctx, key)
		if err == nil && onlineRes != nil {
			if onlineRes.AbuseConfidenceScore > out.AbuseConfidenceScore {
				out.AbuseConfidenceScore = onlineRes.AbuseConfidenceScore
			}
			if onlineRes.ReputationScore > out.ReputationScore {
				out.ReputationScore = onlineRes.ReputationScore
			}
			if onlineRes.DomainAgeDays > 0 {
				out.DomainAgeDays = onlineRes.DomainAgeDays
				out.IsNewlyRegistered = onlineRes.IsNewlyRegistered
			}
			out.ThreatCategories = append(out.ThreatCategories, onlineRes.ThreatCategories...)
		}
	}

	out.ThreatCategories = uniqueStrings(out.ThreatCategories)

	r.mu.Lock()
	clone := *out
	r.cache[key] = &clone
	r.mu.Unlock()

	return out, nil
}

func (r *ReputationEnricher) lookupOnline(ctx context.Context, ip string) (*ReputationResult, error) {
	q := make(url.Values)
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-RapidAPI-Key", r.apiKey)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("abuseipdb status %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			DomainAge            int `json:"domainAge"`
			Reports              []struct {
				Categories []int `json:"categories"`
			} `json:"reports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	out := &ReputationResult{
		ReputationScore:      payload.Data.AbuseConfidenceScore,
		AbuseConfidenceScore: payload.Data.AbuseConfidenceScore,
		DomainAgeDays:        payload.Data.DomainAge,
		IsNewlyRegistered:    payload.Data.DomainAge > 0 && payload.Data.DomainAge < 30,
	}

	for _, report := range payload.Data.Reports {
		for _, c := range report.Categories {
			if name, ok := abuseCategoryNames[c]; ok {
				out.ThreatCategories = append(out.ThreatCategories, name)
			}
		}
	}
	out.ThreatCategories = uniqueStrings(out.ThreatCategories)
	return out, nil
}

func (r *ReputationEnricher) isKnownBadNetwork(ip net.IP) bool {
	for _, cidr := range knownBadCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
