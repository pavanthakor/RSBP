package enrichment

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

//go:embed data/tor_exit_nodes.txt
var embeddedTorExitNodes string

type GeoResult struct {
	Country     string
	CountryCode string
	City        string
	ASN         uint32
	ASNOrg      string
	IsVPN       bool
	IsTor       bool
	IsHosting   bool
}

type GeoIPEnricher struct {
	cityDB     *geoip2.Reader
	asnDB      *geoip2.Reader
	httpClient *http.Client
	rateLimit  <-chan time.Time
	torExitSet map[string]struct{}
	logger     *zap.Logger
}

var knownVPNASNs = map[uint32]struct{}{
	13335: {},
	16509: {},
	14061: {},
	9009:  {},
	16276: {},
	20473: {},
	24940: {},
}

var knownHostingASNs = map[uint32]struct{}{
	8075:  {},
	14618: {},
	15169: {},
	16509: {},
	16276: {},
	63949: {},
	45102: {},
}

func NewGeoIPEnricher(cityPath, asnPath string, logger *zap.Logger) *GeoIPEnricher {
	if logger == nil {
		logger = zap.NewNop()
	}

	g := &GeoIPEnricher{
		httpClient: &http.Client{Timeout: 900 * time.Millisecond},
		rateLimit:  time.Tick(time.Minute / 45),
		torExitSet: make(map[string]struct{}),
		logger:     logger,
	}

	if cityPath != "" {
		if st, err := os.Stat(cityPath); err == nil && !st.IsDir() {
			if db, openErr := geoip2.Open(cityPath); openErr == nil {
				g.cityDB = db
			}
		}
	}

	if asnPath != "" {
		if st, err := os.Stat(asnPath); err == nil && !st.IsDir() {
			if db, openErr := geoip2.Open(asnPath); openErr == nil {
				g.asnDB = db
			}
		}
	}

	for _, line := range strings.Split(embeddedTorExitNodes, "\n") {
		ip := strings.TrimSpace(line)
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		g.torExitSet[ip] = struct{}{}
	}

	return g
}

func (g *GeoIPEnricher) Lookup(ctx context.Context, ip net.IP) (*GeoResult, error) {
	if ip == nil {
		return &GeoResult{}, fmt.Errorf("nil ip")
	}

	result := &GeoResult{}
	if g.cityDB != nil || g.asnDB != nil {
		if g.cityDB != nil {
			city, err := g.cityDB.City(ip)
			if err == nil && city != nil {
				result.Country = city.Country.Names["en"]
				result.CountryCode = city.Country.IsoCode
				result.City = city.City.Names["en"]
			}
		}

		if g.asnDB != nil {
			asn, err := g.asnDB.ASN(ip)
			if err == nil && asn != nil {
				result.ASN = uint32(asn.AutonomousSystemNumber)
				result.ASNOrg = asn.AutonomousSystemOrganization
			}
		}
	} else {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-g.rateLimit:
		}

		fallback, err := g.lookupViaIPAPI(ctx, ip)
		if err != nil {
			return result, err
		}
		result = fallback
	}

	if _, ok := knownVPNASNs[result.ASN]; ok {
		result.IsVPN = true
	}
	if _, ok := knownHostingASNs[result.ASN]; ok {
		result.IsHosting = true
	}
	if _, ok := g.torExitSet[ip.String()]; ok {
		result.IsTor = true
	}

	return result, nil
}

func (g *GeoIPEnricher) lookupViaIPAPI(ctx context.Context, ip net.IP) (*GeoResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipapi.co/"+ip.String()+"/json/", nil)
	if err != nil {
		return nil, err
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ipapi returned status %d", resp.StatusCode)
	}

	var payload struct {
		CountryName string `json:"country_name"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		ASN         string `json:"asn"`
		Org         string `json:"org"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	result := &GeoResult{
		Country:     payload.CountryName,
		CountryCode: payload.CountryCode,
		City:        payload.City,
		ASNOrg:      payload.Org,
	}
	if strings.HasPrefix(payload.ASN, "AS") {
		if n, convErr := strconv.ParseUint(strings.TrimPrefix(payload.ASN, "AS"), 10, 32); convErr == nil {
			result.ASN = uint32(n)
		}
	}

	return result, nil
}
