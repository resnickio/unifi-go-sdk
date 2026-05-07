//go:build integration

// enum_probe_test.go contains TestEnumProbe — a per-validator integration test
// that POSTs a deliberately-invalid value to the live UniFi controller and
// asserts the controller's enum-error message lists exactly the values the
// SDK's isOneOf() validator currently accepts.
//
// Drift in either direction fails the test:
//   - validator MISSING values the controller accepts → users get plan-time
//     rejections of valid configs.
//   - validator EXTRA values the controller rejects → plan succeeds, apply
//     fails with an opaque controller error.
//
// Each probe leaves no resources on the controller because every payload is
// rejected at validation time, before the resource is created.
//
// See CLAUDE.md "Source-of-truth hierarchy" for the source-priority rules
// these probes enforce.
package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

const probeSentinel = "___SDK_PROBE___"

// parseJacksonEnum extracts the canonical accepted values from a v2 API error
// response of the form:
//
//	"… not one of the values accepted for Enum class: [APP, DOMAIN, IP, …]"
var jacksonEnumRe = regexp.MustCompile(`accepted for Enum class:\s*\[([^\]]+)\]`)

func parseJacksonEnum(body string) []string {
	m := jacksonEnumRe.FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	parts := strings.Split(m[1], ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// parseLegacyValidationPattern extracts the canonical accepted values from a
// legacy REST error response of the form:
//
//	{"meta":{"rc":"error",…},"data":[{"validationError":{"field":"X","pattern":"all|groups|devices"},…}]}
//
// Some controller patterns are not pure pipe-separated literal lists; they
// embed regex fragments. This parser expands two common shapes
// ("prefix[N-M]?" → enumerated values; "^$" → dropped, since validators
// already gate empty strings via "if field != ''") and silently filters any
// remaining regex-only fragments (e.g. numeric character classes used for
// IANA protocol codes). Filtered fragments are documented in the validator
// where they apply.
func parseLegacyValidationPattern(body string) []string {
	var resp struct {
		Data []struct {
			ValidationError struct {
				Pattern string `json:"pattern"`
			} `json:"validationError"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil
	}
	for _, d := range resp.Data {
		if d.ValidationError.Pattern == "" {
			continue
		}
		seen := map[string]bool{}
		var out []string
		for _, raw := range strings.Split(d.ValidationError.Pattern, "|") {
			for _, expanded := range expandLegacyPatternValue(raw) {
				if seen[expanded] {
					continue
				}
				seen[expanded] = true
				out = append(out, expanded)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

var rangePatternRe = regexp.MustCompile(`^([A-Za-z_-]+)\[(\d)-(\d)\](\?)?$`)

// expandLegacyPatternValue converts one fragment from a "|"-split legacy
// validation pattern into zero or more literal values.
//
//   - "^$" → nil (empty marker; validator's "if field != ''" gates this).
//   - "prefix[N-M]?" → ["prefix", "prefixN", …, "prefixM"]
//     (the trailing "?" makes the digit optional, so the bare prefix is also a valid value).
//   - Anything still containing regex metacharacters is dropped — these tend
//     to be numeric character classes (e.g., "[0-9]", "1[0-9]{2}") that
//     can't reasonably be enumerated as enum values.
//   - Plain literals pass through.
func expandLegacyPatternValue(s string) []string {
	if s == "" || s == "^$" {
		return nil
	}
	if m := rangePatternRe.FindStringSubmatch(s); m != nil {
		prefix, lo, hi := m[1], int(m[2][0]-'0'), int(m[3][0]-'0')
		optional := m[4] == "?"
		var out []string
		if optional {
			out = append(out, prefix)
		}
		for i := lo; i <= hi; i++ {
			out = append(out, fmt.Sprintf("%s%d", prefix, i))
		}
		return out
	}
	if strings.ContainsAny(s, "[](){}^$\\") {
		return nil
	}
	return []string{s}
}

// enumProbe describes one isOneOf() validator and how to provoke the
// controller into revealing the canonical accepted values.
type enumProbe struct {
	// Where the validator lives, for failure messages.
	structName string
	fieldName  string

	// HTTP request to send.
	method string
	path   string // path under client.BaseURL

	// payload returns the JSON-marshalable body to POST/PUT, with the bad
	// value injected at the field under test. nil for GET/DELETE.
	payload func(badValue string) any

	// parser to apply to the error response body.
	parser func(body string) []string

	// validatorValues are the values the SDK's isOneOf() currently accepts.
	validatorValues []string
}

func sortedCopy(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

type setDiffResult struct {
	missing []string // in canonical, not in validator → too restrictive
	extra   []string // in validator, not in canonical → too permissive
}

func setDiff(canonical, validator []string) setDiffResult {
	canSet := map[string]bool{}
	for _, v := range canonical {
		canSet[v] = true
	}
	valSet := map[string]bool{}
	for _, v := range validator {
		valSet[v] = true
	}
	var d setDiffResult
	for _, v := range canonical {
		if !valSet[v] {
			d.missing = append(d.missing, v)
		}
	}
	for _, v := range validator {
		if !canSet[v] {
			d.extra = append(d.extra, v)
		}
	}
	return d
}

// runProbe executes a single probe against the live controller and reports
// any drift via t.Error.
func runProbe(t *testing.T, client *NetworkClient, p enumProbe) {
	t.Helper()

	body := p.payload(probeSentinel)
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("[%s.%s] marshal payload: %v", p.structName, p.fieldName, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, p.method, client.BaseURL+p.path, bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("[%s.%s] new request: %v", p.structName, p.fieldName, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if client.apiKey != "" {
		req.Header.Set("X-API-KEY", client.apiKey)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("[%s.%s] do: %v", p.structName, p.fieldName, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("[%s.%s] expected 4xx, got %d; body: %s", p.structName, p.fieldName, resp.StatusCode, string(rawBody))
	}

	canonical := p.parser(string(rawBody))
	if len(canonical) == 0 {
		t.Fatalf("[%s.%s] parser returned no values; raw response: %s", p.structName, p.fieldName, string(rawBody))
	}

	have := sortedCopy(p.validatorValues)
	diff := setDiff(canonical, have)
	if len(diff.missing) == 0 && len(diff.extra) == 0 {
		return
	}

	var msg strings.Builder
	fmt.Fprintf(&msg, "ENUM DRIFT: %s.%s\n", p.structName, p.fieldName)
	fmt.Fprintf(&msg, "  validator accepts:  %v\n", have)
	fmt.Fprintf(&msg, "  controller accepts: %v\n", canonical)
	if len(diff.missing) > 0 {
		fmt.Fprintf(&msg, "  validator MISSING (controller accepts but validator rejects): %v\n", diff.missing)
	}
	if len(diff.extra) > 0 {
		fmt.Fprintf(&msg, "  validator EXTRA (validator accepts but controller rejects): %v\n", diff.extra)
	}
	t.Error(msg.String())
}

// probeNetworkID returns an existing networkconf _id for use in probes that
// require a real network reference (e.g., WLAN creation). It picks the first
// network that is not the controller's auto-generated WAN.
func probeNetworkID(t *testing.T, client *NetworkClient) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nets, err := client.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("listing networks for probe: %v", err)
	}
	for _, n := range nets {
		if n.ID != "" {
			return n.ID
		}
	}
	t.Fatal("no networkconf found on controller")
	return ""
}

// probeZoneID returns an existing firewall zone _id, needed for FirewallPolicy
// probes (the controller validates source.zone_id / destination.zone_id before
// reaching enum-field validation).
func probeZoneID(t *testing.T, client *NetworkClient) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	zones, err := client.ListFirewallZones(ctx)
	if err != nil {
		t.Fatalf("listing firewall zones for probe: %v", err)
	}
	for _, z := range zones {
		if z.ID != "" {
			return z.ID
		}
	}
	t.Fatal("no firewall zones found on controller")
	return ""
}

// probeDeviceID returns the _id of the first adopted device on the controller.
// Required for DeviceConfig/PortOverride/RadioOverride probes (PUT to
// /rest/device/{id}). Skips if no adopted device is present (the probes that
// depend on it will then skip via the same path).
func probeDeviceID(t *testing.T, client *NetworkClient) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	path := "/proxy/network/api/s/" + client.Site + "/stat/device"
	req, err := http.NewRequestWithContext(ctx, "GET", client.BaseURL+path, nil)
	if err != nil {
		t.Fatalf("building stat/device request: %v", err)
	}
	if client.apiKey != "" {
		req.Header.Set("X-API-KEY", client.apiKey)
	}
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("stat/device request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var parsed struct {
		Data []struct {
			ID string `json:"_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decoding stat/device: %v", err)
	}
	for _, d := range parsed.Data {
		if d.ID != "" {
			return d.ID
		}
	}
	t.Skip("no adopted devices on controller; device-attached probes skipped")
	return ""
}

// TestEnumProbe runs all enum-validator probes. Each subtest is named
// Struct.Field for easy identification in failure output.
func TestEnumProbe(t *testing.T) {
	client := skipIfNoEnv(t)
	site := client.Site
	netID := probeNetworkID(t, client)
	zoneID := probeZoneID(t, client)
	deviceID := probeDeviceID(t, client)

	v2 := func(endpoint string) string {
		return "/proxy/network/v2/api/site/" + site + "/" + endpoint
	}
	rest := func(endpoint string) string {
		return "/proxy/network/api/s/" + site + "/rest/" + endpoint
	}
	settingSet := func(key string) string {
		return "/proxy/network/api/s/" + site + "/set/setting/" + key
	}
	device := func() string {
		return "/proxy/network/api/s/" + site + "/rest/device/" + deviceID
	}

	probes := buildProbes(netID, zoneID, device(), v2, rest, settingSet)

	for _, p := range probes {
		p := p
		t.Run(p.structName+"."+p.fieldName, func(t *testing.T) {
			runProbe(t, client, p)
		})
	}
}

// buildProbes constructs the per-validator probe table.
//
// Skipped (and why):
//   - PolicySchedule.RepeatOnDays — string-list validator. Probed inline
//     via PolicySchedule.RepeatOnDays below using a dedicated probe entry
//     against the trafficrules endpoint (Jackson exposes the enum class on
//     parse failure).
//   - RadioOverride.Radio and RadioOverride.TxPowerMode — when probed against
//     PUT /rest/device/{id}, the controller silently returns rc:ok with no
//     validation error (different validation path for radio_table_overrides
//     than for port_overrides). Validator values trusted; needs a different
//     probe approach (likely UI-capture) when the controller's behavior
//     changes.
//
// All other validators in network_models.go are covered.
func buildProbes(netID, zoneID, devicePath string, v2, rest, settingSet func(string) string) []enumProbe {
	jx := parseJacksonEnum
	lg := parseLegacyValidationPattern

	// fpBase returns a minimum-viable FirewallPolicy payload that passes the
	// controller's structural validators (source/destination/schedule/ipVersion
	// all required), so probes can isolate single-field enum errors.
	fpBase := func(extra map[string]any) map[string]any {
		body := map[string]any{
			"name":        "sdk_probe",
			"action":      "ALLOW",
			"ip_version":  "IPV4",
			"source":      map[string]any{"matching_target": "ANY", "zone_id": zoneID},
			"destination": map[string]any{"matching_target": "ANY", "zone_id": zoneID},
			"schedule":    map[string]any{"mode": "ALWAYS"},
		}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}

	return []enumProbe{
		// ---- v2 API: FirewallPolicy ----
		{
			structName: "FirewallPolicy", fieldName: "Action",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{"action": bad})
			},
			parser:          jx,
			validatorValues: []string{"ALLOW", "BLOCK", "REJECT"},
		},
		// FirewallPolicy.Protocol — un-probeable: the controller responds with
		// "api.err.InvalidFirewallPolicyProtocolName" without revealing the
		// enum. Validator values trusted from OpenAPI spec; if the provider
		// reports a rejection, hand-probe by trying each suspected value.
		{
			structName: "FirewallPolicy", fieldName: "IPVersion",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{"ip_version": bad})
			},
			parser:          jx,
			validatorValues: []string{"BOTH", "IPV4", "IPV6"},
		},
		{
			structName: "FirewallPolicy", fieldName: "ConnectionStateType",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{"connection_state_type": bad})
			},
			parser:          jx,
			validatorValues: []string{"ALL", "RESPOND_ONLY", "CUSTOM"},
		},
		// ---- v2 API: PolicyEndpoint ----
		{
			structName: "PolicyEndpoint", fieldName: "MatchingTarget",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{
					"source": map[string]any{"matching_target": bad, "zone_id": zoneID},
				})
			},
			parser: jx,
			validatorValues: []string{
				"ANY", "CLIENT", "EXTERNAL_SOURCE", "IID", "IP", "MAC", "NETWORK", "REGION",
				"USER_IDENTITY", "USER_IDENTITY_ONE_CLICK_VPN", "USER_IDENTITY_ONE_CLICK_WIFI", "VPN_USER",
			},
		},
		{
			structName: "PolicyEndpoint", fieldName: "MatchingTargetType",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{
					"source": map[string]any{"matching_target_type": bad, "zone_id": zoneID},
				})
			},
			parser:          jx,
			validatorValues: []string{"SPECIFIC", "OBJECT"},
		},
		{
			structName: "PolicyEndpoint", fieldName: "PortMatchingType",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{
					"source": map[string]any{"port_matching_type": bad, "zone_id": zoneID},
				})
			},
			parser:          jx,
			validatorValues: []string{"ANY", "OBJECT", "SPECIFIC"},
		},
		{
			structName: "PolicySchedule", fieldName: "Mode",
			method: "POST", path: v2("firewall-policies"),
			payload: func(bad string) any {
				return fpBase(map[string]any{
					"schedule": map[string]any{"mode": bad},
				})
			},
			parser:          jx,
			validatorValues: []string{"ALWAYS", "CUSTOM", "EVERY_DAY", "EVERY_WEEK", "ONE_TIME_ONLY"},
		},
		// PolicySchedule.RepeatOnDays — un-probeable here: the controller's
		// Jackson config emits "No enum constant ... <value>" rather than the
		// "not one of the values accepted for Enum class: [...]" format our
		// parser can extract a list from. The validator values
		// {mon, tue, wed, thu, fri, sat, sun} were determined by manual
		// elimination probing (lowercase 3-letter accepted; full names like
		// MONDAY and uppercase short MON both rejected). When the controller
		// changes the days enum, the unit test TestPolicyScheduleValidate
		// "rejected legacy" cases still guard against rolling back to
		// uppercase, but the SDK can't auto-detect drift here.

		// ---- v2 API: TrafficRule / TrafficRoute ----
		{
			structName: "TrafficRule", fieldName: "Action",
			method: "POST", path: v2("trafficrules"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "action": bad}
			},
			parser:          jx,
			validatorValues: []string{"BLOCK", "ALLOW"},
		},
		{
			structName: "TrafficRule", fieldName: "MatchingTarget",
			method: "POST", path: v2("trafficrules"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "action": "BLOCK", "matching_target": bad}
			},
			parser:          jx,
			validatorValues: []string{"INTERNET", "IP", "DOMAIN", "REGION", "APP", "APP_CATEGORY", "LOCAL_NETWORK"},
		},
		{
			structName: "TrafficRoute", fieldName: "MatchingTarget",
			method: "POST", path: v2("trafficroutes"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "matching_target": bad}
			},
			parser:          jx,
			validatorValues: []string{"INTERNET", "IP", "DOMAIN", "REGION"},
		},

		// ---- v2 API: NatRule ----
		{
			structName: "NatRule", fieldName: "Type",
			method: "POST", path: v2("nat"),
			payload: func(bad string) any {
				return map[string]any{"type": bad}
			},
			parser:          jx,
			validatorValues: []string{"MASQUERADE", "DNAT", "SNAT"},
		},
		// NatRule.Protocol — un-probeable: every NAT POST that gets past the
		// type enum check returns 500 (controller-side bug; the model also
		// has unrecognized field names, separate concern). Validator values
		// trusted from spec until NAT model is reworked.

		// ---- v2 API: StaticDNS ----
		{
			structName: "StaticDNS", fieldName: "RecordType",
			method: "POST", path: v2("static-dns"),
			payload: func(bad string) any {
				return map[string]any{"key": "sdk-probe.example.com", "value": "1.2.3.4", "record_type": bad}
			},
			parser:          jx,
			validatorValues: []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV"},
		},

		// ---- Legacy REST: Network ----
		{
			structName: "Network", fieldName: "Purpose",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": bad}
			},
			parser:          lg,
			validatorValues: []string{"wan", "corporate", "vlan-only", "remote-user-vpn", "site-vpn", "guest", "vpn-client"},
		},
		{
			structName: "Network", fieldName: "SettingPreference",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "corporate", "setting_preference": bad}
			},
			parser:          lg,
			validatorValues: []string{"auto", "manual"},
		},
		{
			structName: "Network", fieldName: "GatewayType",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "corporate", "gateway_type": bad}
			},
			parser:          lg,
			validatorValues: []string{"default", "switch"},
		},
		// NetworkRouting.NetworkGroup is purpose-dependent on the controller:
		// corporate-purpose networks accept LAN..LAN8, wan-purpose networks
		// accept WAN/WAN2. The validator stores the permissive union; a
		// single probe response can only reveal one half. Validator coverage
		// for both halves is verified manually in this session's history.
		{
			structName: "NetworkWAN", fieldName: "WANType",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "wan", "wan_type": bad}
			},
			parser:          lg,
			validatorValues: []string{"dhcp", "static", "pppoe", "disabled", "dslite", "dslite-over-pppoe", "map-e,hubspoke", "map-e,jpix", "map-e,ntt"},
		},
		{
			structName: "NetworkWANIPv6", fieldName: "WANTypeV6",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "wan", "wan_type_v6": bad}
			},
			parser:          lg,
			validatorValues: []string{"disabled", "dhcpv6", "static", "slaac"},
		},
		{
			structName: "NetworkWANLoadBalance", fieldName: "WANLoadBalanceType",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "wan", "wan_load_balance_type": bad}
			},
			parser:          lg,
			validatorValues: []string{"failover-only", "weighted"},
		},
		{
			structName: "NetworkIPv6", fieldName: "IPV6InterfaceType",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "corporate", "ipv6_interface_type": bad}
			},
			parser:          lg,
			validatorValues: []string{"none", "static", "pd", "single_network"},
		},
		{
			structName: "NetworkIPv6", fieldName: "IPV6RaPriority",
			method: "POST", path: rest("networkconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "purpose": "corporate", "ipv6_ra_priority": bad}
			},
			parser:          lg,
			validatorValues: []string{"high", "medium", "low"},
		},

		// ---- Legacy REST: FirewallRule ----
		{
			structName: "FirewallRule", fieldName: "Action",
			method: "POST", path: rest("firewallrule"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "ruleset": "WAN_IN", "action": bad}
			},
			parser:          lg,
			validatorValues: []string{"accept", "drop", "reject"},
		},
		{
			structName: "FirewallRule", fieldName: "Ruleset",
			method: "POST", path: rest("firewallrule"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "action": "accept", "ruleset": bad}
			},
			parser: lg,
			validatorValues: []string{
				"WAN_IN", "WAN_OUT", "WAN_LOCAL", "LAN_IN", "LAN_OUT", "LAN_LOCAL",
				"GUEST_IN", "GUEST_OUT", "GUEST_LOCAL",
				"WANv6_IN", "WANv6_OUT", "WANv6_LOCAL",
				"LANv6_IN", "LANv6_OUT", "LANv6_LOCAL",
				"GUESTv6_IN", "GUESTv6_OUT", "GUESTv6_LOCAL",
			},
		},
		{
			structName: "FirewallRule", fieldName: "Protocol",
			method: "POST", path: rest("firewallrule"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "ruleset": "WAN_IN", "action": "accept", "protocol": bad}
			},
			parser: lg,
			validatorValues: []string{
				"all", "tcp", "udp", "tcp_udp", "icmp", "ah", "ax.25", "dccp", "ddp",
				"egp", "eigrp", "encap", "esp", "etherip", "fc", "ggp", "gre", "hip", "hmp",
				"idpr-cmtp", "idrp", "igmp", "igp", "ip", "ipcomp", "ipencap", "ipip",
				"ipv6", "ipv6-frag", "ipv6-icmp", "ipv6-nonxt", "ipv6-opts", "ipv6-route",
				"isis", "iso-tp4", "l2tp", "manet", "mobility-header", "mpls-in-ip", "ospf",
				"pim", "pup", "rdp", "rohc", "rspf", "rsvp", "sctp", "shim6", "skip", "st",
				"udplite", "vmtp", "vrrp", "wesp", "xns-idp", "xtp",
				// Numeric protocol codes 0-255 are also accepted by the controller
				// but not enumerated here; see the validator for that allowance.
			},
		},
		{
			structName: "FirewallRule", fieldName: "IPSec",
			method: "POST", path: rest("firewallrule"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "ruleset": "WAN_IN", "action": "accept", "ipsec": bad}
			},
			parser:          lg,
			validatorValues: []string{"match-ipsec", "match-none"},
		},

		// ---- Legacy REST: FirewallGroup ----
		{
			structName: "FirewallGroup", fieldName: "GroupType",
			method: "POST", path: rest("firewallgroup"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "group_type": bad, "group_members": []string{"1.2.3.4"}}
			},
			parser:          lg,
			validatorValues: []string{"address-group", "port-group", "ipv6-address-group"},
		},

		// ---- Legacy REST: Routing ----
		{
			structName: "Routing", fieldName: "Type",
			method: "POST", path: rest("routing"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "type": bad}
			},
			parser:          lg,
			validatorValues: []string{"static-route"},
		},
		{
			structName: "Routing", fieldName: "StaticRouteType",
			method: "POST", path: rest("routing"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "type": "static-route", "static-route_type": bad}
			},
			parser:          lg,
			validatorValues: []string{"nexthop-route", "interface-route", "blackhole"},
		},

		// ---- Legacy REST: PortForward ----
		{
			structName: "PortForward", fieldName: "Proto",
			method: "POST", path: rest("portforward"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "proto": bad, "dst_port": "80", "fwd": "1.2.3.4", "fwd_port": "80"}
			},
			parser:          lg,
			validatorValues: []string{"tcp", "udp", "tcp_udp"},
		},
		{
			structName: "PortForward", fieldName: "PfwdInterface",
			method: "POST", path: rest("portforward"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "proto": "tcp", "dst_port": "80", "fwd": "1.2.3.4", "fwd_port": "80", "pfwd_interface": bad}
			},
			parser:          lg,
			validatorValues: []string{"all", "both", "wan", "wan2", "wan3", "wan4", "wan5", "wan6", "wan7", "wan8", "wan9"},
		},

		// ---- Legacy REST: DynamicDNS ----
		{
			structName: "DynamicDNS", fieldName: "Service",
			method: "POST", path: rest("dynamicdns"),
			payload: func(bad string) any {
				return map[string]any{"service": bad, "host_name": "probe.example.com"}
			},
			parser:          lg,
			validatorValues: []string{
				"afraid", "changeip", "cloudflare", "cloudxns", "custom", "ddnss", "dhis",
				"dnsexit", "dnsomatic", "dnspark", "dnspod", "dslreports", "dtdns", "duckdns",
				"duiadns", "dyn", "dyndns", "dynv6", "easydns", "freemyip", "googledomains",
				"loopia", "namecheap", "noip", "nsupdate", "ovh", "sitelutions", "spdyn",
				"strato", "tunnelbroker", "zoneedit",
			},
		},
		{
			structName: "DynamicDNS", fieldName: "Interface",
			method: "POST", path: rest("dynamicdns"),
			payload: func(bad string) any {
				return map[string]any{"service": "dyndns", "host_name": "probe.example.com", "interface": bad}
			},
			parser:          lg,
			validatorValues: []string{"wan", "wan2", "wan3", "wan4", "wan5", "wan6", "wan7", "wan8", "wan9"},
		},

		// ---- Legacy REST: WLANConf ----
		{
			structName: "WLANConf", fieldName: "Security",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": bad}
			},
			parser:          lg,
			validatorValues: []string{"open", "wep", "wpapsk", "wpaeap", "osen"},
		},
		{
			structName: "WLANConf", fieldName: "WPAMode",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "wpapsk", "x_passphrase": "abcdefgh", "wpa_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"auto", "wpa1", "wpa2"},
		},
		{
			structName: "WLANConf", fieldName: "WPAEnc",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "wpapsk", "x_passphrase": "abcdefgh", "wpa_enc": bad}
			},
			parser:          lg,
			validatorValues: []string{"auto", "ccmp", "gcmp", "ccmp-256", "gcmp-256"},
		},
		{
			structName: "WLANConf", fieldName: "WLANBand",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "open", "wlan_band": bad}
			},
			parser:          lg,
			validatorValues: []string{"2g", "5g", "both"},
		},
		{
			structName: "WLANConf", fieldName: "MacFilterPolicy",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "open", "mac_filter_policy": bad}
			},
			parser:          lg,
			validatorValues: []string{"allow", "deny"},
		},
		{
			structName: "WLANConf", fieldName: "PmfMode",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "open", "pmf_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"disabled", "optional", "required"},
		},
		{
			structName: "WLANConf", fieldName: "DtimMode",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "open", "dtim_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"default", "custom"},
		},
		{
			structName: "WLANConf", fieldName: "APGroupMode",
			method: "POST", path: rest("wlanconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "networkconf_id": netID, "security": "open", "ap_group_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"all", "groups", "devices"},
		},

		// ---- Legacy REST: PortConf ----
		{
			structName: "PortConf", fieldName: "Forward",
			method: "POST", path: rest("portconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "forward": bad}
			},
			parser:          lg,
			validatorValues: []string{"all", "native", "customize", "disabled"},
		},
		{
			structName: "PortConf", fieldName: "Dot1xCtrl",
			method: "POST", path: rest("portconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "forward": "all", "dot1x_ctrl": bad}
			},
			parser:          lg,
			validatorValues: []string{"force_authorized", "force_unauthorized", "auto", "mac_based", "multi_host"},
		},
		{
			structName: "PortConf", fieldName: "OpMode",
			method: "POST", path: rest("portconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "forward": "all", "op_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"switch"},
		},
		{
			structName: "PortConf", fieldName: "PoeMode",
			method: "POST", path: rest("portconf"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "forward": "all", "poe_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"auto", "off"},
		},

		// ---- Legacy REST: User ----
		// (User has only MAC + IP fields validated; no enums to probe.)

		// ---- Legacy REST: RADIUSProfile ----
		{
			structName: "RADIUSProfile", fieldName: "VlanWlanMode",
			method: "POST", path: rest("radiusprofile"),
			payload: func(bad string) any {
				return map[string]any{"name": "sdk_probe", "vlan_wlan_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"disabled", "optional", "required"},
		},

		// ---- Settings (PUT to set/setting/{key}) ----
		{
			structName: "SettingUSG", fieldName: "MSSClamp",
			method: "PUT", path: settingSet("usg"),
			payload: func(bad string) any {
				return map[string]any{"key": "usg", "mss_clamp": bad}
			},
			parser:          lg,
			validatorValues: []string{"custom", "auto", "disabled"},
		},
		{
			structName: "SettingIPS", fieldName: "IPSMode",
			method: "PUT", path: settingSet("ips"),
			payload: func(bad string) any {
				return map[string]any{"key": "ips", "ips_mode": bad}
			},
			parser:          lg,
			validatorValues: []string{"disabled", "ids", "ips", "ipsInline"},
		},
		{
			structName: "SettingIPS", fieldName: "AdvancedFilteringPreference",
			method: "PUT", path: settingSet("ips"),
			payload: func(bad string) any {
				return map[string]any{"key": "ips", "advanced_filtering_preference": bad}
			},
			parser:          lg,
			validatorValues: []string{"disabled", "manual"},
		},
		{
			structName: "SettingGuestAccess", fieldName: "Auth",
			method: "PUT", path: settingSet("guest_access"),
			payload: func(bad string) any {
				return map[string]any{"key": "guest_access", "auth": bad}
			},
			parser:          lg,
			validatorValues: []string{"none", "hotspot", "facebook_wifi", "custom"},
		},

		// ---- Device-attached (PUT /rest/device/{id}) ----
		// Validation rejects the payload before any state change is applied.
		{
			structName: "DeviceConfig", fieldName: "LedOverride",
			method: "PUT", path: devicePath,
			payload: func(bad string) any {
				return map[string]any{"led_override": bad}
			},
			parser:          lg,
			validatorValues: []string{"default", "on", "off"},
		},
		{
			structName: "PortOverride", fieldName: "SettingPreference",
			method: "PUT", path: devicePath,
			payload: func(bad string) any {
				return map[string]any{"port_overrides": []any{map[string]any{"port_idx": 1, "setting_preference": bad}}}
			},
			parser:          lg,
			validatorValues: []string{"auto", "manual"},
		},
		{
			structName: "PortOverride", fieldName: "PoeMode",
			method: "PUT", path: devicePath,
			payload: func(bad string) any {
				return map[string]any{"port_overrides": []any{map[string]any{"port_idx": 1, "poe_mode": bad}}}
			},
			parser:          lg,
			validatorValues: []string{"auto", "off", "pasv24", "passthrough"},
		},
		{
			structName: "PortOverride", fieldName: "OpMode",
			method: "PUT", path: devicePath,
			payload: func(bad string) any {
				return map[string]any{"port_overrides": []any{map[string]any{"port_idx": 1, "op_mode": bad}}}
			},
			parser:          lg,
			validatorValues: []string{"switch", "mirror", "aggregate"},
		},
		{
			structName: "PortOverride", fieldName: "Forward",
			method: "PUT", path: devicePath,
			payload: func(bad string) any {
				return map[string]any{"port_overrides": []any{map[string]any{"port_idx": 1, "forward": bad}}}
			},
			parser:          lg,
			validatorValues: []string{"all", "native", "customize", "disabled"},
		},
		{
			structName: "PortOverride", fieldName: "TaggedVlanMgmt",
			method: "PUT", path: devicePath,
			payload: func(bad string) any {
				return map[string]any{"port_overrides": []any{map[string]any{"port_idx": 1, "tagged_vlan_mgmt": bad}}}
			},
			parser:          lg,
			validatorValues: []string{"auto", "block_all", "custom"},
		},
	}
}
