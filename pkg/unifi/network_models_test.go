package unifi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUserGroupValidate(t *testing.T) {
	tests := []struct {
		name    string
		group   UserGroup
		wantErr string
	}{
		{"valid", UserGroup{Name: "Test"}, ""},
		{"missing name", UserGroup{}, "name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallZoneValidate(t *testing.T) {
	tests := []struct {
		name    string
		zone    FirewallZone
		wantErr string
	}{
		{"valid", FirewallZone{Name: "Test"}, ""},
		{"missing name", FirewallZone{}, "name is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.zone.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallGroupValidate(t *testing.T) {
	tests := []struct {
		name    string
		group   FirewallGroup
		wantErr string
	}{
		{"valid address-group", FirewallGroup{Name: "Test", GroupType: "address-group"}, ""},
		{"valid port-group", FirewallGroup{Name: "Test", GroupType: "port-group"}, ""},
		{"valid ipv6-address-group", FirewallGroup{Name: "Test", GroupType: "ipv6-address-group"}, ""},
		{"missing name", FirewallGroup{GroupType: "address-group"}, "name is required"},
		{"invalid group_type", FirewallGroup{Name: "Test", GroupType: "invalid"}, "group_type must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestRoutingValidate(t *testing.T) {
	tests := []struct {
		name    string
		route   Routing
		wantErr string
	}{
		{"valid", Routing{Name: "Test", Type: "static-route", StaticRouteNetwork: "10.0.0.0/8", StaticRouteNexthop: "192.168.1.1"}, ""},
		{"missing name", Routing{}, "name is required"},
		{"invalid type", Routing{Name: "Test", Type: "invalid"}, "type must be one of"},
		{"invalid static-route_type", Routing{Name: "Test", StaticRouteType: "invalid"}, "static-route_type must be one of"},
		{"invalid static-route_network", Routing{Name: "Test", StaticRouteNetwork: "invalid"}, "must be a valid CIDR"},
		{"invalid static-route_nexthop", Routing{Name: "Test", StaticRouteNexthop: "invalid"}, "must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestDynamicDNSValidate(t *testing.T) {
	tests := []struct {
		name    string
		ddns    DynamicDNS
		wantErr string
	}{
		{"valid", DynamicDNS{Service: "cloudflare", HostName: "example.com"}, ""},
		{"missing service", DynamicDNS{HostName: "example.com"}, "service is required"},
		{"invalid service", DynamicDNS{Service: "invalid", HostName: "example.com"}, "service must be one of"},
		{"missing hostname", DynamicDNS{Service: "cloudflare"}, "host_name is required"},
		{"invalid interface", DynamicDNS{Service: "cloudflare", HostName: "example.com", Interface: "invalid"}, "interface must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ddns.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNatRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    NatRule
		wantErr string
	}{
		{"valid MASQUERADE", NatRule{Type: "MASQUERADE"}, ""},
		{"valid DNAT", NatRule{Type: "DNAT", TranslatedIP: "192.168.1.1"}, ""},
		{"valid SNAT", NatRule{Type: "SNAT", TranslatedIP: "192.168.1.1"}, ""},
		{"missing type", NatRule{}, "type is required"},
		{"invalid type", NatRule{Type: "invalid"}, "type must be one of"},
		{"invalid protocol", NatRule{Type: "MASQUERADE", Protocol: "invalid"}, "protocol must be one of"},
		{"invalid source_address", NatRule{Type: "MASQUERADE", SourceAddress: "invalid"}, "source_address must be a valid IP or CIDR"},
		{"invalid source_port", NatRule{Type: "MASQUERADE", SourcePort: "invalid"}, "source_port must be a valid port"},
		{"invalid translated_ip", NatRule{Type: "DNAT", TranslatedIP: "invalid"}, "translated_ip must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestPortForwardValidate(t *testing.T) {
	tests := []struct {
		name    string
		pf      PortForward
		wantErr string
	}{
		{"valid", PortForward{Name: "Test", Proto: "tcp", DstPort: "80", Fwd: "192.168.1.1", FwdPort: "8080"}, ""},
		{"missing name", PortForward{}, "name is required"},
		{"invalid proto", PortForward{Name: "Test", Proto: "invalid"}, "proto must be one of"},
		{"invalid pfwd_interface", PortForward{Name: "Test", PfwdInterface: "invalid"}, "pfwd_interface must be one of"},
		{"invalid dst_port", PortForward{Name: "Test", DstPort: "invalid"}, "dst_port must be a valid port"},
		{"invalid fwd_port", PortForward{Name: "Test", FwdPort: "invalid"}, "fwd_port must be a valid port"},
		{"invalid fwd", PortForward{Name: "Test", Fwd: "invalid"}, "fwd must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pf.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestStaticDNSValidate(t *testing.T) {
	port := 80
	invalidPort := 0
	tests := []struct {
		name    string
		dns     StaticDNS
		wantErr string
	}{
		{"valid", StaticDNS{Key: "example.com", Value: "192.168.1.1", RecordType: "A"}, ""},
		{"missing key", StaticDNS{Value: "192.168.1.1"}, "key is required"},
		{"missing value", StaticDNS{Key: "example.com"}, "value is required"},
		{"invalid record_type", StaticDNS{Key: "example.com", Value: "192.168.1.1", RecordType: "INVALID"}, "record_type must be one of"},
		{"valid port", StaticDNS{Key: "example.com", Value: "192.168.1.1", Port: &port}, ""},
		{"invalid port", StaticDNS{Key: "example.com", Value: "192.168.1.1", Port: &invalidPort}, "port must be between 1 and 65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dns.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestRADIUSProfileValidate(t *testing.T) {
	validPort := 1812
	invalidPort := 0
	tests := []struct {
		name    string
		profile RADIUSProfile
		wantErr string
	}{
		{"valid", RADIUSProfile{Name: "Test"}, ""},
		{"missing name", RADIUSProfile{}, "name is required"},
		{"invalid vlan_wlan_mode", RADIUSProfile{Name: "Test", VlanWlanMode: "invalid"}, "vlan_wlan_mode must be one of"},
		{"valid auth_server", RADIUSProfile{Name: "Test", AuthServers: []RADIUSServer{{IP: "192.168.1.1", Port: &validPort}}}, ""},
		{"invalid auth_server ip", RADIUSProfile{Name: "Test", AuthServers: []RADIUSServer{{IP: "invalid"}}}, "auth_servers[0].ip must be a valid IP"},
		{"invalid auth_server port", RADIUSProfile{Name: "Test", AuthServers: []RADIUSServer{{IP: "192.168.1.1", Port: &invalidPort}}}, "auth_servers[0].port must be between 1 and 65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    FirewallRule
		wantErr string
	}{
		{"valid", FirewallRule{Name: "Test", Action: "accept", Ruleset: "WAN_IN"}, ""},
		{"missing name", FirewallRule{}, "name is required"},
		{"invalid action", FirewallRule{Name: "Test", Action: "invalid"}, "action must be one of"},
		{"invalid ruleset", FirewallRule{Name: "Test", Ruleset: "invalid"}, "ruleset must be a valid ruleset"},
		{"invalid protocol", FirewallRule{Name: "Test", Protocol: "invalid_proto"}, "protocol must be a valid protocol"},
		{"invalid src_address", FirewallRule{Name: "Test", SrcAddress: "invalid"}, "src_address must be a valid IP or CIDR"},
		{"invalid dst_port", FirewallRule{Name: "Test", DstPort: "invalid"}, "dst_port must be a valid port"},
		{"invalid src_mac_address", FirewallRule{Name: "Test", SrcMACAddress: "invalid"}, "src_mac_address must be a valid MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestFirewallPolicyValidate(t *testing.T) {
	tests := []struct {
		name   string
		policy FirewallPolicy
		wantErr string
	}{
		{"valid", FirewallPolicy{Name: "Test", Action: "ALLOW"}, ""},
		{"missing name", FirewallPolicy{}, "name is required"},
		{"invalid action", FirewallPolicy{Name: "Test", Action: "invalid"}, "action must be one of"},
		{"invalid protocol", FirewallPolicy{Name: "Test", Protocol: "invalid"}, "protocol must be one of"},
		{"invalid ip_version", FirewallPolicy{Name: "Test", IPVersion: "invalid"}, "ip_version must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestTrafficRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    TrafficRule
		wantErr string
	}{
		{"valid", TrafficRule{Name: "Test", Action: "BLOCK"}, ""},
		{"missing name", TrafficRule{}, "name is required"},
		{"invalid action", TrafficRule{Name: "Test", Action: "invalid"}, "action must be one of"},
		{"invalid matching_target", TrafficRule{Name: "Test", MatchingTarget: "invalid"}, "matching_target must be one of"},
		{"invalid ip_addresses", TrafficRule{Name: "Test", IPAddresses: []string{"invalid"}}, "ip_addresses[0] must be a valid IP or CIDR"},
		{"valid ip_addresses", TrafficRule{Name: "Test", IPAddresses: []string{"192.168.1.0/24"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestTrafficRouteValidate(t *testing.T) {
	tests := []struct {
		name    string
		route   TrafficRoute
		wantErr string
	}{
		{"valid", TrafficRoute{Name: "Test"}, ""},
		{"missing name", TrafficRoute{}, "name is required"},
		{"invalid matching_target", TrafficRoute{Name: "Test", MatchingTarget: "invalid"}, "matching_target must be one of"},
		{"invalid ip_addresses", TrafficRoute{Name: "Test", IPAddresses: []string{"invalid"}}, "ip_addresses[0] must be a valid IP or CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.route.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestPortConfValidate(t *testing.T) {
	tests := []struct {
		name    string
		conf    PortConf
		wantErr string
	}{
		{"valid", PortConf{Name: "Test", Forward: "all"}, ""},
		{"missing name", PortConf{}, "name is required"},
		{"invalid forward", PortConf{Name: "Test", Forward: "invalid"}, "forward must be one of"},
		{"invalid dot1x_ctrl", PortConf{Name: "Test", Dot1xCtrl: "invalid"}, "dot1x_ctrl must be one of"},
		{"invalid op_mode", PortConf{Name: "Test", OpMode: "invalid"}, "op_mode must be one of"},
		{"invalid poe_mode", PortConf{Name: "Test", PoeMode: "invalid"}, "poe_mode must be one of"},
		{"invalid mac", PortConf{Name: "Test", PortSecurityMacAddress: []string{"invalid"}}, "port_security_mac_address[0] must be a valid MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.conf.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestWLANConfValidate(t *testing.T) {
	tests := []struct {
		name    string
		wlan    WLANConf
		wantErr string
	}{
		{"valid", WLANConf{Name: "Test", Security: "wpapsk"}, ""},
		{"missing name", WLANConf{}, "name is required"},
		{"invalid security", WLANConf{Name: "Test", Security: "invalid"}, "security must be one of"},
		{"invalid wpa_mode", WLANConf{Name: "Test", WPAMode: "invalid"}, "wpa_mode must be one of"},
		{"invalid wpa_enc", WLANConf{Name: "Test", WPAEnc: "invalid"}, "wpa_enc must be one of"},
		{"invalid wlan_band", WLANConf{Name: "Test", WLANBand: "invalid"}, "wlan_band must be one of"},
		{"invalid mac_filter_policy", WLANConf{Name: "Test", MacFilterPolicy: "invalid"}, "mac_filter_policy must be one of"},
		{"invalid mac_filter_list", WLANConf{Name: "Test", MacFilterList: []string{"invalid"}}, "mac_filter_list[0] must be a valid MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wlan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkValidate(t *testing.T) {
	tests := []struct {
		name    string
		network Network
		wantErr string
	}{
		{"valid", Network{Name: "Test", Purpose: "corporate"}, ""},
		{"missing name", Network{}, "name is required"},
		{"invalid purpose", Network{Name: "Test", Purpose: "invalid"}, "purpose must be one of"},
		{"invalid networkgroup", Network{Name: "Test", NetworkRouting: NetworkRouting{NetworkGroup: "invalid"}}, "networkgroup must be one of"},
		{"invalid wan_type", Network{Name: "Test", NetworkWAN: NetworkWAN{WANType: "invalid"}}, "wan_type must be one of"},
		{"invalid ip_subnet", Network{Name: "Test", NetworkVLAN: NetworkVLAN{IPSubnet: "invalid"}}, "ip_subnet must be a valid CIDR"},
		{"invalid dhcpd_start", Network{Name: "Test", NetworkDHCP: NetworkDHCP{DHCPDStart: "invalid"}}, "dhcpd_start must be a valid IP"},
		{"invalid wan_gateway", Network{Name: "Test", NetworkWAN: NetworkWAN{WANGateway: "invalid"}}, "wan_gateway must be a valid IP"},
		{"valid cidr", Network{Name: "Test", NetworkVLAN: NetworkVLAN{IPSubnet: "192.168.1.0/24"}}, ""},
		{"valid dhcp", Network{Name: "Test", NetworkDHCP: NetworkDHCP{DHCPDStart: "192.168.1.100", DHCPDStop: "192.168.1.200"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.network.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func checkError(t *testing.T, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Errorf("expected error containing %q, got nil", wantErr)
		return
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("expected error containing %q, got %q", wantErr, err.Error())
	}
}

func TestNetworkJSONRoundTrip(t *testing.T) {
	original := Network{
		Name:              "TestNet",
		Purpose:           "corporate",
		SettingPreference: "auto",
		GatewayType:       "default",
		NetworkVLAN: NetworkVLAN{
			VLAN:        IntPtr(100),
			VLANEnabled: BoolPtr(true),
			IPSubnet:    "192.168.1.0/24",
		},
		NetworkDHCP: NetworkDHCP{
			DHCPDEnabled: BoolPtr(true),
			DHCPDStart:   "192.168.1.100",
			DHCPDStop:    "192.168.1.200",
			NetworkDHCPDNS: NetworkDHCPDNS{
				DHCPDDNSEnabled: BoolPtr(true),
				DHCPDDns1:       "8.8.8.8",
			},
		},
		NetworkWAN: NetworkWAN{
			WANType:    "dhcp",
			WANGateway: "192.168.1.1",
		},
		NetworkRouting: NetworkRouting{
			NetworkGroup: "LAN",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map error: %v", err)
	}

	flatFields := []string{
		"name", "purpose", "setting_preference", "gateway_type",
		"vlan", "vlan_enabled", "ip_subnet",
		"dhcpd_enabled", "dhcpd_start", "dhcpd_stop",
		"dhcpd_dns_enabled", "dhcpd_dns_1",
		"wan_type", "wan_gateway",
		"networkgroup",
	}
	for _, field := range flatFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q should be at top level in JSON", field)
		}
	}

	var decoded Network
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Name != original.Name {
		t.Errorf("Name mismatch: got %q, want %q", decoded.Name, original.Name)
	}
	if decoded.IPSubnet != original.IPSubnet {
		t.Errorf("IPSubnet mismatch: got %q, want %q", decoded.IPSubnet, original.IPSubnet)
	}
	if decoded.DHCPDStart != original.DHCPDStart {
		t.Errorf("DHCPDStart mismatch: got %q, want %q", decoded.DHCPDStart, original.DHCPDStart)
	}
	if decoded.WANType != original.WANType {
		t.Errorf("WANType mismatch: got %q, want %q", decoded.WANType, original.WANType)
	}
	if decoded.NetworkGroup != original.NetworkGroup {
		t.Errorf("NetworkGroup mismatch: got %q, want %q", decoded.NetworkGroup, original.NetworkGroup)
	}
}

func TestNetworkVLANValidate(t *testing.T) {
	tests := []struct {
		name    string
		vlan    NetworkVLAN
		wantErr string
	}{
		{"valid empty", NetworkVLAN{}, ""},
		{"valid cidr", NetworkVLAN{IPSubnet: "192.168.1.0/24"}, ""},
		{"invalid cidr", NetworkVLAN{IPSubnet: "invalid"}, "ip_subnet must be a valid CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vlan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkDHCPValidate(t *testing.T) {
	tests := []struct {
		name    string
		dhcp    NetworkDHCP
		wantErr string
	}{
		{"valid empty", NetworkDHCP{}, ""},
		{"valid ips", NetworkDHCP{DHCPDStart: "192.168.1.100", DHCPDStop: "192.168.1.200"}, ""},
		{"invalid start", NetworkDHCP{DHCPDStart: "invalid"}, "dhcpd_start must be a valid IP"},
		{"invalid stop", NetworkDHCP{DHCPDStop: "invalid"}, "dhcpd_stop must be a valid IP"},
		{"invalid gateway", NetworkDHCP{NetworkDHCPGateway: NetworkDHCPGateway{DHCPDGateway: "invalid"}}, "dhcpd_gateway must be a valid IP"},
		{"invalid dns1", NetworkDHCP{NetworkDHCPDNS: NetworkDHCPDNS{DHCPDDns1: "invalid"}}, "dhcpd_dns_1 must be a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dhcp.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkWANValidate(t *testing.T) {
	tests := []struct {
		name    string
		wan     NetworkWAN
		wantErr string
	}{
		{"valid empty", NetworkWAN{}, ""},
		{"valid wan_type", NetworkWAN{WANType: "dhcp"}, ""},
		{"invalid wan_type", NetworkWAN{WANType: "invalid"}, "wan_type must be one of"},
		{"invalid wan_ip", NetworkWAN{WANIP: "invalid"}, "wan_ip must be a valid IP"},
		{"invalid wan_gateway", NetworkWAN{WANGateway: "invalid"}, "wan_gateway must be a valid IP"},
		{"invalid wan_netmask", NetworkWAN{WANNetmask: "invalid"}, "wan_netmask must be a valid IP"},
		{"invalid wan_type_v6", NetworkWAN{NetworkWANIPv6: NetworkWANIPv6{WANTypeV6: "invalid"}}, "wan_type_v6 must be one of"},
		{"invalid load_balance_type", NetworkWAN{NetworkWANLoadBalance: NetworkWANLoadBalance{WANLoadBalanceType: "invalid"}}, "wan_load_balance_type must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wan.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}

func TestNetworkRoutingValidate(t *testing.T) {
	tests := []struct {
		name    string
		routing NetworkRouting
		wantErr string
	}{
		{"valid empty", NetworkRouting{}, ""},
		{"valid networkgroup", NetworkRouting{NetworkGroup: "LAN"}, ""},
		{"invalid networkgroup", NetworkRouting{NetworkGroup: "invalid"}, "networkgroup must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.routing.Validate()
			checkError(t, err, tt.wantErr)
		})
	}
}
