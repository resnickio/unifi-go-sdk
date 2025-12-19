package unifi

import "testing"

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"", false},
		{"invalid", false},
		{"192.168.1", false},
		{"192.168.1.256", false},
		{"192.168.1.1/24", false},
	}
	for _, tt := range tests {
		if got := isValidIP(tt.input); got != tt.want {
			t.Errorf("isValidIP(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsValidCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", true},
		{"0.0.0.0/0", true},
		{"2001:db8::/32", true},
		{"", false},
		{"invalid", false},
		{"192.168.1.1", false},
		{"192.168.1.0/33", false},
	}
	for _, tt := range tests {
		if got := isValidCIDR(tt.input); got != tt.want {
			t.Errorf("isValidCIDR(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		input int
		want  bool
	}{
		{1, true},
		{80, true},
		{443, true},
		{65535, true},
		{0, false},
		{-1, false},
		{65536, false},
	}
	for _, tt := range tests {
		if got := isValidPort(tt.input); got != tt.want {
			t.Errorf("isValidPort(%d) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsValidPortRange(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"80", true},
		{"443", true},
		{"1-1024", true},
		{"80-443", true},
		{"1-65535", true},
		{"", false},
		{"invalid", false},
		{"0", false},
		{"65536", false},
		{"443-80", false},
		{"1-2-3", false},
		{"-80", false},
	}
	for _, tt := range tests {
		if got := isValidPortRange(tt.input); got != tt.want {
			t.Errorf("isValidPortRange(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsValidMAC(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"00:11:22:33:44:55", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"", false},
		{"invalid", false},
		{"00:11:22:33:44", false},
		{"00:11:22:33:44:55:66", false},
		{"00-11-22-33-44-55", false},
		{"0011.2233.4455", false},
	}
	for _, tt := range tests {
		if got := isValidMAC(tt.input); got != tt.want {
			t.Errorf("isValidMAC(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsOneOf(t *testing.T) {
	tests := []struct {
		value   string
		allowed []string
		want    bool
	}{
		{"a", []string{"a", "b", "c"}, true},
		{"b", []string{"a", "b", "c"}, true},
		{"d", []string{"a", "b", "c"}, false},
		{"", []string{"a", "b", "c"}, false},
		{"a", []string{}, false},
	}
	for _, tt := range tests {
		if got := isOneOf(tt.value, tt.allowed...); got != tt.want {
			t.Errorf("isOneOf(%q, %v) = %v, want %v", tt.value, tt.allowed, got, tt.want)
		}
	}
}
