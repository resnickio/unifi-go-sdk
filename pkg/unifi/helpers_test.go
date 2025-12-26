package unifi

import "testing"

func TestStringPtr(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"non-empty string", "hello"},
		{"empty string", ""},
		{"string with spaces", "hello world"},
		{"unicode string", "こんにちは"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringPtr(tt.input)
			if result == nil {
				t.Fatal("StringPtr returned nil")
			}
			if *result != tt.input {
				t.Errorf("StringPtr(%q) = %q, want %q", tt.input, *result, tt.input)
			}
		})
	}
}
