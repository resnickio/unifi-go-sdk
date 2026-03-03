package unifi

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// IntPtr returns a pointer to the given int value.
// Useful for setting optional config fields like MaxRetries.
func IntPtr(i int) *int { return &i }

// BoolPtr returns a pointer to the given bool value.
// Useful for setting optional model fields like Enabled.
func BoolPtr(b bool) *bool { return &b }

// StringPtr returns a pointer to the given string value.
// Useful for setting optional model fields.
func StringPtr(s string) *string { return &s }

// FlexInt is an int that can be unmarshaled from either a JSON number or a
// JSON string containing a number. The UniFi controller is inconsistent about
// which representation it uses for certain fields across different API
// endpoints (e.g., ListNetworks returns strings, GetNetwork returns ints).
type FlexInt int

func (fi *FlexInt) UnmarshalJSON(data []byte) error {
	// Try number first
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*fi = FlexInt(n)
		return nil
	}

	// Try string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("FlexInt: cannot convert string %q to int: %w", s, err)
		}
		*fi = FlexInt(n)
		return nil
	}

	return fmt.Errorf("FlexInt: cannot unmarshal %s", string(data))
}

func (fi FlexInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(fi))
}

// FlexIntPtr returns a pointer to a FlexInt with the given value.
func FlexIntPtr(i int) *FlexInt {
	fi := FlexInt(i)
	return &fi
}
