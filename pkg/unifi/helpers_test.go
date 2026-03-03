package unifi

import (
	"encoding/json"
	"testing"
)

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

func TestFlexInt_UnmarshalJSON(t *testing.T) {
	t.Run("from JSON number", func(t *testing.T) {
		var fi FlexInt
		if err := json.Unmarshal([]byte(`300`), &fi); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fi != 300 {
			t.Errorf("got %d, want 300", fi)
		}
	})

	t.Run("from JSON string", func(t *testing.T) {
		var fi FlexInt
		if err := json.Unmarshal([]byte(`"300"`), &fi); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fi != 300 {
			t.Errorf("got %d, want 300", fi)
		}
	})

	t.Run("from null pointer", func(t *testing.T) {
		type wrapper struct {
			Value *FlexInt `json:"value"`
		}
		var w wrapper
		if err := json.Unmarshal([]byte(`{"value":null}`), &w); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if w.Value != nil {
			t.Errorf("expected nil, got %d", *w.Value)
		}
	})

	t.Run("from negative number", func(t *testing.T) {
		var fi FlexInt
		if err := json.Unmarshal([]byte(`-42`), &fi); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fi != -42 {
			t.Errorf("got %d, want -42", fi)
		}
	})

	t.Run("invalid string errors", func(t *testing.T) {
		var fi FlexInt
		if err := json.Unmarshal([]byte(`"abc"`), &fi); err == nil {
			t.Fatal("expected error for non-numeric string")
		}
	})

	t.Run("unexpected type errors", func(t *testing.T) {
		var fi FlexInt
		if err := json.Unmarshal([]byte(`true`), &fi); err == nil {
			t.Fatal("expected error for boolean")
		}
	})
}

func TestFlexInt_MarshalJSON(t *testing.T) {
	fi := FlexInt(300)
	data, err := json.Marshal(fi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "300" {
		t.Errorf("got %s, want 300", data)
	}
}

func TestFlexInt_RoundTrip(t *testing.T) {
	type model struct {
		Value *FlexInt `json:"value"`
	}

	// String input → marshal → number output
	var m model
	if err := json.Unmarshal([]byte(`{"value":"7200"}`), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(data) != `{"value":7200}` {
		t.Errorf("got %s, want {\"value\":7200}", data)
	}
}

func TestFlexIntPtr(t *testing.T) {
	result := FlexIntPtr(42)
	if result == nil {
		t.Fatal("FlexIntPtr returned nil")
	}
	if *result != 42 {
		t.Errorf("got %d, want 42", *result)
	}
}
