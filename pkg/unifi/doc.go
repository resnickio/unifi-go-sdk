// Package unifi provides clients for the UniFi Site Manager and Network APIs.
//
// This SDK supports two distinct APIs:
//
// # Site Manager API (Cloud)
//
// The Site Manager API is a cloud-based API hosted at api.ui.com that provides
// read-only access to hosts, sites, and devices across your UniFi deployment.
// Authentication uses an API key obtained from https://unifi.ui.com.
//
// Use [NewSiteManagerClient] to create a client:
//
//	client, err := unifi.NewSiteManagerClient(unifi.SiteManagerClientConfig{
//	    APIKey: "your-api-key",
//	})
//
// # Network API (Controller)
//
// The Network API connects directly to a UniFi controller (Dream Machine, Cloud Key,
// or self-hosted) for full CRUD operations on network configuration including
// networks, firewall rules, WLANs, port forwards, and more.
//
// Use [NewNetworkClient] to create a client:
//
//	client, err := unifi.NewNetworkClient(unifi.NetworkClientConfig{
//	    BaseURL:  "https://192.168.1.1",
//	    Username: "admin",
//	    Password: "password",
//	})
//
// # Error Handling
//
// Both clients return sentinel errors for common HTTP status codes. Use [errors.Is]
// to check for specific error conditions:
//
//	if errors.Is(err, unifi.ErrNotFound) {
//	    // Handle 404
//	}
//
// For detailed error information including status codes and messages, use [errors.As]
// with [APIError]:
//
//	var apiErr *unifi.APIError
//	if errors.As(err, &apiErr) {
//	    log.Printf("Status: %d, Message: %s", apiErr.StatusCode, apiErr.Message)
//	}
//
// # Retry Logic
//
// Both clients automatically retry transient errors (502, 503, 504) and rate limit
// responses (429) with exponential backoff and jitter. Configure retry behavior
// via MaxRetries and MaxRetryWait in the client config.
//
// # Model Field Conventions
//
// Some model structs have fields with an "X" prefix (e.g., XPassphrase, XPassword).
// This follows the UniFi API convention where "x_" prefixed fields are write-only:
// they can be set when creating/updating resources but are not returned in responses.
// This is commonly used for sensitive data like passwords and pre-shared keys.
//
// Some fields use [json.RawMessage] for complex or rarely-used nested structures
// (e.g., QoSPolicies, WANDHCPOptions, AccessDevices, ProtectDevices). These preserve
// the raw JSON and can be unmarshaled into custom types if needed. Access and Protect
// device fields are included for completeness but are outside the scope of this
// Network API SDK.
package unifi
