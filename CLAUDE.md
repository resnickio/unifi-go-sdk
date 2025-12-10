# UniFi Go SDK

Go SDK for the UniFi Site Manager and Network APIs.

## Structure

- `pkg/unifi/` - SDK package
- `cmd/example/` - Test harness (requires `.env` with `UNIFI_API_KEY`)

## API Documentation

- Site Manager: https://developer.ui.com/site-manager-api/gettingstarted
- Network API: https://unifi.ui.com/consoles/602232751F750000000006ADC7430000000006FE426700000000631440BA:1714109442/unifi-api/network

## Build & Run
```bash
UNIFI_API_KEY=your-key go run cmd/example/main.go
```

## Downstream Usage

This SDK is intended to support a Terraform provider. Prioritize type safety with pointers for nullable JSON fields.

## Preferences

- **Commits**: Do not include Claude Code citations or co-author tags
- **Code style**: Minimal comments, no inline comments unless truly necessary
- **Go idioms**: Prefer exported fields over setter methods for simplicity. Skip helper functions (like `IsNotFound()`) - use standard `errors.Is()` patterns instead
- **Testing**: Use `httptest` for mocking. Export struct fields to allow test configuration
- **CI**: Keep simple - build and test only. Avoid paid services (Codecov, etc.) unless explicitly requested
- **Over-engineering**: Avoid. Don't add abstractions, helpers, or features beyond what's requested