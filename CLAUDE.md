# UniFi Go SDK

Go SDK for the UniFi Site Manager and Network APIs.

## Structure

- `pkg/unifi/` - SDK package
- `cmd/example/` - Test harness

## API Documentation

- Site Manager: https://developer.ui.com/site-manager-api/gettingstarted
- Network API: https://unifi.ui.com/consoles/602232751F750000000006ADC7430000000006FE426700000000631440BA:1714109442/unifi-api/network

## Build & Run
```bash
UNIFI_API_KEY=your-key go run cmd/example/main.go
```