# Trajan Browser - WASM Security Scanner

Browser-based GitHub Actions security scanner powered by WebAssembly.

## Quick Start

```bash
# Build WASM binary
./browser/build.sh

# Start development server
./browser/serve.sh

# Open browser
open http://localhost:8080
```

## Features

- 🌐 Browser-based scanning (no installation required)
- ⚡ WebAssembly performance (12MB binary, <3s load)
- 🔒 Client-side analysis (no backend server)
- 💾 Offline storage (IndexedDB + localStorage)
- 🎯 15 vulnerability detectors
- ⚔️ 7 attack plugins
- 🎨 Modern UI (4 tabs: Analysis, Attack, Shell, Settings)

## Architecture

### Entry Point

- `cmd/trajan-wasm/` - WASM main() and JavaScript exports

### Shared Code (from main Trajan)

- `pkg/analysis/` - Parsers, flow analysis, expression evaluation
- `pkg/detections/` - All 28 vulnerability detectors
- `pkg/attacks/` - All 8 attack plugins
- `pkg/platforms/` - GitHub/GitLab/Azure/Bitbucket API clients

### Browser-Specific Code

- `pkg/storage/` - IndexedDB adapter (replaces file I/O)
- `pkg/config/` - localStorage configuration
- `pkg/results/` - Result formatting

### UI Files

- `browser/index.html` - Main UI
- `browser/app.js` - Application logic
- `browser/bridge.js` - WASM bridge
- `browser/styles.css` - Styling

## Build System

- `browser/build.sh` - Compiles cmd/trajan-wasm to WASM
- `browser/build-dist.sh` - Creates production dist/ folder
- `browser/serve.sh` - Development server

## Deployment

See main README.md for deployment options (Docker, static hosting, etc.)

## Testing

```bash
# Unit tests (native Go)
go test ./pkg/...

# WASM build verification
GOOS=js GOARCH=wasm go build ./cmd/trajan-wasm

# Browser functional testing
./browser/serve.sh &
open http://localhost:8080
# Follow test checklist in docs/testing/browser-testing-guide.md
```

## Documentation

- `README.md` - Main documentation (CLI + browser)
- `browser/README.md` - This file
- `docs/testing/browser-testing-guide.md` - Browser testing guide
- `cmd/trajan-wasm/README.md` - WASM API reference

## Differences from CLI

| Feature | CLI | Browser |
|---------|-----|---------|
| Platform | macOS, Linux, Windows | Any browser |
| Installation | Go binary | Visit URL |
| Storage | Files in ~/.trajan/ | IndexedDB + localStorage |
| Configuration | YAML files | Browser UI |
| Authentication | Token in config file | Token in localStorage |
| Output | Terminal, files | Browser UI, downloads |

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 15+
- Edge 90+
