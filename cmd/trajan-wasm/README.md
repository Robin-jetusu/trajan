# Trajan WASM API Reference

JavaScript API exported for browser integration.

## Initialization

```javascript
// Auto-initialized when WASM loads
// Check: window.trajanInitialize
```

## Configuration

### trajanConfigGet(key)
Get configuration value by dot-notation key.

```javascript
const result = await trajanConfigGet('github.token');
console.log(result.value);
```

### trajanConfigSet(key, value)
Set configuration value.

```javascript
await trajanConfigSet('github.token', 'ghp_...');
```

## Scanning

### trajanStartScan(target, options)
Start vulnerability scan.

```javascript
const result = await trajanStartScan('https://github.com/owner/repo', {
  platform: 'github',
  token: 'ghp_...',
  concurrent: 5,
  onProgress: (percent, message) => console.log(message)
});
console.log(result.scanId);
```

### trajanGetResults(scanId)
Get scan results.

```javascript
const result = await trajanGetResults(scanId);
console.log(result.findings);
```

### trajanCancelScan()
Cancel active scan.

```javascript
await trajanCancelScan();
```

## Attacks

### trajanListAttackPlugins()
List available attack plugins.

```javascript
const result = await trajanListAttackPlugins();
console.log(result.plugins); // Array of {id, name, description}
```

### trajanExecuteAttack(plugin, target, options)
Execute attack plugin.

```javascript
const result = await trajanExecuteAttack('secrets-dump', 'https://github.com/owner/repo', {
  token: 'ghp_...',
  authorized: true,
  dryRun: true,
  saveSession: true
});
```

### trajanCleanupSession(sessionId, token)
Cleanup attack artifacts.

```javascript
const result = await trajanCleanupSession('session_123', 'ghp_...');
console.log(result.summary);
```

## Sessions

### trajanListSessions()
List all attack sessions.

```javascript
const result = await trajanListSessions();
console.log(result.sessions);
```

## Version

### trajanGetVersion()
Get build information.

```javascript
const info = trajanGetVersion();
console.log(info.version, info.buildTime, info.gitCommit);
```

## Export

### trajanExportJSON(scanId)
Export results as JSON.

```javascript
const result = await trajanExportJSON(scanId);
console.log(result.data); // JSON string
```

### trajanExportSARIF(scanId)
Export results as SARIF.

```javascript
const result = await trajanExportSARIF(scanId);
console.log(result.data); // SARIF JSON string
```

## Error Handling

All functions return promises. Errors are returned as:

```javascript
{
  error: "Error message string"
}
```

Check for errors before using results:

```javascript
const result = await trajanStartScan(...);
if (result.error) {
  console.error('Scan failed:', result.error);
  return;
}
// Use result.scanId
```
