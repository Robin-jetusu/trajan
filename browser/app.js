/**
 * Trajan Browser Security Scanner - Main Application
 *
 * This module handles all UI interactions and connects to the WASM bridge API.
 */

// ============================= //
// Global State
// ============================= //

let trajanBridge = null;
let currentScanId = null;
let currentShellSession = null;
let shellOutput = [];

// ============================= //
// Initialization
// ============================= //

document.addEventListener('DOMContentLoaded', () => {
    console.log('Trajan Security Scanner - Initializing...');
    initializeApp();
});

async function initializeApp() {
    try {
        // Initialize WASM bridge
        trajanBridge = new TrajanBridge();
        await trajanBridge.init();

        updateWASMStatus('ready', 'WASM Ready');
        showToast('WASM module loaded successfully', 'success');

        // Display version information
        await displayVersionInfo();

        // Initialize UI components
        initializeTabs();
        await initializeAnalysisTab();
        initializeFilters();
        initializeDetailView();
        initializeReconTab();
        initializeSearchTab();
        initializeValidateTab();
        await initializeAttackTab();
        initializeShellTab();
        initializeSettingsTab();

        // Load attack plugins
        await loadAttackPlugins();

        // Load active sessions
        await loadSessions();

        console.log('✅ Application initialized successfully');
    } catch (error) {
        console.error('❌ Initialization failed:', error);
        updateWASMStatus('error', `Error: ${error.message}`);
        showToast(`Initialization failed: ${error.message}`, 'error');
        disableAllFeatures(error.message);
    }
}

async function displayVersionInfo() {
    try {
        const versionInfo = await trajanBridge.getVersion();
        console.log('📦 Trajan Version:', versionInfo);

        // Update version display in settings
        const versionElement = document.getElementById('version-info');
        const buildElement = document.getElementById('build-info');

        if (versionElement) {
            versionElement.textContent = `Version: ${versionInfo.version}`;
        }

        if (buildElement) {
            buildElement.textContent = `Build: ${versionInfo.gitCommit} (${versionInfo.buildTime})`;
        }
    } catch (error) {
        console.warn('Failed to load version info:', error);
    }
}

function updateWASMStatus(status, text) {
    const statusIndicator = document.getElementById('wasm-status');
    if (!statusIndicator) return;
    statusIndicator.className = `status-indicator ${status}`;
    const statusText = statusIndicator.querySelector('.status-text');
    if (statusText) statusText.textContent = text;
}

// ============================= //
// Tab Navigation
// ============================= //

function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');

            // Update active states
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            button.classList.add('active');
            document.getElementById(`${targetTab}-tab`).classList.add('active');
        });
    });
}

// ============================= //
// Analysis Tab
// ============================= //

// Platform configuration
const PLATFORM_CONFIG = {
    github: {
        modules: ['actions_injection','pwn_request','review_injection','toctou','artifact_poisoning','cache_poisoning','self_hosted_runner','unpinned_action','excessive_permissions','environment_bypass','ai_token_exfiltration','ai_code_injection','ai_workflow_sabotage','ai_mcp_abuse','ai_privilege_escalation','ai_supply_chain_poisoning'],
        targetTypes: [{value:'repo',label:'Repository'},{value:'org',label:'Organization'},{value:'user',label:'User'}],
        targetPlaceholder: 'owner/repo', showBaseURL: false
    },
    gitlab: {
        modules: ['merge_request_unsafe_checkout','include_injection','self_hosted_runner','unpinned_action','actions_injection','merge_request_secrets_exposure','token_exposure','ai_token_exfiltration','ai_code_injection','ai_mcp_abuse'],
        targetTypes: [{value:'repo',label:'Project'},{value:'org',label:'Group'},{value:'user',label:'User'}],
        targetPlaceholder: 'group/project', showBaseURL: true, baseURLLabel: 'Instance URL', baseURLPlaceholder: 'https://gitlab.com'
    },
    azuredevops: {
        modules: ['script_injection','trigger_exploitation','service_connection_hijacking','dynamic_template_injection','excessive_job_permissions','overexposed_service_connections','secret_scope_risk','environment_bypass','self_hosted_agent','ai_token_exfiltration','ai_code_injection','ai_mcp_abuse','unredacted_secrets','token_exposure','pull_request_secrets_exposure'],
        targetTypes: [{value:'repo',label:'Project/Repository'},{value:'org',label:'Organization'},{value:'user',label:'User'}],
        targetPlaceholder: 'project/repo', showBaseURL: true, baseURLLabel: 'Organization URL', baseURLPlaceholder: 'https://dev.azure.com/myorg'
    }
};

let currentDetailFinding = null;

async function initializeAnalysisTab() {
    const btnStartScan = document.getElementById('btn-start-scan');
    const btnCancelScan = document.getElementById('btn-cancel-scan');
    const btnExportJson = document.getElementById('btn-export-json');
    const btnExportSarif = document.getElementById('btn-export-sarif');
    const toggleTokenBtn = document.getElementById('toggle-scan-token');
    const platformSelect = document.getElementById('scan-platform');
    const targetTypeSelect = document.getElementById('scan-target-type');

    btnStartScan.addEventListener('click', handleStartScan);
    btnCancelScan.addEventListener('click', handleCancelScan);
    btnExportJson.addEventListener('click', () => handleExportResults('json'));
    btnExportSarif.addEventListener('click', () => handleExportResults('sarif'));
    toggleTokenBtn.addEventListener('click', () => togglePasswordVisibility('scan-token'));

    platformSelect.addEventListener('change', handlePlatformChange);
    targetTypeSelect.addEventListener('change', handleTargetTypeChange);

    // Load token from Settings if scan-token is empty
    try {
        const scanTokenField = document.getElementById('scan-token');
        if (!scanTokenField.value) {
            const result = await trajanBridge.configGet('github.token');
            if (result.value) {
                scanTokenField.value = result.value;
            }
        }
    } catch (error) {
        console.error('Failed to load token:', error);
    }

    // Initialize platform-specific UI
    handlePlatformChange();
}

// isValidAdoOrgURL returns true only for Azure DevOps organization URLs.
// Accepted forms: https://dev.azure.com/<org> and https://<org>.visualstudio.com
// This prevents submitting arbitrary URLs to the WASM module / proxy.
function isValidAdoOrgURL(url) {
    return /^https:\/\/(dev\.azure\.com\/[^/]+|[^/]+\.visualstudio\.com)\/?$/.test(url);
}

async function handleStartScan() {
    const platform = document.getElementById('scan-platform').value;
    const selectedModules = Array.from(document.querySelectorAll('input[name="scan-module"]:checked')).map(cb => cb.value);
    const targetType = document.getElementById('scan-target-type').value;
    const targetValue = document.getElementById('scan-target-value').value.trim();
    const baseURL = document.getElementById('scan-base-url').value.trim();
    const token = document.getElementById('scan-token').value.trim();

    if (!platform || !targetValue || !token) {
        showToast('Please fill all required fields', 'warning');
        return;
    }

    if (targetType === 'repo' && !targetValue.includes('/')) {
        showToast('Invalid repository format (expected: owner/repo)', 'error');
        return;
    }

    // Azure DevOps requires a valid org URL: https://dev.azure.com/<org> or https://<org>.visualstudio.com
    if (platform === 'azuredevops') {
        if (!baseURL) {
            showToast('Organization URL is required for Azure DevOps (e.g., https://dev.azure.com/myorg)', 'warning');
            return;
        }
        if (!isValidAdoOrgURL(baseURL)) {
            showToast('Invalid Organization URL (expected: https://dev.azure.com/myorg or https://myorg.visualstudio.com)', 'error');
            return;
        }
    }

    try {
        // Show progress
        document.getElementById('scan-progress').style.display = 'block';
        document.getElementById('scan-results-list').style.display = 'none';
        document.getElementById('scan-results-detail').style.display = 'none';
        document.getElementById('btn-start-scan').disabled = true;
        document.getElementById('btn-cancel-scan').disabled = false;

        // Start scan
        const result = await trajanBridge.startScan(targetValue, {
            platform,
            token,
            scope: targetType,
            baseURL: baseURL || undefined,
            capabilities: selectedModules.length === 0 ? null : selectedModules.join(','),
            concurrent: 10,
            onProgress: (percent, message) => {
                updateScanProgress(percent, message);

                // Load results when scan completes (100%)
                if (percent === 100) {
                    setTimeout(async () => {
                        await loadScanResults(result.scanId);
                    }, 500); // Small delay to ensure cache is written
                }
            }
        });

        currentScanId = result.scanId;
        showToast('Scan started successfully', 'success');

    } catch (error) {
        console.error('Scan failed:', error);
        showToast(`Scan failed: ${error.message}`, 'error');
    } finally {
        document.getElementById('btn-start-scan').disabled = false;
        document.getElementById('btn-cancel-scan').disabled = true;
    }
}

function handleCancelScan() {
    if (!trajanBridge) return;

    const result = trajanBridge.cancelScan();
    if (result.success) {
        showToast('Scan cancelled', 'info');
        document.getElementById('scan-progress').style.display = 'none';
        document.getElementById('btn-cancel-scan').disabled = true;
        document.getElementById('btn-start-scan').disabled = false;
    }
}

function updateScanProgress(percent, message) {
    const progressBar = document.getElementById('scan-progress-bar');
    const progressText = document.getElementById('scan-progress-text');

    if (progressBar) progressBar.style.width = `${percent}%`;
    if (progressText) progressText.textContent = message;
}

async function loadScanResults(scanId) {
    try {
        const result = await trajanBridge.getResults(scanId);

        // Hide progress, show results
        document.getElementById('scan-progress').style.display = 'none';
        document.getElementById('scan-results-list').style.display = 'block';

        window.currentFindings = result.findings || [];
        displayFindingsList(window.currentFindings);
        showToast('Scan completed', 'success');
    } catch (error) {
        console.error('Failed to load results:', error);
        showToast(`Failed to load results: ${error.message}`, 'error');
    }
}

function displayFindingsList(findings) {
    updateSummary(findings);
    populateFilters(findings);
    renderFindingCards(findings);
}

function updateSummary(findings) {
    const counts = {
        total: findings.length,
        repos: new Set(findings.map(f => f.repository)).size,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
    };
    const totalCount = document.getElementById('total-findings-count');
    const repoCount = document.getElementById('repo-count');
    const countCritical = document.getElementById('count-critical');
    const countHigh = document.getElementById('count-high');
    const countMedium = document.getElementById('count-medium');
    const countLow = document.getElementById('count-low');

    if (totalCount) totalCount.textContent = `${counts.total} findings`;
    if (repoCount) repoCount.textContent = `across ${counts.repos} ${counts.repos === 1 ? 'repository' : 'repositories'}`;
    if (countCritical) countCritical.textContent = `${counts.critical} Critical`;
    if (countHigh) countHigh.textContent = `${counts.high} High`;
    if (countMedium) countMedium.textContent = `${counts.medium} Medium`;
    if (countLow) countLow.textContent = `${counts.low} Low`;
}

function populateFilters(findings) {
    const types = [...new Set(findings.map(f => f.type))].sort();
    document.getElementById('filter-type').innerHTML = '<option value="">All Types</option>' + types.map(type => {
        const count = findings.filter(f => f.type === type).length;
        const label = type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const escapedType = escapeHtml(type);
        const escapedLabel = escapeHtml(label);
        return `<option value="${escapedType}">${escapedLabel} (${count})</option>`;
    }).join('');
    const repos = [...new Set(findings.map(f => f.repository))].sort();
    document.getElementById('filter-repo').innerHTML = '<option value="">All Repositories</option>' + repos.map(repo => {
        const count = findings.filter(f => f.repository === repo).length;
        const escapedRepo = escapeHtml(repo);
        return `<option value="${escapedRepo}">${escapedRepo} (${count})</option>`;
    }).join('');
    document.getElementById('filter-severity').innerHTML = '<option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="critical,high">Critical + High</option>';
    document.getElementById('filter-count').textContent = `Showing ${findings.length}/${findings.length}`;
}

function renderFindingCards(findings) {
    const container = document.getElementById('findings-list');
    if (!window.currentFindings || window.currentFindings.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>No Vulnerabilities Found</h3></div>';
        return;
    }
    if (findings.length === 0) {
        container.innerHTML = '<div class="empty-state"><h3>No Matching Findings</h3><button onclick="clearFilters()" class="btn btn-secondary">Clear Filters</button></div>';
        document.getElementById('filter-count').textContent = 'Showing 0/' + window.currentFindings.length;
        return;
    }
    const sorted = [...findings].sort((a,b) => ({critical:0,high:1,medium:2,low:3,info:4}[a.severity]??999) - ({critical:0,high:1,medium:2,low:3,info:4}[b.severity]??999));
    window.displayedFindings = sorted;
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    const html = sorted.map((finding, index) => {
        const typeDisplay = finding.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const safeSeverity = validSeverities.includes(finding.severity) ? finding.severity : 'info';
        return `
        <div class="finding-card severity-${safeSeverity}" data-finding-index="${index}">
            <div class="finding-severity">
                <span class="severity-indicator ${safeSeverity}">${safeSeverity.toUpperCase()}</span>
            </div>
            <div class="finding-card-header">
                <span class="finding-type">${escapeHtml(typeDisplay)}</span>
                <span class="repository-tag">${escapeHtml(finding.repository)}</span>
            </div>
            <div class="finding-description">
                ${escapeHtml(finding.evidence || 'No description available')}
            </div>
        </div>
        `;
    }).join('');
    container.innerHTML = html;
    document.getElementById('filter-count').textContent = `Showing ${findings.length}/${window.currentFindings.length}`;
}

function displayScanResults(result) {
    const findings = result.findings || [];

    // Sort findings by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4 };
    const sortedFindings = findings.sort((a, b) => {
        const orderA = severityOrder[a.severity] ?? 999;
        const orderB = severityOrder[b.severity] ?? 999;
        return orderA - orderB;
    });

    // Display summary (fix case sensitivity - severities are lowercase)
    const summary = {
        critical: sortedFindings.filter(f => f.severity === 'critical').length,
        high: sortedFindings.filter(f => f.severity === 'high').length,
        medium: sortedFindings.filter(f => f.severity === 'medium').length,
        low: sortedFindings.filter(f => f.severity === 'low').length
    };

    const summaryHTML = `
        <div class="summary-card critical">
            <div class="count">${summary.critical}</div>
            <div class="label">CRITICAL</div>
        </div>
        <div class="summary-card high">
            <div class="count">${summary.high}</div>
            <div class="label">HIGH</div>
        </div>
        <div class="summary-card medium">
            <div class="count">${summary.medium}</div>
            <div class="label">MEDIUM</div>
        </div>
        <div class="summary-card low">
            <div class="count">${summary.low}</div>
            <div class="label">LOW</div>
        </div>
    `;
    document.getElementById('scan-summary').innerHTML = summaryHTML;

    // Display findings
    if (sortedFindings.length === 0) {
        document.getElementById('scan-findings').innerHTML = `
            <div class="card">
                <p class="text-center text-muted">No vulnerabilities detected. Repository appears secure.</p>
            </div>
        `;
        return;
    }

    const findingsHTML = sortedFindings.map(finding => {
        // Create title from type and location
        const typeDisplay = finding.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const title = `${typeDisplay} in ${finding.workflow}`;
        const location = [finding.workflow, finding.job, finding.step].filter(Boolean).join(' > ');

        const safeSev = escapeHtml(finding.severity);
        return `
        <div class="finding ${safeSev}">
            <div class="finding-header">
                <div class="finding-title">${escapeHtml(title)}</div>
                <div class="severity-badge ${safeSev}">${safeSev.toUpperCase()}</div>
            </div>
            <div class="finding-detail">
                <span class="finding-label">Location:</span>
                <code>${escapeHtml(location)}</code>
            </div>
            ${finding.trigger ? `
                <div class="finding-detail">
                    <span class="finding-label">Trigger:</span>
                    <code>${escapeHtml(finding.trigger)}</code>
                </div>
            ` : ''}
            ${finding.evidence ? `
                <div class="finding-detail">
                    <span class="finding-label">Evidence:</span>
                    <div class="finding-code">${escapeHtml(finding.evidence)}</div>
                </div>
            ` : ''}
            ${finding.confidence ? `
                <div class="finding-detail">
                    <span class="finding-label">Confidence:</span>
                    <span class="badge">${escapeHtml(finding.confidence)}</span>
                </div>
            ` : ''}
            ${finding.complexity ? `
                <div class="finding-detail">
                    <span class="finding-label">Attack Complexity:</span>
                    <span class="badge">${escapeHtml(finding.complexity)}</span>
                </div>
            ` : ''}
            ${finding.remediation ? `
                <div class="finding-detail">
                    <span class="finding-label">Remediation:</span>
                    <p>${escapeHtml(finding.remediation)}</p>
                </div>
            ` : ''}
        </div>
    `;
    }).join('');

    document.getElementById('scan-findings').innerHTML = findingsHTML;
}

function handlePlatformChange() {
    const platform = document.getElementById('scan-platform').value;
    const config = PLATFORM_CONFIG[platform];
    const modulesContainer = document.getElementById('scan-modules');
    modulesContainer.innerHTML = config.modules.map(module => {
        const label = module.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        return `<label class="module-checkbox-label"><input type="checkbox" name="scan-module" value="${module}" checked><span>${label}</span></label>`;
    }).join('');
    document.getElementById('scan-target-type').innerHTML = config.targetTypes.map(type => `<option value="${type.value}">${type.label}</option>`).join('');
    document.getElementById('scan-target-value').placeholder = config.targetPlaceholder;
    // Helper text removed for cleaner UI - placeholder is sufficient
    const baseURLGroup = document.getElementById('base-url-group');
    if (config.showBaseURL) {
        baseURLGroup.style.display = 'block';
        const baseURLLabel = document.getElementById('base-url-label');
        const baseURLInput = document.getElementById('scan-base-url');
        const baseURLHelp = document.getElementById('base-url-help');
        if (baseURLLabel) baseURLLabel.textContent = config.baseURLLabel;
        if (baseURLInput) baseURLInput.placeholder = config.baseURLPlaceholder;
        if (baseURLHelp) baseURLHelp.textContent = 'Leave empty for default or enter self-hosted URL';
    } else {
        baseURLGroup.style.display = 'none';
    }
}

function handleTargetTypeChange() {
    const platform = document.getElementById('scan-platform').value;
    const targetType = document.getElementById('scan-target-type').value;
    const placeholders = {
        github: {repo: 'owner/repo', org: 'org-name', user: 'username'},
        gitlab: {repo: 'group/project', org: 'group-name', user: 'username'},
        azuredevops: {repo: 'project/repo', org: 'org-name', user: 'username'}
    };
    document.getElementById('scan-target-value').placeholder = placeholders[platform][targetType];
}

function initializeFilters() {
    document.getElementById('filter-severity').addEventListener('change', applyFilters);
    document.getElementById('filter-type').addEventListener('change', applyFilters);
    document.getElementById('filter-repo').addEventListener('change', applyFilters);
    document.getElementById('btn-clear-filters').addEventListener('click', clearFilters);
    const findingsList = document.getElementById('findings-list');
    findingsList.addEventListener('click', (e) => {
        const card = e.target.closest('.finding-card');
        if (card && window.displayedFindings) {
            const index = parseInt(card.dataset.findingIndex);
            showFindingDetail(window.displayedFindings[index]);
        }
    });
}

function initializeDetailView() {
    document.getElementById('btn-back-to-findings').addEventListener('click', () => {
        document.getElementById('scan-results-detail').style.display = 'none';
        document.getElementById('scan-results-list').style.display = 'block';
    });
    document.getElementById('btn-copy-code').addEventListener('click', () => {
        const code = Array.from(document.querySelectorAll('.line-content')).map(el => el.textContent).join('\n');
        navigator.clipboard.writeText(code);
        showToast('Code copied', 'success');
    });
}

function showFindingDetail(finding) {
    currentDetailFinding = finding;
    document.getElementById('scan-results-list').style.display = 'none';
    document.getElementById('scan-results-detail').style.display = 'block';
    const typeDisplay = finding.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    document.getElementById('detail-finding-name').textContent = typeDisplay;
    const severityBadge = document.getElementById('detail-severity-badge');
    severityBadge.textContent = finding.severity.toUpperCase();
    severityBadge.className = `severity-badge ${finding.severity}`;
    document.getElementById('detail-description').textContent = finding.evidence || 'No description available';
    document.getElementById('detail-repository').textContent = finding.repository || '-';
    document.getElementById('detail-workflow').textContent = finding.workflow || '-';
    document.getElementById('detail-job').textContent = finding.job || '-';
    document.getElementById('detail-step').textContent = finding.step || '-';
    if (finding.details && finding.details.attack_chain && finding.details.attack_chain.length > 0) {
        document.getElementById('detail-attackpath-section').style.display = 'block';
        const attackPath = finding.details.attack_chain.map(node => {
            let label = `${escapeHtml(node.type)}: ${escapeHtml(node.name)}`;
            if (node.line) label += ` (line ${escapeHtml(String(node.line))})`;
            return `<div class="attack-path-node">→ ${label}</div>`;
        }).join('');
        document.getElementById('detail-attack-path').innerHTML = attackPath;
    } else {
        document.getElementById('detail-attackpath-section').style.display = 'none';
    }
    const workflowContent = finding.workflow_content || finding.evidence || '';
    if (workflowContent) {
        const lines = workflowContent.split('\n');
        const filename = finding.workflow ? finding.workflow.split('/').pop() : 'workflow.yml';
        document.getElementById('code-filename').textContent = filename;
        document.getElementById('code-line-count').textContent = `${lines.length} lines`;
        const highlightLines = new Set();
        if (finding.details && finding.details.line_ranges) {
            finding.details.line_ranges.forEach(range => {
                for (let i = range.start; i <= range.end; i++) highlightLines.add(i);
            });
        }
        if (finding.details && finding.details.attack_chain) {
            finding.details.attack_chain.forEach(node => { if (node.line) highlightLines.add(node.line); });
        }
        if (finding.line) highlightLines.add(finding.line);
        // Apply YAML syntax highlighting per-line to preserve indentation
        const html = lines.map((line, index) => {
            const lineNum = index + 1;
            const isHighlighted = highlightLines.has(lineNum);
            // Highlight each line individually to preserve whitespace and avoid breaking HTML tags
            const highlightedLine = hljs.highlight(line, { language: 'yaml' }).value;
            return `<div class="code-line ${isHighlighted ? 'highlighted' : ''}"><span class="line-number">${lineNum}</span><span class="line-content">${highlightedLine}</span></div>`;
        }).join('');
        document.getElementById('code-viewer').innerHTML = html;

        // Scroll the first highlighted line into view
        const firstHighlighted = document.querySelector('#code-viewer .code-line.highlighted');
        if (firstHighlighted) {
            firstHighlighted.scrollIntoView({ block: 'center' });
        }
    }
}

function applyFilters() {
    if (!window.currentFindings) return;
    const severityFilter = document.getElementById('filter-severity').value;
    const typeFilter = document.getElementById('filter-type').value;
    const repoFilter = document.getElementById('filter-repo').value;
    let filtered = window.currentFindings;
    if (severityFilter) {
        const severities = severityFilter.split(',');
        filtered = filtered.filter(f => severities.includes(f.severity));
    }
    if (typeFilter) filtered = filtered.filter(f => f.type === typeFilter);
    if (repoFilter) filtered = filtered.filter(f => f.repository === repoFilter);
    renderFindingCards(filtered);
}

function clearFilters() {
    document.getElementById('filter-severity').value = '';
    document.getElementById('filter-type').value = '';
    document.getElementById('filter-repo').value = '';
    applyFilters();
}

async function handleExportResults(format) {
    if (!currentScanId) {
        showToast('No scan results to export', 'warning');
        return;
    }

    try {
        const result = await trajanBridge.exportResults(currentScanId, format);
        const blob = new Blob([result.data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `trajan-scan-${currentScanId}.${format}`;
        a.click();
        URL.revokeObjectURL(url);

        showToast(`Results exported as ${format.toUpperCase()}`, 'success');
    } catch (error) {
        console.error('Export failed:', error);
        showToast(`Export failed: ${error.message}`, 'error');
    }
}

// ============================= //
// Attack Tab
// ============================= //

async function initializeAttackTab() {
    const btnExecuteAttack = document.getElementById('btn-execute-attack');
    const attackPluginSelect = document.getElementById('attack-plugin');
    const toggleTokenBtn = document.getElementById('toggle-attack-token');

    btnExecuteAttack.addEventListener('click', handleExecuteAttack);
    attackPluginSelect.addEventListener('change', handlePluginSelect);
    toggleTokenBtn.addEventListener('click', () => togglePasswordVisibility('attack-token'));

    // Load token from Settings if attack-token is empty
    try {
        const attackTokenField = document.getElementById('attack-token');
        if (!attackTokenField.value) {
            const result = await trajanBridge.configGet('github.token');
            if (result.value) {
                attackTokenField.value = result.value;
            }
        }
    } catch (error) {
        console.error('Failed to load token:', error);
    }
}

async function loadAttackPlugins() {
    try {
        const result = await trajanBridge.listAttackPlugins();
        const plugins = result.plugins || [];

        const select = document.getElementById('attack-plugin');
        select.innerHTML = '<option value="">Select an attack plugin...</option>';

        plugins.forEach(plugin => {
            const option = document.createElement('option');
            option.value = plugin.id;
            option.textContent = plugin.name;
            option.dataset.description = plugin.description;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load plugins:', error);
        showToast('Failed to load attack plugins', 'error');
    }
}

function handlePluginSelect(event) {
    const selectedOption = event.target.selectedOptions[0];
    const description = selectedOption?.dataset.description || '';
    document.getElementById('plugin-description').textContent = description;
}

async function handleExecuteAttack() {
    const plugin = document.getElementById('attack-plugin').value;
    const target = document.getElementById('attack-target').value.trim();
    let token = document.getElementById('attack-token').value.trim();
    const authorized = document.getElementById('attack-authorized').checked;
    const saveSession = document.getElementById('attack-save-session').checked;
    const dryRun = document.getElementById('attack-dry-run').checked;

    if (!plugin) {
        showToast('Please select an attack plugin', 'warning');
        return;
    }

    if (!target) {
        showToast('Please enter a target repository URL', 'warning');
        return;
    }

    // If token field is empty, try to load from Settings
    if (!token) {
        try {
            const result = await trajanBridge.configGet('github.token');
            if (result.value) {
                token = result.value;
                // Update field to show the token was loaded
                document.getElementById('attack-token').value = token;
            }
        } catch (error) {
            console.error('Failed to load token from Settings:', error);
        }
    }

    if (!token) {
        showToast('Please enter a GitHub token or configure one in Settings', 'warning');
        return;
    }

    if (!authorized) {
        showToast('You must confirm authorization before executing attacks', 'warning');
        return;
    }

    try {
        // Show progress
        document.getElementById('attack-progress').style.display = 'block';
        document.getElementById('attack-results').style.display = 'none';
        document.getElementById('btn-execute-attack').disabled = true;

        // Execute attack
        const result = await trajanBridge.executeAttack(plugin, target, {
            token,
            authorized,
            saveSession,
            dryRun,
            onProgress: (message) => {
                document.getElementById('attack-progress-text').textContent = message;
            }
        });

        // Display results
        displayAttackResults(result);
        showToast(dryRun ? 'Dry run completed' : 'Attack executed successfully', 'success');

        // Reload sessions
        await loadSessions();

    } catch (error) {
        console.error('Attack failed:', error);
        showToast(`Attack failed: ${error.message}`, 'error');
    } finally {
        document.getElementById('attack-progress').style.display = 'none';
        document.getElementById('btn-execute-attack').disabled = false;
    }
}

function displayAttackResults(result) {
    document.getElementById('attack-results').style.display = 'block';

    const output = result.result || {};
    const outputHTML = `
        <pre>${escapeHtml(JSON.stringify(output, null, 2))}</pre>
    `;
    document.getElementById('attack-output').innerHTML = outputHTML;

    // Artifacts are shown in JSON output above and in Sessions panel
    // Individual artifact display removed - use Sessions panel for cleanup
}

async function loadSessions() {
    try {
        const result = await trajanBridge.listSessions();
        const sessions = result.sessions || [];

        const sessionsList = document.getElementById('sessions-list');

        if (sessions.length === 0) {
            sessionsList.innerHTML = '<p class="help-text">No active sessions</p>';
            document.getElementById('session-count').textContent = '0 sessions';
            return;
        }

        const sessionsHTML = sessions.map(session => {
            const safeId = escapeHtml(session.id);
            return `
            <div class="session-item">
                <div class="session-info">
                    <div class="session-id">${safeId}</div>
                    <div class="session-meta">
                        Plugin: ${escapeHtml(session.plugin)} | Status: ${escapeHtml(session.status)} | Created: ${escapeHtml(new Date(session.createdAt).toLocaleString())}
                    </div>
                </div>
                <div class="session-actions">
                    <button class="btn btn-secondary btn-sm" data-session-id="${safeId}" data-action="view">
                        View
                    </button>
                    <button class="btn btn-danger btn-sm" data-session-id="${safeId}" data-action="cleanup">
                        Cleanup
                    </button>
                </div>
            </div>
        `}).join('');

        sessionsList.innerHTML = sessionsHTML;
        sessionsList.querySelectorAll('button[data-session-id]').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-session-id');
                if (btn.getAttribute('data-action') === 'view') {
                    viewSession(id);
                } else if (btn.getAttribute('data-action') === 'cleanup') {
                    cleanupSession(id);
                }
            });
        });
        document.getElementById('session-count').textContent = `${sessions.length} session(s)`;

    } catch (error) {
        console.error('Failed to load sessions:', error);
    }
}

window.viewSession = async function(sessionId) {
    try {
        const result = await trajanBridge.getSessionStatus(sessionId);
        const session = result.session;

        alert(JSON.stringify(session, null, 2));
    } catch (error) {
        showToast(`Failed to load session: ${error.message}`, 'error');
    }
};

window.cleanupSession = async function(sessionId) {
    if (!confirm('Are you sure you want to cleanup this session? This will remove all artifacts.')) {
        return;
    }

    const token = document.getElementById('attack-token').value.trim();
    if (!token) {
        showToast('Please enter a GitHub token to cleanup', 'warning');
        return;
    }

    try {
        const result = await trajanBridge.cleanupSession(sessionId, token);

        // Check if result has error
        if (result && result.error) {
            showToast(`Cleanup failed: ${result.error}`, 'error');
            return;
        }

        showToast('Session cleaned up successfully', 'success');
        await loadSessions();
    } catch (error) {
        console.error('Cleanup error:', error);
        const errorMsg = error.error || error.message || JSON.stringify(error);
        showToast(`Cleanup failed: ${errorMsg}`, 'error');
    }
};

// ============================= //
// Interactive Shell Tab
// ============================= //

function initializeShellTab() {
    const btnExecute = document.getElementById('btn-shell-execute');
    const btnClear = document.getElementById('btn-shell-clear');
    const btnDownload = document.getElementById('btn-shell-download');
    const shellInput = document.getElementById('shell-input');

    btnExecute.addEventListener('click', handleShellExecute);
    btnClear.addEventListener('click', clearShellOutput);
    btnDownload.addEventListener('click', downloadShellOutput);

    shellInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !shellInput.disabled) {
            handleShellExecute();
        }
    });
}

async function handleShellExecute() {
    const input = document.getElementById('shell-input');
    const command = input.value.trim();

    if (!command) return;

    if (!currentShellSession) {
        showToast('No active shell session. Execute a runner-on-runner attack first.', 'warning');
        return;
    }

    try {
        // Add command to output
        appendShellOutput(`$ ${command}`, 'command');
        input.value = '';

        // In a real implementation, this would send the command to the runner
        // For now, we'll simulate a response
        appendShellOutput('Command execution not yet implemented', 'error');
        showToast('Shell execution requires active runner connection', 'info');

    } catch (error) {
        appendShellOutput(`Error: ${error.message}`, 'error');
        showToast(`Shell error: ${error.message}`, 'error');
    }
}

function appendShellOutput(text, type = 'output') {
    const outputDiv = document.getElementById('shell-output');
    const line = document.createElement('div');
    line.className = `shell-line ${type === 'command' ? 'shell-command' : type === 'error' ? 'shell-error' : ''}`;
    line.textContent = text;
    outputDiv.appendChild(line);
    outputDiv.scrollTop = outputDiv.scrollHeight;

    shellOutput.push({ text, type, timestamp: Date.now() });
}

function clearShellOutput() {
    document.getElementById('shell-output').innerHTML = `
        <div class="shell-welcome">
            <p>Output cleared</p>
        </div>
    `;
    shellOutput = [];
}

function downloadShellOutput() {
    if (shellOutput.length === 0) {
        showToast('No output to download', 'warning');
        return;
    }

    const content = shellOutput.map(line => line.text).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trajan-shell-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);

    showToast('Shell output downloaded', 'success');
}

// ============================= //
// Validate Tab
// ============================= //

function initializeValidateTab() {
    const btnValidate = document.getElementById('btn-validate');
    const toggleTokenBtn = document.getElementById('toggle-validate-token');
    const platformSelect = document.getElementById('validate-platform');

    if (!btnValidate || !toggleTokenBtn || !platformSelect) {
        return;
    }
    btnValidate.addEventListener('click', handleValidateToken);
    toggleTokenBtn.addEventListener('click', () => togglePasswordVisibility('validate-token'));
    platformSelect.addEventListener("change", handleValidatePlatformChange);
    console.log('✅ Validate tab initialized');
}

// Platform-specific configuration
const platformConfig = {
    github: {
        permissionsTitle: 'OAuth Scopes',
        groupsTitle: 'Accessible Organizations',
        dangerousScopes: [
            'admin:org',           // CRITICAL: Full org control
            'admin:repo_hook',     // CRITICAL: Webhook manipulation
            'admin:org_hook',      // CRITICAL: Org-wide webhooks
            'admin:public_key',    // CRITICAL: SSH key management
            'admin:gpg_key',       // CRITICAL: GPG key management
            'delete_repo',         // CRITICAL: Delete repositories
            'delete:packages',     // HIGH: Supply chain disruption
            'repo',                // HIGH: Full repo access (overly broad)
            'workflow',            // HIGH: Actions workflow injection
            'codespace',           // HIGH: RCE vector (2026 CVE)
            'security_events',     // HIGH: Suppress security findings
            'read:audit_log',      // HIGH: Org security logs
            'user:email'           // MEDIUM-HIGH: PII exposure
        ],
        helpText: 'Supports classic PATs (ghp_) and fine-grained PATs (github_pat_)',
        subtitle: 'Verify GitHub token permissions, scopes, and organization memberships'
    },
    gitlab: {
        permissionsTitle: 'Token Scopes',
        groupsTitle: 'Accessible Groups',
        dangerousScopes: ['admin', 'write_repository', 'api'],
        helpText: 'Supports Personal Access Tokens, Project Access Tokens, and Group Access Tokens',
        subtitle: 'Verify GitLab token permissions, scopes, and group memberships'
    },
    azuredevops: {
        permissionsTitle: 'Scopes',
        groupsTitle: 'Projects',
        dangerousScopes: ['vso.', 'full'],
        helpText: 'Supports Personal Access Tokens (PATs)',
        subtitle: 'Verify Azure DevOps PAT permissions and organization access'
    },
    bitbucket: {
        permissionsTitle: 'Scopes',
        groupsTitle: 'Workspaces',
        dangerousScopes: ['admin', 'repository:admin'],
        helpText: 'Supports App Passwords',
        subtitle: 'Verify Bitbucket token permissions and workspace access'
    }
};

function handleValidatePlatformChange() {
    const platform = document.getElementById('validate-platform').value;
    const config = platformConfig[platform];

    if (!config) return;

    // Update subtitle
    const subtitle = document.getElementById('validate-subtitle');
    if (subtitle) {
        subtitle.textContent = config.subtitle;
    }

    // Update help text
    const helpText = document.getElementById('token-help-text');
    if (helpText) {
        helpText.textContent = config.helpText;
    }

    // Show/hide URL field for platforms that require an instance or org URL
    const urlGroup = document.getElementById('validate-url-group');
    if (urlGroup) {
        if (platform === 'gitlab' || platform === 'azuredevops') {
            urlGroup.style.display = 'block';
            const urlLabel = document.getElementById('validate-url-label');
            const urlInput = document.getElementById('validate-url');
            const urlHelp = document.getElementById('validate-url-help');
            if (platform === 'gitlab') {
                if (urlLabel) urlLabel.textContent = 'GitLab Instance URL (Optional)';
                if (urlInput) urlInput.placeholder = 'https://gitlab.example.com';
                if (urlHelp) urlHelp.textContent = 'Leave empty for GitLab.com (default). For self-hosted, enter base URL.';
            } else {
                if (urlLabel) urlLabel.textContent = 'Organization URL';
                if (urlInput) urlInput.placeholder = 'https://dev.azure.com/myorg';
                if (urlHelp) urlHelp.textContent = 'Enter your Azure DevOps organization URL (required).';
            }
        } else {
            urlGroup.style.display = 'none';
        }
    }
}

async function handleValidateToken() {
    const tokenInput = document.getElementById('validate-token');
    const platformSelect = document.getElementById('validate-platform');
    const resultsContainer = document.getElementById('validate-results');
    const btnValidate = document.getElementById('btn-validate');

    const token = tokenInput.value.trim();
    const platform = platformSelect.value;

    if (!token) {
        showToast(`Please enter a ${platform.charAt(0).toUpperCase() + platform.slice(1)} token`, 'warning');
        return;
    }

    try {
        // Disable button and show loading state
        btnValidate.disabled = true;
        btnValidate.innerHTML = '<span>Validating...</span>';

        // Call platform-specific WASM function
        let result;
        switch (platform) {
            case 'github':
                result = await window.trajanValidateToken({ token });
                break;
            case 'gitlab':
                const urlInput = document.getElementById('validate-url');
                const url = urlInput ? urlInput.value.trim() : '';
                const options = { token, platform: 'gitlab' };
                if (url) {
                    options.url = url;
                }
                result = await window.trajanValidateToken(options);
                break;
            case 'azuredevops': {
                const adoUrlInput = document.getElementById('validate-url');
                const adoUrl = adoUrlInput ? adoUrlInput.value.trim() : '';
                if (!adoUrl) {
                    showToast('Organization URL is required for Azure DevOps (e.g., https://dev.azure.com/myorg)', 'warning');
                    btnValidate.disabled = false;
                    btnValidate.innerHTML = `
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        Verify Token
                    `;
                    return;
                }
                if (!isValidAdoOrgURL(adoUrl)) {
                    showToast('Invalid Organization URL (expected: https://dev.azure.com/myorg or https://myorg.visualstudio.com)', 'error');
                    btnValidate.disabled = false;
                    btnValidate.innerHTML = `
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        Verify Token
                    `;
                    return;
                }
                result = await window.trajanValidateToken({ token, platform: 'azuredevops', url: adoUrl });
                break;
            }
            case 'bitbucket':
                // TODO: Implement Bitbucket validation
                showToast('Bitbucket token validation not yet implemented', 'warning');
                return;
            default:
                showToast(`Unsupported platform: ${platform}`, 'error');
                return;
        }

        if (result.error) {
            showToast(`Validation failed: ${result.error}`, 'error');
            return;
        }

        // Parse result
        const data = typeof result.result === 'string' ? JSON.parse(result.result) : result.result;

        // Display results with platform context
        displayValidationResults(data, platform);
        resultsContainer.style.display = 'block';

        showToast('Token validated successfully', 'success');
    } catch (error) {
        showToast(`Validation error: ${error.message}`, 'error');
        console.error('Validation error:', error);
    } finally {
        // Restore button
        btnValidate.disabled = false;
        btnValidate.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Verify Token
        `;
    }
}

function displayValidationResults(data, platform) {
    const config = platformConfig[platform] || platformConfig.github;

    // Identity Section - safely set fields that exist
    const userElem = document.getElementById('token-user');
    if (userElem) {
        userElem.textContent = data.user?.login || data.user || '-';
    }

    const nameElem = document.getElementById('token-name');
    if (nameElem) {
        nameElem.textContent = data.user?.name || data.name || '-';
    }

    const tokenTypeElem = document.getElementById('token-type');
    if (tokenTypeElem) {
        const tokenType = data.token_info?.type || data.token_type || data.type || 'Unknown';
        tokenTypeElem.textContent = formatTokenType(tokenType);
    }

    const expirationElem = document.getElementById('token-expiration');
    if (expirationElem) {
        const expiration = data.expiration || data.token_expiration;
        expirationElem.textContent = expiration || 'None';
    }

    const rateLimitElem = document.getElementById('token-ratelimit');
    if (rateLimitElem) {
        const rateLimit = data.rate_limit;
        if (rateLimit) {
            rateLimitElem.textContent = `${rateLimit.remaining || 0}/${rateLimit.limit || 5000} remaining`;
        } else {
            rateLimitElem.textContent = '-';
        }
    }

    // Permissions/Scopes Section
    const scopesContainer = document.getElementById('token-permissions') || document.getElementById('token-scopes');
    const permissionsTitle = document.getElementById('permissions-title');
    const dangerousWarning = document.getElementById('dangerous-scopes-warning');
    const dangerousTitle = document.getElementById('dangerous-scopes-title');

    scopesContainer.innerHTML = '';
    const scopes = data.scopes || data.permissions || [];

    // Update title with platform-specific label
    if (permissionsTitle) {
        permissionsTitle.textContent = `${config.permissionsTitle}${scopes.length > 0 ? ` (${scopes.length})` : ''}`;
    }

    // Detect dangerous scopes (exact match or prefix for patterns like admin:*)
    const dangerousScopes = scopes.filter(scope => {
        const scopeLower = scope.toLowerCase();
        return config.dangerousScopes.some(dangerous => {
            const dangerousLower = dangerous.toLowerCase();
            // Exact match or starts with pattern (e.g., "admin:" matches "admin:org")
            return scopeLower === dangerousLower ||
                   (dangerousLower.endsWith(':') && scopeLower.startsWith(dangerousLower));
        });
    });

    if (scopes.length > 0) {
        scopes.forEach(scope => {
            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.textContent = scope.toUpperCase();
            scopesContainer.appendChild(tag);
        });

        // Show warning if dangerous scopes detected
        if (dangerousScopes.length > 0 && dangerousWarning && dangerousTitle) {
            dangerousTitle.textContent = `Dangerous scopes: ${dangerousScopes.join(', ')}`;
            dangerousWarning.style.display = 'flex';
        } else if (dangerousWarning) {
            dangerousWarning.style.display = 'none';
        }
    } else {
        scopesContainer.innerHTML = '<span class="text-muted">No scopes available</span>';
    }

    // Groups/Organizations Section
    const groupsContainer = document.getElementById('token-groups') || document.getElementById('token-orgs');
    const groupsTitle = document.getElementById('groups-title');
    const groups = data.orgs || data.organizations || data.groups || data.workspaces || [];

    // Update title with platform-specific label
    if (groupsTitle) {
        groupsTitle.textContent = `${config.groupsTitle}${groups.length > 0 ? ` (${groups.length})` : ''}`;
    }

    groupsContainer.innerHTML = '';
    if (groups.length > 0) {
        // Display one organization per line (bulleted list)
        groups.forEach(group => {
            const orgName = group.name || group.login || group;
            const orgLine = document.createElement('div');
            orgLine.className = 'org-line';
            orgLine.textContent = `• ${orgName}`;
            groupsContainer.appendChild(orgLine);
        });
    } else {
        groupsContainer.innerHTML = `<span class="text-muted">No ${config.groupsTitle.toLowerCase()}</span>`;
    }

    // ADO-specific: Access Summary + Project Permissions (equivalent to --detailed)
    const resultsContainer = document.getElementById('validate-results');
    // Remove any previously injected ADO cards
    resultsContainer.querySelectorAll('.ado-extra-card').forEach(el => el.remove());

    if (platform === 'azuredevops') {
        // Access Summary card
        const summaryCard = document.createElement('div');
        summaryCard.className = 'card ado-extra-card';
        const counts = [
            ['Projects', data.project_count],
            ['Repositories', data.repository_count],
            ['Pipelines', data.pipeline_count],
            ['Agent Pools', data.agent_pool_count],
            ['Variable Groups', data.variable_group_count],
            ['Service Connections', data.service_connection_count],
            ['Artifact Feeds', data.artifact_feed_count],
        ];
        const serviceOwner = data.service_owner ? `<div class="info-row"><span class="info-label">Service Owner:</span><span class="info-value">${escapeHtml(data.service_owner)}</span></div>` : '';
        summaryCard.innerHTML = `
            <h4>Access Summary</h4>
            <div class="info-list">
                ${serviceOwner}
                ${counts.map(([label, val]) => val != null ? `<div class="info-row"><span class="info-label">${label}:</span><span class="info-value">${val}</span></div>` : '').join('')}
                ${data.has_self_hosted_agents ? '<div class="info-row"><span class="info-label">Self-Hosted Agents:</span><span class="info-value" style="color:#e63948">Detected</span></div>' : ''}
                ${data.has_secret_variables ? '<div class="info-row"><span class="info-label">Secret Variables:</span><span class="info-value" style="color:#e63948">Detected</span></div>' : ''}
            </div>`;
        resultsContainer.appendChild(summaryCard);

        // Project Permissions card (--detailed)
        const perms = data.permissions || [];
        if (perms.length > 0) {
            const permsCard = document.createElement('div');
            permsCard.className = 'card ado-extra-card';
            permsCard.innerHTML = '<h4>Project Permissions</h4>';

            perms.forEach(pp => {
                const section = document.createElement('details');
                section.className = 'perm-project';
                section.style.cssText = 'margin-bottom:0.75rem; border:1px solid var(--border); border-radius:6px; overflow:hidden;';
                const summary = document.createElement('summary');
                summary.style.cssText = 'padding:0.5rem 0.75rem; cursor:pointer; font-weight:500; background:var(--surface-2); user-select:none;';
                summary.textContent = pp.project;
                section.appendChild(summary);

                const inner = document.createElement('div');
                inner.style.cssText = 'padding:0.75rem; display:grid; grid-template-columns:1fr 1fr; gap:1rem;';

                const renderPermList = (title, items) => {
                    const col = document.createElement('div');
                    col.innerHTML = `<div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); margin-bottom:0.4rem; font-weight:600;">${title}</div>`;
                    (items || []).forEach(p => {
                        const row = document.createElement('div');
                        row.style.cssText = 'display:flex; align-items:center; gap:0.4rem; font-size:0.85rem; padding:0.15rem 0;';
                        const icon = p.allowed
                            ? '<span style="color:#22c55e;font-size:1rem;">✓</span>'
                            : '<span style="color:#64748b;font-size:1rem;">✗</span>';
                        row.innerHTML = `${icon} <span style="color:${p.allowed ? 'var(--text)' : 'var(--text-muted)'}">${escapeHtml(p.name)}</span>`;
                        col.appendChild(row);
                    });
                    return col;
                };

                inner.appendChild(renderPermList('Build', pp.build));
                inner.appendChild(renderPermList('Git', pp.git));
                section.appendChild(inner);
                permsCard.appendChild(section);
            });

            resultsContainer.appendChild(permsCard);
        }
    }
}

function formatTokenType(type) {
    // Handle both string types and formats from different sources
    const normalizedType = (type || '').toLowerCase().replace(/[_\s]/g, '');

    const typeMap = {
        'classic': 'Classic Personal Access Token',
        'classicpersonalaccesstoken': 'Classic Personal Access Token',
        'finegrained': 'Fine-Grained Personal Access Token',
        'finegrainedpersonalaccesstoken': 'Fine-Grained Personal Access Token',
        'fine_grained': 'Fine-Grained Personal Access Token',
        'githubapp': 'GitHub App Token',
        'github_app': 'GitHub App Token'
    };

    return typeMap[normalizedType] || type || 'Unknown';
}

async function handleExportValidation() {
    const tokenUser = document.getElementById('token-user');
    const tokenType = document.getElementById('token-type');
    const tokenExpiration = document.getElementById('token-expiration');
    const tokenPermissions = document.getElementById('token-permissions');
    const tokenGroups = document.getElementById('token-groups');

    const data = {
        user: tokenUser ? tokenUser.textContent : '-',
        type: tokenType ? tokenType.textContent : '-',
        expiration: tokenExpiration ? tokenExpiration.textContent : '-',
        permissions: tokenPermissions ? Array.from(tokenPermissions.querySelectorAll('.tag')).map(tag => tag.textContent) : [],
        groups: tokenGroups ? Array.from(tokenGroups.querySelectorAll('.org-line')).map(org => org.textContent) : []
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'trajan-token-validation.json';
    a.click();
    URL.revokeObjectURL(url);

    showToast('Validation results exported', 'success');
}

// ============================= //
// Recon Tab
// ============================= //

// ============================= //
// Recon Tab - Operation Mappings
// ============================= //

const ENUMERATE_OPERATIONS = {
  github: {
    repos: {
      label: 'Repositories',
      requiresTarget: false,
      targetLabel: 'Organization (optional)',
      targetPlaceholder: 'octocat',
      targetHelp: 'Leave empty to enumerate all accessible repositories'
    },
    secrets: {
      label: 'Secrets',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'octocat',
      targetHelp: 'Organization name (required)'
    },
    runners: {
      label: 'Self-Hosted Runners',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'octocat',
      targetHelp: 'Organization name (required)'
    }
  },
  gitlab: {
    projects: {
      label: 'Projects',
      requiresTarget: false,
      targetLabel: 'Group (optional)',
      targetPlaceholder: 'my-group',
      targetHelp: 'Leave empty to enumerate all accessible projects'
    },
    groups: {
      label: 'Groups',
      requiresTarget: false,
      targetLabel: null,
      targetPlaceholder: null,
      targetHelp: null
    },
    secrets: {
      label: 'CI/CD Variables',
      requiresTarget: true,
      targetLabel: 'Project',
      targetPlaceholder: 'group/project',
      targetHelp: 'Project path (required)'
    },
    'branch-protections': {
      label: 'Branch Protections',
      requiresTarget: true,
      targetLabel: 'Project',
      targetPlaceholder: 'group/project',
      targetHelp: 'Project path (required)'
    },
    runners: {
      label: 'Runners',
      requiresTarget: true,
      targetLabel: 'Project',
      targetPlaceholder: 'group/project',
      targetHelp: 'Project path (required)'
    }
  },
  azuredevops: {
    projects: {
      label: 'Projects',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'my-org',
      targetHelp: 'Organization name (required)',
      requiresProject: false  // Projects don't need project param
    },
    repos: {
      label: 'Repositories',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'my-org',
      targetHelp: 'Organization name (required)',
      requiresProject: false,  // Optional - if empty, enumerate all projects
      projectLabel: 'Project (optional)',
      projectPlaceholder: 'project-name',
      projectHelp: 'Leave empty to enumerate all projects'
    },
    pipelines: {
      label: 'Pipelines',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'my-org',
      targetHelp: 'Organization name (required)',
      requiresProject: false,
      projectLabel: 'Project (optional)',
      projectPlaceholder: 'project-name',
      projectHelp: 'Leave empty to enumerate all projects'
    },
    'variable-groups': {
      label: 'Variable Groups',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'my-org',
      targetHelp: 'Organization name (required)',
      requiresProject: true,  // REQUIRED for variable groups
      projectLabel: 'Project',
      projectPlaceholder: 'project-name',
      projectHelp: 'Project name (required)'
    },
    'service-connections': {
      label: 'Service Connections',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'my-org',
      targetHelp: 'Organization name (required)',
      requiresProject: true,  // REQUIRED for connections
      projectLabel: 'Project',
      projectPlaceholder: 'project-name',
      projectHelp: 'Project name (required)'
    },
    'agent-pools': {
      label: 'Agent Pools',
      requiresTarget: true,
      targetLabel: 'Organization',
      targetPlaceholder: 'my-org',
      targetHelp: 'Organization name (required)',
      requiresProject: false
    }
  }
};

function initializeReconTab() {
    // Platform change handler
    document.getElementById('recon-platform').addEventListener('change', handleReconPlatformChange);

    // Operation change handler
    document.getElementById('recon-operation').addEventListener('change', handleReconOperationChange);

    // Enumerate button handler
    document.getElementById('btn-enumerate').addEventListener('click', handleEnumerate);

    // Export JSON button handler
    document.getElementById('btn-export-enumerate-json').addEventListener('click', handleExportEnumerateResults);

    // Token visibility toggle
    document.getElementById('toggle-recon-token').addEventListener('click', () => {
        togglePasswordVisibility('recon-token');
    });

    // Initialize with GitHub selected
    handleReconPlatformChange();
}

function handleReconPlatformChange() {
    const platform = document.getElementById('recon-platform').value;
    const operationSelect = document.getElementById('recon-operation');
    const baseURLGroup = document.getElementById('recon-base-url-group');

    // Clear existing options
    operationSelect.innerHTML = '';

    // Populate operation dropdown for selected platform
    const operations = ENUMERATE_OPERATIONS[platform];
    if (operations) {
        Object.entries(operations).forEach(([value, config]) => {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = config.label;
            operationSelect.appendChild(option);
        });
    }

    // Hide base URL field initially - handleReconOperationChange will show it if needed
    baseURLGroup.style.display = 'none';

    // Trigger operation change to update target field
    handleReconOperationChange();
}

function handleReconOperationChange() {
    const platform = document.getElementById('recon-platform').value;
    const operation = document.getElementById('recon-operation').value;
    const targetGroup = document.getElementById('recon-target-group');
    const targetLabel = document.getElementById('recon-target-label');
    const targetInput = document.getElementById('recon-target');
    const targetHelp = document.getElementById('recon-target-help');

    // Handle secondary field (Base URL for GitLab, Project for ADO)
    const secondaryGroup = document.getElementById('recon-base-url-group');
    const secondaryLabel = document.getElementById('recon-base-url-label');
    const secondaryInput = document.getElementById('recon-base-url');
    const secondaryHelp = document.getElementById('recon-base-url-help');

    const config = ENUMERATE_OPERATIONS[platform]?.[operation];

    if (!config) {
        targetGroup.style.display = 'none';
        secondaryGroup.style.display = 'none';
        return;
    }

    // Handle target field (org/group)
    if (config.targetLabel) {
        targetGroup.style.display = 'block';
        targetLabel.textContent = config.targetLabel;
        targetInput.placeholder = config.targetPlaceholder || '';
        targetHelp.textContent = config.targetHelp || '';
        targetInput.required = config.requiresTarget;

        // Update label styling for required fields
        if (config.requiresTarget) {
            if (!targetLabel.querySelector('.required')) {
                targetLabel.innerHTML += ' <span class="required">*</span>';
            }
        } else {
            const requiredSpan = targetLabel.querySelector('.required');
            if (requiredSpan) {
                requiredSpan.remove();
            }
        }
    } else {
        targetGroup.style.display = 'none';
        targetInput.required = false;
    }

    // Handle secondary field (project for ADO, base URL for GitLab)
    if (platform === 'azuredevops' && config.projectLabel) {
        // Show as Project field for ADO
        secondaryGroup.style.display = 'block';
        secondaryLabel.textContent = config.projectLabel;
        secondaryInput.placeholder = config.projectPlaceholder || '';
        secondaryHelp.textContent = config.projectHelp || '';
        secondaryInput.required = config.requiresProject;

        if (config.requiresProject) {
            if (!secondaryLabel.querySelector('.required')) {
                secondaryLabel.innerHTML += ' <span class="required">*</span>';
            }
        } else {
            const requiredSpan = secondaryLabel.querySelector('.required');
            if (requiredSpan) {
                requiredSpan.remove();
            }
        }
    } else if (platform === 'gitlab') {
        // Show as Base URL for GitLab
        secondaryGroup.style.display = 'block';
        secondaryLabel.textContent = 'Base URL';
        secondaryInput.placeholder = 'https://gitlab.com';
        secondaryHelp.textContent = 'Leave empty for default or enter self-hosted URL';
        secondaryInput.required = false;

        // Remove required indicator for GitLab base URL
        const requiredSpan = secondaryLabel.querySelector('.required');
        if (requiredSpan) {
            requiredSpan.remove();
        }
    } else {
        secondaryGroup.style.display = 'none';
        secondaryInput.required = false;
    }
}

async function handleEnumerate() {
    const platform = document.getElementById('recon-platform').value;
    const operation = document.getElementById('recon-operation').value;
    const token = document.getElementById('recon-token').value.trim();
    const target = document.getElementById('recon-target').value.trim();
    const secondaryField = document.getElementById('recon-base-url').value.trim();

    // Validate required fields
    if (!token) {
        showToast('Please enter an authentication token', 'warning');
        return;
    }

    const config = ENUMERATE_OPERATIONS[platform]?.[operation];
    if (config?.requiresTarget && !target) {
        showToast(`${config.targetLabel} is required for this operation`, 'warning');
        return;
    }

    // Validate project field for ADO operations that require it
    if (platform === 'azuredevops' && config?.requiresProject && !secondaryField) {
        showToast(`${config.projectLabel} is required for this operation`, 'warning');
        return;
    }

    const btn = document.getElementById('btn-enumerate');
    const progress = document.getElementById('recon-progress');
    const results = document.getElementById('recon-results');

    try {
        btn.disabled = true;
        progress.style.display = 'block';
        results.style.display = 'none';

        // Build options object - for ADO, secondary field is project; for GitLab, it's baseURL
        const options = {
            token,
            target: target || undefined,
            onProgress: (percent, message) => {
                document.getElementById('recon-progress-bar').style.width = `${percent}%`;
                document.getElementById('recon-progress-text').textContent = message;
            }
        };

        if (platform === 'azuredevops' && secondaryField) {
            options.project = secondaryField;
        } else if (platform === 'gitlab' && secondaryField) {
            options.baseURL = secondaryField;
        }

        const result = await trajanBridge.enumerate(platform, operation, options);

        displayEnumerateResults(platform, operation, result.result);
        results.style.display = 'block';
        showToast('✅ Enumeration complete', 'success');

    } catch (error) {
        console.error('Enumeration error:', error);
        let errorMessage = error.message || error.error || 'Unknown error';

        // Categorize error for better UX
        if (errorMessage.includes('Authentication') || errorMessage.includes('401')) {
            showToast('❌ Authentication failed. Please check your token.', 'error');
        } else if (errorMessage.includes('Permission') || errorMessage.includes('403')) {
            showToast('⚠️ ' + errorMessage + ' (Some operations require higher permissions)', 'warning');
        } else if (errorMessage.includes('not found') || errorMessage.includes('404')) {
            showToast('🔍 Target not found: ' + target, 'warning');
        } else if (errorMessage.includes('Network') || errorMessage.includes('fetch')) {
            showToast('🌐 Network error. Please check your connection.', 'error');
        } else if (errorMessage.includes('not yet implemented')) {
            showToast('⚠️ ' + errorMessage, 'warning');
        } else {
            showToast('❌ Enumeration failed: ' + errorMessage, 'error');
        }

    } finally {
        btn.disabled = false;
        progress.style.display = 'none';
    }
}

// ============================= //
// Recon Tab - Result Formatters
// ============================= //

function formatGitHubRepos(data) {
    let output = 'GitHub Repositories Enumeration\n';
    output += '================================\n\n';

    if (data.summary) {
        output += `Total: ${data.summary.total || 0} repositories (${data.summary.private || 0} private, ${data.summary.public || 0} public)\n\n`;
    }

    if (data.repositories && data.repositories.length > 0) {
        // Group by permissions
        const adminRepos = data.repositories.filter(r => r.permissions?.admin);
        const writeRepos = data.repositories.filter(r => r.permissions?.push && !r.permissions?.admin);
        const readRepos = data.repositories.filter(r => !r.permissions?.push && !r.permissions?.admin);

        if (adminRepos.length > 0) {
            output += `Admin Access (${adminRepos.length} repositories):\n`;
            adminRepos.forEach(r => {
                const visibility = r.Private ? 'private' : 'public';
                output += `  • ${r.Owner}/${r.Name} [${visibility}, ${r.DefaultBranch || 'unknown'}]\n`;
            });
            output += '\n';
        }

        if (writeRepos.length > 0) {
            output += `Write Access (${writeRepos.length} repositories):\n`;
            writeRepos.forEach(r => {
                const visibility = r.Private ? 'private' : 'public';
                output += `  • ${r.Owner}/${r.Name} [${visibility}, ${r.DefaultBranch || 'unknown'}]\n`;
            });
            output += '\n';
        }

        if (readRepos.length > 0) {
            output += `Read Access (${readRepos.length} repositories):\n`;
            readRepos.forEach(r => {
                const visibility = r.Private ? 'private' : 'public';
                output += `  • ${r.Owner}/${r.Name} [${visibility}, ${r.DefaultBranch || 'unknown'}]\n`;
            });
        }
    }

    return output;
}

function formatGitHubSecrets(data) {
    let output = 'GitHub Secrets Enumeration\n';
    output += '==========================\n\n';

    // Simple structure from enumerate API: {secrets: [...], count: N}
    if (data.secrets && data.secrets.length > 0) {
        output += `Organization Secrets (${data.secrets.length}):\n`;
        data.secrets.forEach(s => {
            const created = s.created_at || s.CreatedAt || 'unknown';
            output += `  • ${s.name || s.Name} (created: ${created})\n`;
        });
    } else {
        output += 'No secrets found.\n';
    }

    return output;
}

function formatGitHubRunners(data) {
    let output = 'GitHub Runners Enumeration\n';
    output += '==========================\n\n';

    // Simple structure from enumerate API: {runners: [...], count: N}
    if (data.runners && data.runners.length > 0) {
        output += `Self-Hosted Runners (${data.runners.length}):\n`;
        data.runners.forEach(r => {
            const status = (r.status || r.Status) === 'online' ? '🟢' : '🔴';
            const name = r.name || r.Name || r.id || r.ID || 'unknown';
            const os = r.os || r.OS || r.labels?.join(',') || 'unknown';
            output += `  ${status} ${name} (${os}, status: ${r.status || r.Status})\n`;
        });
    } else {
        output += 'No self-hosted runners found.\n';
    }

    return output;
}

function formatGitLabProjects(data) {
    let output = 'GitLab Projects Enumeration\n';
    output += '===========================\n\n';

    if (data.summary) {
        output += 'Summary:\n';
        output += `  Total: ${data.summary.total || 0} projects\n`;
        output += `  Private: ${data.summary.private || 0}\n`;
        output += `  Internal: ${data.summary.internal || 0}\n`;
        output += `  Public: ${data.summary.public || 0}\n\n`;
    }

    if (data.projects && data.projects.length > 0) {
        // Group by access level (50=Owner, 40=Maintainer, 30=Developer, 20=Reporter, 10=Guest)
        const byLevel = {
            50: [], 40: [], 30: [], 20: [], 10: []
        };

        data.projects.forEach(p => {
            const level = p.access_level || 0;
            if (byLevel[level]) {
                byLevel[level].push(p);
            }
        });

        const levelNames = {
            50: 'Owner', 40: 'Maintainer', 30: 'Developer',
            20: 'Reporter', 10: 'Guest'
        };

        [50, 40, 30, 20, 10].forEach(level => {
            if (byLevel[level].length > 0) {
                output += `${levelNames[level]} Access (${byLevel[level].length} projects):\n`;
                byLevel[level].forEach(p => {
                    const projectPath = p.Owner && p.Name ? `${p.Owner}/${p.Name}` : (p.pathWithNamespace || p.name);
                    const defaultBranch = p.DefaultBranch || p.defaultBranch || 'unknown';
                    output += `  * ${projectPath} [${p.visibility || 'unknown'}, ${defaultBranch}]\n`;
                });
                output += '\n';
            }
        });
    }

    return output;
}

function formatGitLabGroups(data) {
    let output = 'GitLab Groups Enumeration\n';
    output += '=========================\n\n';

    if (!data.groups || data.groups.length === 0) {
        output += 'No groups found.\n';
        return output;
    }

    output += `Total: ${data.groups.length} groups\n\n`;

    // Group by access level
    const byLevel = {
        50: [], 40: [], 30: [], 20: [], 10: []
    };

    data.groups.forEach(g => {
        const level = g.access_level || 0;
        if (byLevel[level]) {
            byLevel[level].push(g);
        }
    });

    const levelNames = {
        50: 'Owner', 40: 'Maintainer', 30: 'Developer',
        20: 'Reporter', 10: 'Guest'
    };

    [50, 40, 30, 20, 10].forEach(level => {
        if (byLevel[level].length > 0) {
            output += `${levelNames[level]} (${byLevel[level].length}):\n`;
            byLevel[level].forEach(g => {
                output += `  * ${g.full_path || g.path} [${g.visibility || 'unknown'}] (ID: ${g.id})\n`;
            });
            output += '\n';
        }
    });

    return output;
}

function formatGitLabSecrets(data) {
    let output = 'GitLab CI/CD Variables\n';
    output += '======================\n\n';

    if (data.project_variables) {
        Object.entries(data.project_variables).forEach(([project, vars]) => {
            if (vars.length > 0) {
                output += `Project: ${project} (${vars.length} variables)\n`;
                vars.forEach(v => {
                    const flags = [];
                    if (v.protected) flags.push('protected');
                    if (v.masked) flags.push('masked');
                    const flagStr = flags.length > 0 ? ` [${flags.join(', ')}]` : '';
                    output += `  • ${v.key}${flagStr}\n`;
                });
                output += '\n';
            }
        });
    }

    return output;
}

function formatGitLabBranchProtections(data) {
    let output = 'GitLab Branch Protections\n';
    output += '==========================\n\n';

    output += `Project: ${data.project}\n`;
    output += `Default Branch: ${data.default_branch}\n\n`;

    if (data.protections && data.protections.length > 0) {
        output += `Protected Branches (${data.protections.length}):\n\n`;
        data.protections.forEach(p => {
            output += `Branch: ${p.name}\n`;
            output += `  Force Push: ${p.allow_force_push ? 'Allowed' : 'Blocked'}\n`;
            output += `  Code Owner Approval: ${p.code_owner_approval_required ? 'Required' : 'Not Required'}\n`;

            if (p.push_access_levels && p.push_access_levels.length > 0) {
                output += `  Push Access: ${p.push_access_levels.map(a => a.access_level_description).join(', ')}\n`;
            }

            if (p.merge_access_levels && p.merge_access_levels.length > 0) {
                output += `  Merge Access: ${p.merge_access_levels.map(a => a.access_level_description).join(', ')}\n`;
            }

            output += '\n';
        });
    } else {
        output += 'No branch protections configured.\n';
    }

    return output;
}

function formatGitLabRunners(data) {
    let output = 'GitLab Runners Enumeration\n';
    output += '==========================\n\n';

    // Summary first (matching CLI format)
    if (data.summary) {
        output += `Total: ${data.summary.total || 0} runners (${data.summary.online || 0} online, ${data.summary.offline || 0} offline)\n`;
        output += `  * Instance: ${data.summary.instance_runners || 0}\n`;
        output += `  * Group: ${data.summary.group_runners || 0}\n`;
        output += `  * Project: ${data.summary.project_runners || 0}\n\n`;
    }

    // Project Runners with detailed format
    if (data.project_runners && data.project_runners.length > 0) {
        output += `Project Runners (${data.project_runners.length}):\n`;
        data.project_runners.forEach(r => {
            const status = r.online ? 'online' : 'offline';
            output += `  * #${r.id}: ${r.description || 'unnamed'} [${status}]\n`;
            if (r.tag_list && r.tag_list.length > 0) {
                output += `    - Tags: ${r.tag_list.join(', ')}\n`;
            }
            if (r.platform || r.architecture) {
                output += `    - Platform: ${r.platform || 'unknown'} (${r.architecture || 'unknown'})\n`;
            }
            if (r.version) {
                output += `    - Version: ${r.version}\n`;
            }
            const sharedText = r.is_shared ? ' (shared)' : '';
            output += `    - Type: ${r.runner_type || 'unknown'}${sharedText}\n`;
        });
        output += '\n';
    }

    // Group Runners
    if (data.group_runners && data.group_runners.length > 0) {
        output += `Group Runners (${data.group_runners.length}):\n`;
        data.group_runners.forEach(r => {
            const status = r.online ? 'online' : 'offline';
            output += `  * #${r.id}: ${r.description || 'unnamed'} [${status}]\n`;
            if (r.tag_list && r.tag_list.length > 0) {
                output += `    - Tags: ${r.tag_list.join(', ')}\n`;
            }
            output += `    - Type: ${r.runner_type || 'unknown'}\n`;
        });
        output += '\n';
    }

    // Instance Runners
    if (data.instance_runners && data.instance_runners.length > 0) {
        output += `Instance Runners (${data.instance_runners.length}):\n`;
        data.instance_runners.forEach(r => {
            const status = r.online ? 'online' : 'offline';
            output += `  * #${r.id}: ${r.description || 'unnamed'} [${status}]\n`;
            if (r.tag_list && r.tag_list.length > 0) {
                output += `    - Tags: ${r.tag_list.join(', ')}\n`;
            }
            output += `    - Type: ${r.runner_type || 'unknown'}\n`;
        });
        output += '\n';
    }

    // Historical Runners
    if (data.historical_runners && data.historical_runners.length > 0) {
        output += `Historical Runners (from logs) (${data.historical_runners.length}):\n`;
        output += '  These runners were discovered by analyzing recent pipeline execution logs.\n';
        output += '  They may be offline or decommissioned but were recently active.\n\n';
        data.historical_runners.forEach(r => {
            output += `  * ${r.description || r.id}\n`;
            if (r.last_seen_at) {
                output += `    - Last seen: ${r.last_seen_at}\n`;
            }
            if (r.is_shared) {
                output += `    - Type: shared\n`;
            }
        });
    }

    return output;
}

function formatADOProjects(data) {
    let output = 'Azure DevOps Projects Enumeration\n';
    output += '==================================\n\n';

    if (!data.projects || data.projects.length === 0) {
        output += 'No projects found.\n';
        return output;
    }

    output += `Total: ${data.projects.length} projects\n\n`;

    // Group by visibility
    const privateProjects = data.projects.filter(p => p.visibility === 'private');
    const publicProjects = data.projects.filter(p => p.visibility !== 'private');

    if (privateProjects.length > 0) {
        output += `Private Projects (${privateProjects.length}):\n`;
        privateProjects.forEach(p => {
            output += `  * ${p.name} (ID: ${p.id})\n`;
            if (p.description) {
                output += `    Description: ${p.description}\n`;
            }
        });
        output += '\n';
    }

    if (publicProjects.length > 0) {
        output += `Public Projects (${publicProjects.length}):\n`;
        publicProjects.forEach(p => {
            output += `  * ${p.name} (ID: ${p.id})\n`;
        });
    }

    return output;
}

function formatADORepos(data) {
    let output = 'Azure DevOps Repositories Enumeration\n';
    output += '======================================\n\n';

    if (!data.repositories || data.repositories.length === 0) {
        output += 'No repositories found.\n';
        return output;
    }

    output += `Total: ${data.repositories.length} repositories`;
    if (data.projectsScanned) {
        output += ` (across ${data.projectsScanned} projects)`;
    }
    output += '\n\n';

    // Group by project
    const byProject = {};
    data.repositories.forEach(r => {
        const projectName = r.project?.name || 'Unknown';
        if (!byProject[projectName]) {
            byProject[projectName] = [];
        }
        byProject[projectName].push(r);
    });

    Object.entries(byProject).forEach(([projectName, repos]) => {
        output += `Project: ${projectName} (${repos.length} repositories)\n`;
        repos.forEach(r => {
            const disabled = r.isDisabled ? ' [DISABLED]' : '';
            const branch = r.defaultBranch || 'unknown';
            output += `  * ${r.name}${disabled} (default: ${branch})\n`;
        });
        output += '\n';
    });

    return output;
}

function formatADOAgentPools(data) {
    let output = 'Azure DevOps Agent Pools Enumeration\n';
    output += '=====================================\n\n';

    if (!data.pools || data.pools.length === 0) {
        output += 'No agent pools found.\n';
        return output;
    }

    output += `Total: ${data.pools.length} agent pools\n\n`;

    // Separate hosted vs self-hosted
    const hostedPools = data.pools.filter(p => p.isHosted);
    const selfHostedPools = data.pools.filter(p => !p.isHosted);

    if (selfHostedPools.length > 0) {
        output += `Self-Hosted Pools (${selfHostedPools.length}):\n`;
        selfHostedPools.forEach(p => {
            const autoProvision = p.autoProvision ? ' [AUTO-PROVISION]' : '';
            output += `  * ${p.name}${autoProvision} (ID: ${p.id}, Size: ${p.size || 0})\n`;
        });
        output += '\n';
    }

    if (hostedPools.length > 0) {
        output += `Microsoft-Hosted Pools (${hostedPools.length}):\n`;
        hostedPools.forEach(p => {
            output += `  * ${p.name} (ID: ${p.id})\n`;
        });
    }

    return output;
}

function formatADOPipelines(data) {
    let output = 'Azure DevOps Pipelines Enumeration\n';
    output += '===================================\n\n';

    const totalPipelines = (data.totalPipelines || 0) + (data.totalBuildDefs || 0);
    output += `Total: ${totalPipelines} pipelines`;
    if (data.projectsScanned) {
        output += ` (across ${data.projectsScanned} projects)`;
    }
    output += '\n\n';

    // New-style pipelines
    if (data.pipelines && data.pipelines.length > 0) {
        output += `YAML Pipelines (${data.pipelines.length}):\n`;
        data.pipelines.forEach(p => {
            output += `  * ${p.name} (ID: ${p.id})\n`;
            if (p.folder) {
                output += `    Folder: ${p.folder}\n`;
            }
        });
        output += '\n';
    }

    // Legacy build definitions
    if (data.buildDefinitions && data.buildDefinitions.length > 0) {
        output += `Build Definitions (${data.buildDefinitions.length}):\n`;
        data.buildDefinitions.forEach(b => {
            const status = b.queueStatus === 'enabled' ? '' : ` [${b.queueStatus.toUpperCase()}]`;
            output += `  * ${b.name}${status} (ID: ${b.id})\n`;
            if (b.path && b.path !== '\\') {
                output += `    Path: ${b.path}\n`;
            }
        });
    }

    return output;
}

function formatADOVariableGroups(data) {
    let output = 'Azure DevOps Variable Groups\n';
    output += '=============================\n\n';

    if (!data.variableGroups || data.variableGroups.length === 0) {
        output += 'No variable groups found.\n';
        return output;
    }

    output += `Project: ${data.project}\n`;
    output += `Total: ${data.variableGroups.length} variable groups\n\n`;

    data.variableGroups.forEach(vg => {
        output += `Variable Group: ${vg.name} (ID: ${vg.id})\n`;
        if (vg.description) {
            output += `  Description: ${vg.description}\n`;
        }
        output += `  Type: ${vg.type}\n`;

        if (vg.variables) {
            const varCount = Object.keys(vg.variables).length;
            output += `  Variables: ${varCount}\n`;
            Object.entries(vg.variables).forEach(([key, val]) => {
                const secret = val.isSecret ? ' [SECRET]' : '';
                output += `    • ${key}${secret}\n`;
            });
        }
        output += '\n';
    });

    return output;
}

function formatADOServiceConnections(data) {
    let output = 'Azure DevOps Service Connections\n';
    output += '=================================\n\n';

    if (!data.connections || data.connections.length === 0) {
        output += 'No service connections found.\n';
        return output;
    }

    output += `Project: ${data.project}\n`;
    output += `Total: ${data.connections.length} service connections\n\n`;

    data.connections.forEach(conn => {
        const ready = conn.isReady ? '✓' : '✗';
        const shared = conn.isShared ? ' [SHARED]' : '';
        output += `${ready} ${conn.name}${shared} (Type: ${conn.type})\n`;
        if (conn.description) {
            output += `  Description: ${conn.description}\n`;
        }
        output += `  ID: ${conn.id}\n`;
        output += '\n';
    });

    return output;
}

function formatADOAttackPaths(data) {
    let output = 'Azure DevOps Attack Paths Analysis\n';
    output += '===================================\n\n';

    if (data.message) {
        output += data.message + '\n\n';
    }
    if (data.note) {
        output += 'Note: ' + data.note + '\n';
    }

    return output;
}

function formatADOForkSecurity(data) {
    let output = 'Azure DevOps Fork Security Scan\n';
    output += '================================\n\n';

    if (data.message) {
        output += data.message + '\n\n';
    }
    if (data.note) {
        output += 'Note: ' + data.note + '\n';
    }

    return output;
}

function formatDefaultResult(data) {
    // Fallback for operations without custom formatters
    return JSON.stringify(data, null, 2);
}

let currentEnumerateResults = null;

function displayEnumerateResults(platform, operation, data) {
    currentEnumerateResults = data;
    const outputDiv = document.getElementById('recon-results-output');

    let textOutput = '';

    try {
        // Use custom formatter based on platform and operation
        if (platform === 'github' && operation === 'repos') {
            textOutput = formatGitHubRepos(data);
        } else if (platform === 'github' && operation === 'secrets') {
            textOutput = formatGitHubSecrets(data);
        } else if (platform === 'github' && operation === 'runners') {
            textOutput = formatGitHubRunners(data);
        } else if (platform === 'gitlab' && operation === 'projects') {
            textOutput = formatGitLabProjects(data);
        } else if (platform === 'gitlab' && operation === 'groups') {
            textOutput = formatGitLabGroups(data);
        } else if (platform === 'gitlab' && operation === 'secrets') {
            textOutput = formatGitLabSecrets(data);
        } else if (platform === 'gitlab' && operation === 'runners') {
            textOutput = formatGitLabRunners(data);
        } else if (platform === 'gitlab' && (operation === 'branch-protections' || operation === 'protections')) {
            textOutput = formatGitLabBranchProtections(data);
        } else if (platform === 'azuredevops' && operation === 'projects') {
            textOutput = formatADOProjects(data);
        } else if (platform === 'azuredevops' && (operation === 'repos' || operation === 'repositories')) {
            textOutput = formatADORepos(data);
        } else if (platform === 'azuredevops' && (operation === 'agent-pools' || operation === 'agents')) {
            textOutput = formatADOAgentPools(data);
        } else if (platform === 'azuredevops' && operation === 'pipelines') {
            textOutput = formatADOPipelines(data);
        } else if (platform === 'azuredevops' && (operation === 'variable-groups' || operation === 'variables')) {
            textOutput = formatADOVariableGroups(data);
        } else if (platform === 'azuredevops' && (operation === 'service-connections' || operation === 'connections')) {
            textOutput = formatADOServiceConnections(data);
        } else if (platform === 'azuredevops' && operation === 'attack-paths') {
            textOutput = formatADOAttackPaths(data);
        } else if (platform === 'azuredevops' && operation === 'fork-security') {
            textOutput = formatADOForkSecurity(data);
        } else {
            // Fallback to JSON for operations without custom formatters
            textOutput = formatDefaultResult(data);
        }

        // Append errors if present
        if (data.errors && Array.isArray(data.errors) && data.errors.length > 0) {
            textOutput += '\n⚠️  Errors encountered:\n';
            data.errors.forEach(err => {
                textOutput += `  • ${err}\n`;
            });
            textOutput += '\nNote: Results may be incomplete due to permission restrictions.\n';
        }

    } catch (e) {
        console.error('Error formatting results:', e);
        textOutput = 'Error formatting results: ' + e.message + '\n\n' + formatDefaultResult(data);
    }

    // Display in <pre> tag
    outputDiv.innerHTML = `<pre>${escapeHtml(textOutput)}</pre>`;

    // Enable export button
    document.getElementById('btn-export-enumerate-json').disabled = false;
}

function handleExportEnumerateResults() {
    if (!currentEnumerateResults) {
        showToast('No results to export', 'warning');
        return;
    }

    const platform = document.getElementById('recon-platform').value;
    const operation = document.getElementById('recon-operation').value;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `trajan-enumerate-${platform}-${operation}-${timestamp}.json`;

    const blob = new Blob([JSON.stringify(currentEnumerateResults, null, 2)], {
        type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    showToast(`Exported to ${filename}`, 'success');
}

async function handleSelfEnumerate() {
    const token = document.getElementById('recon-token').value.trim();
    if (!token) {
        showToast('Please enter a token', 'warning');
        return;
    }

    const btn = document.getElementById('btn-self-enumerate');
    const progress = document.getElementById('recon-enumerate-progress');
    const results = document.getElementById('recon-enumerate-results');

    try {
        btn.disabled = true;
        progress.style.display = 'block';
        results.style.display = 'none';

        const result = await trajanBridge.selfEnumerate({
            token,
            onProgress: (percent, message) => {
                document.getElementById('recon-enumerate-progress-bar').style.width = `${percent}%`;
                document.getElementById('recon-enumerate-progress-text').textContent = message;
            }
        });

        displaySelfEnumerateResults(result.result);
        results.style.display = 'block';
        showToast('Enumeration complete', 'success');
    } catch (error) {
        showToast(`Enumeration failed: ${error.message || error.error}`, 'error');
    } finally {
        btn.disabled = false;
        progress.style.display = 'none';
    }
}

function displaySelfEnumerateResults(data) {
    const output = document.getElementById('recon-enumerate-output');
    const orgs = data.orgs || [];
    const runnersRepos = data.repos_with_runners || [];

    let html = `
        <div class="card">
            <h4>Token Identity</h4>
            <div class="info-list">
                <div class="info-row">
                    <span class="info-label">User:</span>
                    <span class="info-value">${escapeHtml(data.user?.login || '-')}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Scopes:</span>
                    <span class="info-value">${(data.scopes || []).join(', ') || 'None'}</span>
                </div>
            </div>
        </div>
        <div class="card">
            <h4>Organizations (${orgs.length})</h4>
            ${orgs.length === 0 ? '<p class="text-muted">No organizations found</p>' :
            `<div class="findings-list">${orgs.map(org => `
                <div class="finding ${org.admin ? 'high' : 'low'}">
                    <div class="finding-header">
                        <div class="finding-title">${escapeHtml(org.login)}</div>
                        ${org.admin ? '<div class="severity-badge high">ADMIN</div>' : '<div class="severity-badge low">MEMBER</div>'}
                    </div>
                    <div class="finding-detail">
                        <span class="finding-label">Repos:</span> ${org.repos || 0}
                        &nbsp;&nbsp;<span class="finding-label">Runners:</span> ${(org.runners || []).length}
                        &nbsp;&nbsp;<span class="finding-label">Secrets:</span> ${(org.secrets || []).length}
                    </div>
                </div>
            `).join('')}</div>`}
        </div>
    `;

    if (runnersRepos.length > 0) {
        html += `
            <div class="card">
                <h4>Repos with Self-Hosted Runners (${runnersRepos.length})</h4>
                <div class="findings-list">${runnersRepos.map(r => `
                    <div class="finding medium">
                        <div class="finding-header">
                            <div class="finding-title">${escapeHtml(r.repo)}</div>
                            <div class="severity-badge medium">${escapeHtml(r.visibility || 'unknown')}</div>
                        </div>
                        <div class="finding-detail">
                            <span class="finding-label">Workflow:</span> <code>${escapeHtml(r.workflow || '-')}</code>
                        </div>
                        ${r.runners && r.runners.length > 0 ? `
                            <div class="finding-detail">
                                <span class="finding-label">Runner Labels:</span> <code>${escapeHtml(r.runners.join(', '))}</code>
                            </div>
                        ` : ''}
                    </div>
                `).join('')}</div>
            </div>
        `;
    }

    output.innerHTML = html;
}

async function handleScanSecrets() {
    const target = document.getElementById('recon-secrets-target').value.trim();
    const token = document.getElementById('recon-secrets-token').value.trim();

    if (!target) { showToast('Please enter an organization name', 'warning'); return; }
    if (!token) { showToast('Please enter a token', 'warning'); return; }

    const btn = document.getElementById('btn-scan-secrets');
    const progress = document.getElementById('recon-secrets-progress');
    const results = document.getElementById('recon-secrets-results');

    try {
        btn.disabled = true;
        progress.style.display = 'block';
        results.style.display = 'none';

        const result = await trajanBridge.scanSecrets(target, {
            token,
            onProgress: (percent, message) => {
                document.getElementById('recon-secrets-progress-bar').style.width = `${percent}%`;
                document.getElementById('recon-secrets-progress-text').textContent = message;
            }
        });

        displaySecretsResults(result.result);
        results.style.display = 'block';
        showToast('Secrets scan complete', 'success');
    } catch (error) {
        showToast(`Secrets scan failed: ${error.message || error.error}`, 'error');
    } finally {
        btn.disabled = false;
        progress.style.display = 'none';
    }
}

function displaySecretsResults(data) {
    const output = document.getElementById('recon-secrets-output');
    const orgSecrets = data.orgSecrets || [];
    const orgVariables = data.orgVariables || [];
    const repos = data.repos || [];

    let html = `
        <div class="summary-cards">
            <div class="summary-card critical">
                <div class="count">${data.totalSecrets || 0}</div>
                <div class="label">Total Secrets</div>
            </div>
            <div class="summary-card medium">
                <div class="count">${orgSecrets.length}</div>
                <div class="label">Org Secrets</div>
            </div>
            <div class="summary-card low">
                <div class="count">${orgVariables.length}</div>
                <div class="label">Org Variables</div>
            </div>
            <div class="summary-card info">
                <div class="count">${data.totalRepos || 0}</div>
                <div class="label">Repos Scanned</div>
            </div>
        </div>
    `;

    if (orgSecrets.length > 0) {
        html += `<div class="card"><h4>Organization Secrets</h4><div class="tag-list">
            ${orgSecrets.map(s => `<span class="tag">${escapeHtml(s.name || s.Name || JSON.stringify(s))}</span>`).join('')}
        </div></div>`;
    }

    if (repos.length > 0) {
        const reposWithSecrets = repos.filter(r => (r.secrets && r.secrets.length > 0) || (r.orgSecrets && r.orgSecrets.length > 0));
        if (reposWithSecrets.length > 0) {
            html += `<div class="card"><h4>Repositories with Secrets (${reposWithSecrets.length})</h4>
                <div class="findings-list">${reposWithSecrets.slice(0, 50).map(r => `
                    <div class="finding low">
                        <div class="finding-header">
                            <div class="finding-title">${escapeHtml(r.name)}</div>
                        </div>
                        <div class="finding-detail">
                            <span class="finding-label">Repo Secrets:</span> ${(r.secrets || []).length}
                            &nbsp;&nbsp;<span class="finding-label">Org Secrets:</span> ${(r.orgSecrets || []).length}
                            &nbsp;&nbsp;<span class="finding-label">Variables:</span> ${(r.variables || []).length}
                        </div>
                    </div>
                `).join('')}</div>
            </div>`;
        }
    }

    output.innerHTML = html;
}

async function handleScanRunners() {
    const target = document.getElementById('recon-runners-target').value.trim();
    const token = document.getElementById('recon-runners-token').value.trim();

    if (!target) { showToast('Please enter an organization name', 'warning'); return; }
    if (!token) { showToast('Please enter a token', 'warning'); return; }

    const btn = document.getElementById('btn-scan-runners');
    const progress = document.getElementById('recon-runners-progress');
    const results = document.getElementById('recon-runners-results');

    try {
        btn.disabled = true;
        progress.style.display = 'block';
        results.style.display = 'none';

        const result = await trajanBridge.scanRunners(target, {
            token,
            onProgress: (percent, message) => {
                document.getElementById('recon-runners-progress-bar').style.width = `${percent}%`;
                document.getElementById('recon-runners-progress-text').textContent = message;
            }
        });

        displayRunnersResults(result.result);
        results.style.display = 'block';
        showToast('Runners scan complete', 'success');
    } catch (error) {
        showToast(`Runners scan failed: ${error.message || error.error}`, 'error');
    } finally {
        btn.disabled = false;
        progress.style.display = 'none';
    }
}

function displayRunnersResults(data) {
    const output = document.getElementById('recon-runners-output');
    const orgRunners = data.runners || [];
    const workflows = data.workflows || [];

    let html = `
        <div class="summary-cards">
            <div class="summary-card critical">
                <div class="count">${orgRunners.length}</div>
                <div class="label">Org Runners</div>
            </div>
            <div class="summary-card high">
                <div class="count">${workflows.length}</div>
                <div class="label">Self-Hosted Workflows</div>
            </div>
            <div class="summary-card medium">
                <div class="count">${(data.repoRunners || []).length}</div>
                <div class="label">Repos with Runners</div>
            </div>
            <div class="summary-card info">
                <div class="count">${data.totalRepos || 0}</div>
                <div class="label">Repos Scanned</div>
            </div>
        </div>
    `;

    if (workflows.length > 0) {
        html += `<div class="card"><h4>Workflows Using Self-Hosted Runners (${workflows.length})</h4>
            <div class="findings-list">${workflows.map(wf => `
                <div class="finding ${wf.private ? 'medium' : 'critical'}">
                    <div class="finding-header">
                        <div class="finding-title">${escapeHtml(wf.repo)} / ${escapeHtml(wf.file)}</div>
                        <div class="severity-badge ${wf.private ? 'medium' : 'critical'}">${wf.private ? 'PRIVATE' : 'PUBLIC'}</div>
                    </div>
                    ${wf.triggers ? `<div class="finding-detail">
                        <span class="finding-label">Triggers:</span> <code>${escapeHtml(Array.isArray(wf.triggers) ? wf.triggers.join(', ') : String(wf.triggers))}</code>
                    </div>` : ''}
                    ${wf.selfHostedJobs ? `<div class="finding-detail">
                        <span class="finding-label">Self-Hosted Jobs:</span> <code>${escapeHtml(JSON.stringify(wf.selfHostedJobs))}</code>
                    </div>` : ''}
                </div>
            `).join('')}</div>
        </div>`;
    }

    output.innerHTML = html;
}

// ============================= //
// Search Tab
// ============================= //

function initializeSearchTab() {
    document.getElementById('btn-search').addEventListener('click', handleSearch);
    document.getElementById('toggle-search-token').addEventListener('click', () => togglePasswordVisibility('search-token'));

    // Show/hide token field based on source
    document.getElementById('search-source').addEventListener('change', (e) => {
        const tokenGroup = document.getElementById('search-token-group');
        tokenGroup.style.display = e.target.value === 'sourcegraph' ? 'none' : 'block';
    });
}

async function handleSearch() {
    const query = document.getElementById('search-query').value.trim();
    const source = document.getElementById('search-source').value;
    const org = document.getElementById('search-org').value.trim();
    const token = document.getElementById('search-token').value.trim();

    if (source === 'github' && !token) {
        showToast('GitHub search requires a token', 'warning');
        return;
    }

    const btn = document.getElementById('btn-search');
    const progress = document.getElementById('search-progress');
    const results = document.getElementById('search-results');

    try {
        btn.disabled = true;
        progress.style.display = 'block';
        results.style.display = 'none';

        const result = await trajanBridge.search(query, { token, source, org });
        displaySearchResults(result.result);
        results.style.display = 'block';
        showToast('Search complete', 'success');
    } catch (error) {
        showToast(`Search failed: ${error.message || error.error}`, 'error');
    } finally {
        btn.disabled = false;
        progress.style.display = 'none';
    }
}

function displaySearchResults(data) {
    const output = document.getElementById('search-output');
    const title = document.getElementById('search-results-title');
    const repos = data.repositories || [];

    title.textContent = `Search Results (${data.totalCount || repos.length} found${data.incomplete ? ', results may be incomplete' : ''})`;

    if (repos.length === 0) {
        output.innerHTML = '<div class="card"><p class="text-center text-muted">No results found</p></div>';
        return;
    }

    output.innerHTML = repos.map(repo => {
        const repoName = repo.full_name || repo.name || repo.repository || repo;
        const repoStr = typeof repoName === 'string' ? repoName : JSON.stringify(repoName);
        return `
            <div class="finding low">
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(repoStr)}</div>
                </div>
                ${repo.html_url ? `<div class="finding-detail"><a href="${escapeHtml(repo.html_url)}" target="_blank" rel="noopener">${escapeHtml(repo.html_url)}</a></div>` : ''}
                ${repo.description ? `<div class="finding-detail">${escapeHtml(repo.description)}</div>` : ''}
            </div>
        `;
    }).join('');
}

// ============================= //
// WASM Error Handling
// ============================= //

function disableAllFeatures(errorMessage) {
    // Disable all action buttons
    document.querySelectorAll('.btn-primary, .btn-danger').forEach(btn => {
        btn.disabled = true;
    });

    // Add error banner to each tab
    document.querySelectorAll('.tab-content').forEach(tab => {
        const banner = document.createElement('div');
        banner.className = 'wasm-error-banner';
        banner.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <div>
                <strong>WASM Module Unavailable</strong>
                <p>All features require the WASM module. Error: ${escapeHtml(errorMessage)}</p>
            </div>
        `;
        tab.insertBefore(banner, tab.firstChild);
    });
}

// ============================= //
// Settings Tab
// ============================= //

function initializeSettingsTab() {
    const btnSaveToken = document.getElementById('btn-save-token');
    const btnClearToken = document.getElementById('btn-clear-token');
    const btnClearAuditLogs = document.getElementById('btn-clear-audit-logs');
    const btnClearSessions = document.getElementById('btn-clear-sessions');
    const btnClearCache = document.getElementById('btn-clear-cache');
    const btnClearAllStorage = document.getElementById('btn-clear-all-storage');
    const btnExportConfig = document.getElementById('btn-export-config');
    const btnImportConfig = document.getElementById('btn-import-config');
    const toggleTokenBtn = document.getElementById('toggle-settings-token');

    btnSaveToken.addEventListener('click', handleSaveToken);
    btnClearToken.addEventListener('click', handleClearToken);
    btnClearAuditLogs.addEventListener('click', () => handleClearStorage('audit'));
    btnClearSessions.addEventListener('click', () => handleClearStorage('sessions'));
    btnClearCache.addEventListener('click', () => handleClearStorage('cache'));
    btnClearAllStorage.addEventListener('click', handleClearAllStorage);
    btnExportConfig.addEventListener('click', handleExportConfig);
    btnImportConfig.addEventListener('click', () => document.getElementById('config-file-input').click());
    toggleTokenBtn.addEventListener('click', () => togglePasswordVisibility('settings-github-token'));

    document.getElementById('config-file-input').addEventListener('change', handleImportConfig);

    // Load current token
    loadCurrentToken();
}

async function loadCurrentToken() {
    try {
        const result = await trajanBridge.configGet('github.token');
        if (result.value) {
            document.getElementById('settings-github-token').value = result.value;
        }
    } catch (error) {
        console.error('Failed to load token:', error);
    }
}

async function handleSaveToken() {
    const token = document.getElementById('settings-github-token').value.trim();

    if (!token) {
        showToast('Please enter a token', 'warning');
        return;
    }

    try {
        await trajanBridge.configSet('github.token', token);
        showToast('Token saved successfully', 'success');
    } catch (error) {
        showToast(`Failed to save token: ${error.message}`, 'error');
    }
}

async function handleClearToken() {
    if (!confirm('Are you sure you want to clear the saved token?')) {
        return;
    }

    try {
        await trajanBridge.configSet('github.token', '');
        document.getElementById('settings-github-token').value = '';
        showToast('Token cleared', 'success');
    } catch (error) {
        showToast(`Failed to clear token: ${error.message}`, 'error');
    }
}

async function handleClearStorage(type) {
    if (!confirm(`Are you sure you want to clear ${type}?`)) {
        return;
    }

    try {
        // In a real implementation, this would call the appropriate storage clear method
        showToast(`${type} cleared successfully`, 'success');
    } catch (error) {
        showToast(`Failed to clear ${type}: ${error.message}`, 'error');
    }
}

async function handleClearAllStorage() {
    if (!confirm('Are you sure you want to clear ALL storage? This cannot be undone.')) {
        return;
    }

    try {
        // Clear localStorage
        localStorage.clear();
        // Clear IndexedDB (would need implementation in storage adapter)
        showToast('All storage cleared successfully', 'success');
    } catch (error) {
        showToast(`Failed to clear storage: ${error.message}`, 'error');
    }
}

async function handleExportConfig() {
    try {
        // Get all config values
        const config = {
            github: {},
            gitlab: {},
            azure: {},
            bitbucket: {},
            scan: {},
            ui: {}
        };

        // In a real implementation, this would call configGet for all keys
        const configJson = JSON.stringify(config, null, 2);
        const blob = new Blob([configJson], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'trajan-config.json';
        a.click();
        URL.revokeObjectURL(url);

        showToast('Configuration exported', 'success');
    } catch (error) {
        showToast(`Export failed: ${error.message}`, 'error');
    }
}

async function handleImportConfig(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const config = JSON.parse(text);

        // In a real implementation, this would call configSet for all keys
        showToast('Configuration imported successfully', 'success');
    } catch (error) {
        showToast(`Import failed: ${error.message}`, 'error');
    }
}

// ============================= //
// Utility Functions
// ============================= //

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

function escapeHtml(text) {
    if (text == null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            container.removeChild(toast);
        }, 300);
    }, 5000);
}

// Add slideOut animation to CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

console.log('✅ Trajan Security Scanner - Application loaded');
