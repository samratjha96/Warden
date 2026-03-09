/**
 * OSS Watchdog - Static Site Application
 * 
 * This is a minimal client-side application for displaying security reports.
 * Reports are generated asynchronously and placed in /data/reports/ as JSON files.
 * The queue is managed via /data/queue/index.json.
 */

var App = (function() {
    'use strict';
    
    var DATA_PATH = 'data/';
    var REPORTS_PATH = DATA_PATH + 'reports/';
    var QUEUE_PATH = DATA_PATH + 'queue/';
    
    // Utility: fetch JSON with error handling
    function fetchJSON(url) {
        return fetch(url)
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }
                return response.json();
            });
    }
    
    // Load reports index
    function loadReportsIndex() {
        return fetchJSON(REPORTS_PATH + 'index.json')
            .catch(function() {
                return { reports: [] };
            });
    }
    
    // Load queue index
    function loadQueueIndex() {
        return fetchJSON(QUEUE_PATH + 'index.json')
            .catch(function() {
                return { jobs: [] };
            });
    }
    
    // Load a specific report by ID
    // Sanitize ID to prevent path traversal
    function loadReport(id) {
        if (!id || typeof id !== 'string') {
            return Promise.reject(new Error('Invalid report ID'));
        }
        // Only allow alphanumeric, hyphens, underscores, and dots
        var sanitizedId = id.replace(/[^a-zA-Z0-9_.-]/g, '');
        if (sanitizedId !== id || sanitizedId.length === 0) {
            return Promise.reject(new Error('Invalid report ID'));
        }
        // Prevent path traversal
        if (sanitizedId.includes('..') || sanitizedId.startsWith('.')) {
            return Promise.reject(new Error('Invalid report ID'));
        }
        return fetchJSON(REPORTS_PATH + sanitizedId + '.json');
    }
    
    // Load recent reports (limited)
    function loadRecentReports(limit) {
        return loadReportsIndex().then(function(data) {
            var reports = data.reports || [];
            // Sort by date descending
            reports.sort(function(a, b) {
                return b.analyzed.localeCompare(a.analyzed);
            });
            return reports.slice(0, limit || 10);
        });
    }
    
    // Submit a new job to the queue
    function submitJob(url, options) {
        return fetch('/api/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: url,
                ecosystem: options.ecosystem || 'auto',
                severity: options.severity || 'low',
                depth: options.depth || 'shallow'
            })
        })
        .then(function(r) {
            return r.json().then(function(data) {
                if (!r.ok) {
                    var err = new Error(data.error || ('HTTP ' + r.status));
                    err.code = data.code || '';
                    throw err;
                }
                return data;
            });
        })
        .then(function(data) {
            if (data.job) {
                window.location.href = 'queue.html';
            } else {
                alert(data.error || 'Submission failed');
            }
        })
        .catch(function(err) {
            if (err.code === 'duplicate_queue_entry') {
                alert(
                    'MISSION ALREADY ACTIVE\n\n' +
                    err.message + '\n\n' +
                    'Open Queue to track or remove the existing entry before re-submitting.'
                );
                return;
            }
            alert('Error: ' + err.message);
        });
    }

    // Remove queue job by ID
    function removeQueueJob(jobId) {
        if (!jobId) return Promise.reject(new Error('Invalid job ID'));
        return fetch('/api/queue/' + encodeURIComponent(jobId), {
            method: 'DELETE'
        })
        .then(function(r) {
            return r.json().then(function(data) {
                if (!r.ok) {
                    throw new Error(data.error || ('HTTP ' + r.status));
                }
                return data;
            });
        });
    }
    
    // Format risk level for display
    function formatRisk(risk) {
        var map = {
            high: { class: 'risk-h', text: 'HIGH' },
            medium: { class: 'risk-m', text: 'MED' },
            low: { class: 'risk-l', text: 'LOW' }
        };
        return map[risk] || map.low;
    }
    
    // Format verdict for display
    function formatVerdict(verdict) {
        var map = {
            reject: { class: 'v-reject', text: 'Reject' },
            approve: { class: 'v-approve', text: 'Approve' },
            conditional: { class: 'v-cond', text: 'Conditions' },
            pending: { class: 'v-pending', text: 'Pending' }
        };
        return map[verdict] || map.pending;
    }
    
    // Render recent reports table
    function renderRecentTable(reports, tbody) {
        if (!reports || reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">' +
                '<div class="empty-state-title">No analyses yet</div>' +
                '<div class="empty-state-desc">Submit a repository above to get started</div>' +
                '</td></tr>';
            return;
        }
        
        var html = '';
        reports.forEach(function(r) {
            var risk = formatRisk(r.risk);
            var verdict = formatVerdict(r.verdict);
            html += '<tr onclick="window.location.href=\'report.html?id=' + encodeURIComponent(r.id) + '\'">' +
                '<td>' +
                    '<div class="scan-pkg">' + escapeHtml(r.owner + ' / ' + r.repo) + '</div>' +
                    '<div class="scan-sub">commit ' + escapeHtml(r.commit) + '</div>' +
                '</td>' +
                '<td class="scan-eco">' + escapeHtml(r.ecosystem) + '</td>' +
                '<td class="scan-date">' + escapeHtml(r.analyzed) + '</td>' +
                '<td class="' + risk.class + '">' + risk.text + '</td>' +
                '<td class="scan-finding">' + escapeHtml(r.keyFinding) + '</td>' +
                '<td class="verdict-cell ' + verdict.class + '">' + verdict.text + '</td>' +
                '</tr>';
        });
        tbody.innerHTML = html;
    }
    
    // Update verdict counts
    function updateVerdictCounts(reports) {
        var counts = { approve: 0, conditional: 0, reject: 0 };
        reports.forEach(function(r) {
            if (counts.hasOwnProperty(r.verdict)) {
                counts[r.verdict]++;
            }
        });
        
        var approveEl = document.getElementById('approve-count');
        var condEl = document.getElementById('cond-count');
        var rejectEl = document.getElementById('reject-count');
        
        if (approveEl) approveEl.textContent = counts.approve;
        if (condEl) condEl.textContent = counts.conditional;
        if (rejectEl) rejectEl.textContent = counts.reject;
    }
    
    // Escape HTML to prevent XSS
    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
    
    // Get URL parameter
    function getParam(name) {
        var params = new URLSearchParams(window.location.search);
        return params.get(name);
    }
    
    // Render full report page
    function renderReport(report, container) {
        if (!report) {
            container.innerHTML = '<div class="error-banner">Report not found</div>';
            return;
        }
        
        // Build HTML sections
        var html = '';
        
        // Verdict banner
        var verdictClass = report.risk === 'high' ? 'risk-high' : 
                          report.risk === 'medium' ? 'risk-med' : 'risk-low';
        var verdictText = report.verdict === 'reject' ? 'REJECT' :
                         report.verdict === 'approve' ? 'APPROVE' : 'CONDITIONAL';
        
        var repoLabel = escapeHtml(report.owner + ' / ' + report.repo);
        var repoLinkHtml = report.url
            ? '<a href="' + escapeHtml(report.url) + '" target="_blank" rel="noopener noreferrer" style="color:inherit;text-decoration:underline;">' + repoLabel + '</a>'
            : repoLabel;

        html += '<div class="verdict-banner">' +
            '<div>' +
                '<div class="verdict-pkg">' + repoLinkHtml + '</div>' +
                '<div class="verdict-meta">' +
                    '<strong>commit</strong> ' + escapeHtml(report.commit) + ' (shallow clone) &nbsp;·&nbsp;' +
                    '<strong>analyzed</strong> ' + escapeHtml(report.analyzed) + ' &nbsp;·&nbsp;' +
                    '<strong>SOP</strong> oss-security-analyzer v' + escapeHtml(report.sopVersion) + '<br>' +
                    '<strong>ecosystems</strong> ' + escapeHtml(report.ecosystems.join(' · ')) +
                '</div>' +
            '</div>' +
            '<div class="verdict-risk-col">' +
                '<div class="verdict-risk-label">Verdict</div>' +
                '<div class="verdict-risk-val ' + verdictClass + '">' + verdictText + '</div>' +
                '<div style="font-family:\'Space Mono\',monospace;font-size:10px;color:#666;margin-top:4px;">Risk: ' + report.risk.toUpperCase() + '</div>' +
            '</div>' +
        '</div>';
        
        // Body grid
        html += '<div class="body-grid"><div class="main-col">';
        
        // Executive Summary
        html += '<div class="section">' +
            '<div class="section-label"><span>01</span> — Executive Summary</div>' +
            '<table class="exec-table"><thead><tr>' +
            '<th style="width:38%">Category</th>' +
            '<th style="width:14%">Risk</th>' +
            '<th>Key Finding</th>' +
            '</tr></thead><tbody>';
        
        report.summary.forEach(function(s) {
            var riskClass = s.risk === 'high' ? 'risk-high' : 
                           s.risk === 'medium' ? 'risk-med' : 'risk-low';
            html += '<tr>' +
                '<td><span class="cat-name">' + escapeHtml(s.category) + '</span></td>' +
                '<td class="' + riskClass + '">' + s.risk.toUpperCase() + '</td>' +
                '<td class="cat-note">' + escapeHtml(s.finding) + '</td>' +
                '</tr>';
        });
        
        html += '</tbody></table></div>';
        
        // Detailed Findings
        report.findings.forEach(function(section) {
            var sectionRiskClass = section.sectionRisk === 'high' ? 'var(--red)' :
                                  section.sectionRisk === 'medium' ? 'var(--amber)' : 'var(--green)';
            
            html += '<div class="section">' +
                '<div class="section-label"><span>' + escapeHtml(section.sectionNumber) + '</span> — ' + 
                escapeHtml(section.section) + ' · <span style="color:' + sectionRiskClass + ';">' + 
                section.sectionRisk.toUpperCase() + '</span></div>';
            
            section.items.forEach(function(item) {
                var sevClass = item.severity === 'high' ? 'sev-r' : 
                              item.severity === 'medium' ? 'sev-m' : 'sev-g';
                
                html += '<div class="finding">' +
                    '<div class="finding-head">' +
                        '<div class="finding-head-left">' +
                            '<span class="finding-sev ' + sevClass + '">' + item.severity.toUpperCase() + '</span>' +
                            '<span class="finding-title">' + escapeHtml(item.title) + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="finding-body">' +
                        '<p>' + escapeHtml(item.description) + '</p>';
                
                if (item.evidence && item.evidence.length > 0) {
                    html += '<div class="evidence">' +
                        '<div class="evidence-label">References</div>';
                    item.evidence.forEach(function(e) {
                        html += '<div class="evidence-row">' +
                            '<code>' + escapeHtml(e.file) + '</code>' +
                            '<span class="evidence-desc">' + escapeHtml(e.note) + '</span>' +
                            '</div>';
                    });
                    html += '</div>';
                }
                
                html += '</div></div>';
            });
            
            // Checks
            if (section.checks && section.checks.length > 0) {
                section.checks.forEach(function(c) {
                    var icon = c.status === 'ok' ? '✓' : c.status === 'warn' ? '!' : '✕';
                    var iconClass = c.status === 'ok' ? 'ck-ok' : c.status === 'warn' ? 'ck-warn' : 'ck-bad';
                    html += '<div class="check-row">' +
                        '<span class="ck-icon ' + iconClass + '">' + icon + '</span>' +
                        '<span class="ck-text">' + escapeHtml(c.text) + '</span>' +
                        '</div>';
                });
            }
            
            html += '</div>';
        });
        
        // Red Flags
        if (report.redFlags && report.redFlags.length > 0) {
            html += '<div class="section">' +
                '<div class="section-label"><span>13</span> — Red Flags Summary</div>' +
                '<table class="rf-table"><thead><tr>' +
                '<th style="width:52%">Check</th>' +
                '<th style="width:15%">Status</th>' +
                '<th>Notes</th>' +
                '</tr></thead><tbody>';
            
            report.redFlags.forEach(function(rf) {
                var badgeClass = rf.status === 'pass' ? 'rf-pass' : 
                                rf.status === 'caution' ? 'rf-caution' : 'rf-fail';
                html += '<tr>' +
                    '<td>' + escapeHtml(rf.check) + '</td>' +
                    '<td><span class="rf-badge ' + badgeClass + '">' + rf.status.toUpperCase() + '</span></td>' +
                    '<td style="color:var(--mid);font-size:12px;">' + escapeHtml(rf.notes) + '</td>' +
                    '</tr>';
            });
            
            html += '</tbody></table></div>';
        }
        
        // Remediation
        if (report.remediation && report.remediation.length > 0) {
            html += '<div class="section">' +
                '<div class="section-label"><span>15</span> — Remediation</div>' +
                '<p style="font-size:13px;color:var(--mid);margin-bottom:20px;font-family:\'Space Mono\',monospace;">' +
                (report.verdict === 'reject' ? 'APPROVE WITH CONDITIONS only under strict controls:' : 'Recommended actions:') +
                '</p>';
            
            report.remediation.forEach(function(r, i) {
                var num = String(i + 1).padStart(2, '0');
                html += '<div class="rem-item">' +
                    '<div class="rem-num">' + num + '</div>' +
                    '<div class="rem-text">' + escapeHtml(r) + '</div>' +
                    '</div>';
            });
            
            html += '</div>';
        }
        
        html += '</div>'; // end main-col
        
        // Sidebar
        html += '<div class="side-col">';
        
        if (report.sidebar) {
            // Community Trust
            if (report.sidebar.community) {
                html += '<div class="side-block">' +
                    '<div class="side-head">Community Trust</div>' +
                    '<div class="stat-trio">' +
                        '<div class="stat-trio-item"><div class="stat-num">' + escapeHtml(report.sidebar.community.stars) + '</div><div class="stat-lbl">Stars</div></div>' +
                        '<div class="stat-trio-item"><div class="stat-num">' + escapeHtml(report.sidebar.community.forks) + '</div><div class="stat-lbl">Forks</div></div>' +
                        '<div class="stat-trio-item"><div class="stat-num">' + escapeHtml(report.sidebar.community.contributors) + '</div><div class="stat-lbl">Contribs</div></div>' +
                    '</div>' +
                    '<div class="side-body">';
                
                var trust = report.sidebar.trust;
                html += '<div class="side-row"><span class="side-key">SECURITY.md</span><span class="side-val" style="color:' + (trust.securityMd ? 'var(--green)' : 'var(--red)') + ';">' + (trust.securityMd ? 'Present ✓' : 'Missing ✕') + '</span></div>';
                html += '<div class="side-row"><span class="side-key">Branch protection</span><span class="side-val" style="color:' + (trust.branchProtection ? 'var(--green)' : 'var(--red)') + ';">' + (trust.branchProtection ? 'Enabled ✓' : 'Disabled ✕') + '</span></div>';
                html += '<div class="side-row"><span class="side-key">Commit signing</span><span class="side-val" style="color:' + (trust.commitSigning === 'required' ? 'var(--green)' : trust.commitSigning === 'mixed' ? 'var(--amber)' : 'var(--red)') + ';">' + escapeHtml(trust.commitSigning.charAt(0).toUpperCase() + trust.commitSigning.slice(1)) + '</span></div>';
                html += '<div class="side-row"><span class="side-key">Open issues</span><span class="side-val">' + escapeHtml(String(trust.openIssues)) + '</span></div>';
                html += '<div class="side-row"><span class="side-key">Created</span><span class="side-val">' + escapeHtml(trust.created) + '</span></div>';
                
                html += '</div></div>';
            }
            
            // Dependencies
            if (report.sidebar.dependencies) {
                var deps = report.sidebar.dependencies;
                html += '<div class="side-block">' +
                    '<div class="side-head">Dependencies</div>' +
                    '<div class="side-body">' +
                    '<div class="side-row"><span class="side-key">CVEs found</span><span class="side-val" style="color:' + (deps.cves === 0 ? 'var(--green)' : 'var(--red)') + ';">' + deps.cves + '</span></div>' +
                    '<div class="side-row"><span class="side-key">Scanner</span><span class="side-val">' + escapeHtml(deps.scanner) + '</span></div>' +
                    '<div class="side-row"><span class="side-key">Prod transitive</span><span class="side-val">' + escapeHtml(String(deps.prodTransitive)) + '</span></div>' +
                    '<div class="side-row"><span class="side-key">Direct deps</span><span class="side-val">' + escapeHtml(deps.directDeps) + '</span></div>' +
                    '<div class="side-row"><span class="side-key">Exact pins</span><span class="side-val">' + escapeHtml(deps.exactPins) + '</span></div>' +
                    '<div class="side-row"><span class="side-key">Floating ranges</span><span class="side-val">' + escapeHtml(deps.floatingRanges) + '</span></div>' +
                    '</div></div>';
            }
            
            // SOP Checklist
            if (report.sidebar.checklist) {
                html += '<div class="side-block">' +
                    '<div class="side-head">SOP Checklist</div>' +
                    '<div class="side-body">';
                
                report.sidebar.checklist.forEach(function(c) {
                    var icon = c.status === 'pass' ? '✓' : c.status === 'warn' ? '!' : '✕';
                    var color = c.status === 'pass' ? 'var(--green)' : c.status === 'warn' ? 'var(--amber)' : 'var(--red)';
                    html += '<div class="sop-item"><span>' + escapeHtml(c.name) + '</span><span class="sop-icon" style="color:' + color + ';">' + icon + '</span></div>';
                });
                
                html += '</div></div>';
            }
        }
        
        html += '</div>'; // end side-col
        html += '</div>'; // end body-grid
        
        container.innerHTML = html;
    }
    
    // Render queue page
    function renderQueue(jobs, container) {
        if (!jobs || jobs.length === 0) {
            container.innerHTML = '<div class="empty-state">' +
                '<div class="empty-state-title">Queue Empty</div>' +
                '<div class="empty-state-desc">No pending analyses. Submit a repository to start.</div>' +
                '</div>';
            return;
        }
        
        var html = '';
        jobs.forEach(function(job) {
            var statusClass = job.status === 'pending' ? 'pending' :
                             job.status === 'processing' ? 'processing' :
                             job.status === 'complete' ? 'complete' : 'failed';
            
            html += '<div class="queue-item">' +
                '<div class="queue-item-head">' +
                    '<div class="queue-pkg">' + escapeHtml(job.owner + ' / ' + job.repo) + '</div>' +
                    '<div style="display:flex;align-items:center;gap:10px;">' +
                        '<span class="queue-status ' + statusClass + '">' + escapeHtml(job.status) + '</span>' +
                        '<button type="button" onclick="window.removeQueueItem && window.removeQueueItem(\'' + escapeHtml(job.id) + '\')" ' +
                        'style="background:transparent;border:1px solid var(--ink);padding:4px 8px;font-family:\'Space Mono\',monospace;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;cursor:pointer;">Remove</button>' +
                    '</div>' +
                '</div>' +
                '<div class="queue-item-body">' +
                    '<div class="queue-meta">' +
                        'Submitted: ' + escapeHtml(job.submitted) + ' · ' +
                        'URL: ' + escapeHtml(job.url) +
                    '</div>';
            
            if (job.status === 'processing' || job.status === 'pending') {
                var progress = job.progress || (job.status === 'pending' ? 5 : 50);
                html += '<div class="queue-progress" style="margin-top:12px;">' +
                    '<div class="queue-progress-bar" style="width:' + progress + '%; animation: progress-pulse 2s ease-in-out infinite;"></div>' +
                    '</div>' +
                    '<p style="margin-top:8px;font-size:12px;color:var(--mid);font-family:\'Space Mono\',monospace;">' +
                    (job.status === 'pending' ? 'Queued for analysis...' : 'Analysis in progress...') +
                    '</p>';
            }
            
            if (job.status === 'complete' && job.reportId) {
                html += '<div style="margin-top:12px;">' +
                    '<a href="report.html?id=' + encodeURIComponent(job.reportId) + '" ' +
                    'style="font-family:\'Space Mono\',monospace;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:var(--green);">' +
                    'View Report →</a></div>';
            }
            
            if (job.status === 'failed' && job.error) {
                html += '<div style="margin-top:12px;color:var(--red);font-size:13px;">' +
                    'Error: ' + escapeHtml(job.error) + '</div>';
            }
            
            html += '</div></div>';
        });
        
        container.innerHTML = html;
    }
    
    // Public API
    return {
        fetchJSON: fetchJSON,
        loadReportsIndex: loadReportsIndex,
        loadQueueIndex: loadQueueIndex,
        loadReport: loadReport,
        loadRecentReports: loadRecentReports,
        submitJob: submitJob,
        removeQueueJob: removeQueueJob,
        formatRisk: formatRisk,
        formatVerdict: formatVerdict,
        renderRecentTable: renderRecentTable,
        updateVerdictCounts: updateVerdictCounts,
        escapeHtml: escapeHtml,
        getParam: getParam,
        renderReport: renderReport,
        renderQueue: renderQueue
    };
})();
