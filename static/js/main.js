/**
 * PhishGuard AI - Main Client Engine
 * Theme switching, scanner async orchestration, history filtering, and toast feedback.
 */

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initScanner();
    initHistoryTable();
    initCopyButtons();
});

/* ==========================================================================
   1. Theme Management (Dark / Light Mode)
   ========================================================================== */
function initTheme() {
    const themeToggleBtn = document.getElementById("themeToggleBtn");
    const currentTheme = localStorage.getItem("phishguard_theme") || "dark";
    
    document.documentElement.setAttribute("data-theme", currentTheme);
    updateThemeIcon(currentTheme);

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            const activeTheme = document.documentElement.getAttribute("data-theme");
            const newTheme = activeTheme === "light" ? "dark" : "light";
            document.documentElement.setAttribute("data-theme", newTheme);
            localStorage.setItem("phishguard_theme", newTheme);
            updateThemeIcon(newTheme);

            // Re-render charts with updated theme palette if present
            if (window.renderDashboardCharts) {
                window.renderDashboardCharts();
            }
        });
    }
}

function updateThemeIcon(theme) {
    const icon = document.getElementById("themeIcon");
    if (!icon) return;
    if (theme === "light") {
        icon.className = "bi bi-moon-stars-fill";
    } else {
        icon.className = "bi bi-sun-fill";
    }
}

/* ==========================================================================
   2. URL Scanner Module
   ========================================================================== */
function initScanner() {
    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const samplePills = document.querySelectorAll(".sample-url-pill");

    // Click sample URL pills to auto-populate
    samplePills.forEach(pill => {
        pill.addEventListener("click", (e) => {
            e.preventDefault();
            const targetUrl = pill.getAttribute("data-url");
            if (urlInput) {
                urlInput.value = targetUrl;
                urlInput.focus();
                triggerScan(targetUrl);
            }
        });
    });

    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const urlVal = urlInput.value.trim();
            if (!urlVal) {
                showToast("Please enter a valid website URL to scan.", "warning");
                urlInput.focus();
                return;
            }
            triggerScan(urlVal);
        });
    }

    // Auto-trigger if URL parameter was supplied
    if (urlInput && urlInput.value.trim().length > 3) {
        triggerScan(urlInput.value.trim());
    }
}

async function triggerScan(url) {
    const scanBtn = document.getElementById("scanBtn");
    const scanSpinner = document.getElementById("scanSpinner");
    const scanBtnText = document.getElementById("scanBtnText");
    const resultContainer = document.getElementById("scanResultContainer");
    const emptyState = document.getElementById("scannerEmptyState");

    // Show loading state
    if (scanBtn) scanBtn.disabled = true;
    if (scanSpinner) scanSpinner.classList.remove("d-none");
    if (scanBtnText) scanBtnText.innerHTML = `Analyzing Threat...`;
    if (emptyState) emptyState.classList.add("d-none");

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Evaluation failed. Please verify input URL.");
        }

        renderScanResults(data);
        showToast("Analysis complete. Threat metrics generated.", "success");

        // Scroll smoothly to results
        if (resultContainer) {
            resultContainer.scrollIntoView({ behavior: "smooth", block: "start" });
        }

    } catch (err) {
        console.error("Scan error:", err);
        showToast(err.message, "danger");
    } finally {
        if (scanBtn) scanBtn.disabled = false;
        if (scanSpinner) scanSpinner.classList.add("d-none");
        if (scanBtnText) scanBtnText.innerHTML = `<i class="bi bi-shield-shaded"></i> Scan Threat`;
    }
}

function renderScanResults(res) {
    const resultContainer = document.getElementById("scanResultContainer");
    if (!resultContainer) return;
    resultContainer.classList.remove("d-none");

    // 1. Text elements
    setElementText("resUrl", res.url);
    const domainVal = (res.components && res.components.domain) ? res.components.domain : (res.domain || "N/A");
    setElementText("resDomain", domainVal);

    // Update classification badge, text, and icon
    const classBadge = document.getElementById("resClassificationBadge");
    if (classBadge) {
        classBadge.className = `badge-threat ${res.classification_slug || 'safe'}`;
    }

    const classText = document.getElementById("resClassification");
    if (classText) {
        classText.textContent = res.classification || "Safe / Legitimate";
    } else if (classBadge) {
        classBadge.textContent = res.classification || "Safe / Legitimate";
    }

    const classIcon = document.getElementById("resClassificationIcon");
    if (classIcon) {
        if (res.classification_slug === "danger") {
            classIcon.className = "bi bi-shield-slash me-1";
        } else if (res.classification_slug === "suspicious") {
            classIcon.className = "bi bi-exclamation-triangle me-1";
        } else {
            classIcon.className = "bi bi-shield-check me-1";
        }
    }

    setElementText("resModelMode", res.model_mode || "Trained Machine Learning Model");

    const riskVal = document.getElementById("resRiskValue");
    if (riskVal) {
        riskVal.textContent = res.risk_score !== undefined ? res.risk_score : "0.0";
        riskVal.style.color = res.color_code || "#10b981";
    }

    // View Detailed Report button href
    const reportBtn = document.getElementById("resReportBtn");
    if (reportBtn) {
        reportBtn.href = res.scan_id ? `/report/${res.scan_id}` : "#";
    }

    // PDF Download button href
    const pdfBtn = document.getElementById("resPdfBtn");
    if (pdfBtn) {
        pdfBtn.href = res.scan_id ? `/api/reports/download/${res.scan_id}` : "#";
    }

    // 2. Render Animated Risk Meter Arc
    renderRiskMeter(res.risk_score || 0, res.color_code || "#10b981");

    // 3. Render Explainability Findings
    const findingsList = document.getElementById("resFindingsList");
    if (findingsList) {
        findingsList.innerHTML = "";
        if (res.findings && res.findings.length > 0) {
            res.findings.forEach(f => {
                const box = document.createElement("div");
                box.className = `finding-box ${f.type || 'info'}`;
                const weightTag = f.weight ? `<span class="badge bg-secondary ms-2">+${f.weight} pts</span>` : '';
                box.innerHTML = `
                    <div class="d-flex align-items-center mb-1">
                        <i class="bi ${f.icon || 'bi-info-circle'} me-2 fs-5" style="color: ${res.color_code || '#38bdf8'}"></i>
                        <strong class="text-primary">${f.feature}</strong>
                        ${weightTag}
                    </div>
                    <div class="text-secondary small ms-4">${f.description}</div>
                `;
                findingsList.appendChild(box);
            });
        } else {
            findingsList.innerHTML = `<div class="p-3 text-muted">No high-risk structural anomalies detected.</div>`;
        }
    }

    // 4. Render Quantitative Table
    const feats = res.numerical_features || {};
    setElementText("resFeatUrlLen", feats.url_len);
    setElementText("resFeatDomainLen", feats.domain_len);
    setElementText("resFeatDots", feats.dot_count);
    setElementText("resFeatHyphens", feats.hyphen_count);
    setElementText("resFeatSubdomains", feats.subdomain_count);
    setElementText("resFeatIp", feats.is_ip ? "YES (Threat)" : "NO");
    setElementText("resFeatHttps", feats.is_https ? "HTTPS (Encrypted)" : "HTTP (Insecure)");
    setElementText("resFeatShortener", feats.is_shortener ? "YES (Shortened)" : "NO");

    // 5. Render Safety Recommendations
    const recsList = document.getElementById("resRecommendationsList");
    if (recsList) {
        recsList.innerHTML = "";
        if (res.recommendations && res.recommendations.length > 0) {
            res.recommendations.forEach(r => {
                const li = document.createElement("li");
                li.className = "mb-2 d-flex align-items-start";
                li.innerHTML = `<i class="bi bi-shield-check text-cyber-accent me-2 mt-1"></i><span>${r}</span>`;
                recsList.appendChild(li);
            });
        }
    }
}

function renderRiskMeter(score, colorCode) {
    const canvas = document.getElementById("riskMeterCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const centerX = width / 2;
    const centerY = height - 15;
    const radius = 95;
    const startAngle = Math.PI;
    const endAngle = 2 * Math.PI;

    // Background track arc
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, startAngle, endAngle, false);
    ctx.lineWidth = 14;
    ctx.strokeStyle = "rgba(148, 163, 184, 0.2)";
    ctx.lineCap = "round";
    ctx.stroke();

    // Filled score arc
    const numScore = Math.max(0, Math.min(100, parseFloat(score) || 0));
    const scoreAngle = startAngle + (numScore / 100) * (endAngle - startAngle);
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, startAngle, scoreAngle, false);
    ctx.lineWidth = 14;
    ctx.strokeStyle = colorCode || "#10b981";
    ctx.lineCap = "round";
    ctx.stroke();

    // Pulse indicator dot at tip of score
    const tipX = centerX + radius * Math.cos(scoreAngle);
    const tipY = centerY + radius * Math.sin(scoreAngle);
    ctx.beginPath();
    ctx.arc(tipX, tipY, 7, 0, 2 * Math.PI);
    ctx.fillStyle = "#ffffff";
    ctx.fill();
    ctx.strokeStyle = colorCode || "#10b981";
    ctx.lineWidth = 2.5;
    ctx.stroke();
}

function setElementText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val !== undefined ? val : "N/A";
}

/* ==========================================================================
   3. Scan History Manager (Search, Filter, Delete, Clear)
   ========================================================================== */
function initHistoryTable() {
    const searchInput = document.getElementById("historySearch");
    const filterSelect = document.getElementById("historyFilter");
    const sortSelect = document.getElementById("historySort");
    const clearBtn = document.getElementById("clearHistoryBtn");

    if (!document.getElementById("historyTableBody")) return;

    loadHistoryData();

    if (searchInput) {
        let debounceTimer;
        searchInput.addEventListener("input", () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(loadHistoryData, 300);
        });
    }

    if (filterSelect) {
        filterSelect.addEventListener("change", loadHistoryData);
    }

    if (sortSelect) {
        sortSelect.addEventListener("change", loadHistoryData);
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", async () => {
            if (confirm("Are you sure you want to permanently clear all scan audit records?")) {
                try {
                    const res = await fetch("/api/scans/clear", { method: "POST" });
                    const d = await res.json();
                    if (d.success) {
                        showToast(`Audit history cleared (${d.cleared_count} records).`, "success");
                        loadHistoryData();
                    }
                } catch (e) {
                    showToast("Failed to clear history.", "danger");
                }
            }
        });
    }
}

async function loadHistoryData() {
    const tbody = document.getElementById("historyTableBody");
    const countBadge = document.getElementById("historyCountBadge");
    if (!tbody) return;

    const search = document.getElementById("historySearch")?.value || "";
    const filter = document.getElementById("historyFilter")?.value || "";
    const sort = document.getElementById("historySort")?.value || "date_desc";

    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted"><div class="spinner-border spinner-border-sm me-2"></div>Loading audit records...</td></tr>`;

    try {
        const url = `/api/scans?search=${encodeURIComponent(search)}&classification=${encodeURIComponent(filter)}&sort=${encodeURIComponent(sort)}`;
        const res = await fetch(url);
        const data = await res.json();

        if (countBadge) countBadge.textContent = `${data.count} Scans`;

        if (data.scans && data.scans.length > 0) {
            tbody.innerHTML = "";
            data.scans.forEach((s, idx) => {
                const tr = document.createElement("tr");
                const colorCode = s.classification_slug === 'safe' ? 'success' : (s.classification_slug === 'suspicious' ? 'warning' : 'danger');
                
                tr.innerHTML = `
                    <td class="text-muted fw-mono">#${s.scan_uuid || s.id}</td>
                    <td><div class="fw-semibold text-truncate" style="max-width: 280px;" title="${s.submitted_url}">${s.submitted_url}</div></td>
                    <td><span class="badge bg-dark border border-secondary text-light">${s.domain || 'N/A'}</span></td>
                    <td><span class="badge-threat ${s.classification_slug} py-1 px-2" style="font-size: 0.75rem;">${s.classification}</span></td>
                    <td><span class="fw-bold text-${colorCode}">${s.risk_score}</span> <span class="text-muted small">/100</span></td>
                    <td class="text-muted small">${s.created_at}</td>
                    <td class="text-end">
                        <div class="btn-group btn-group-sm">
                            <a href="/report/${s.id}" class="btn btn-outline-info" title="View Full Report"><i class="bi bi-file-earmark-text"></i></a>
                            <a href="/api/reports/download/${s.id}" class="btn btn-outline-secondary" title="Download PDF"><i class="bi bi-download"></i></a>
                            <button class="btn btn-outline-danger" onclick="deleteScanItem(${s.id})" title="Delete Record"><i class="bi bi-trash"></i></button>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center py-5 text-muted">
                        <i class="bi bi-folder-x fs-1 d-block mb-2"></i>
                        No audit records matched your search query.
                    </td>
                </tr>
            `;
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">Failed to load history records.</td></tr>`;
    }
}

window.deleteScanItem = async function(id) {
    if (!confirm(`Delete scan record #${id}?`)) return;
    try {
        const res = await fetch(`/api/scans/${id}`, { method: "DELETE" });
        const d = await res.json();
        if (d.success) {
            showToast("Record deleted.", "success");
            loadHistoryData();
        } else {
            showToast(d.error || "Failed to delete record.", "danger");
        }
    } catch (e) {
        showToast("Error communicating with server.", "danger");
    }
};

/* ==========================================================================
   4. Utility: Toast Notifications & Copy to Clipboard
   ========================================================================== */
function showToast(message, type = "info") {
    let toastContainer = document.getElementById("toastContainer");
    if (!toastContainer) {
        toastContainer = document.createElement("div");
        toastContainer.id = "toastContainer";
        toastContainer.className = "toast-container position-fixed bottom-0 end-0 p-3";
        toastContainer.style.zIndex = "9999";
        document.body.appendChild(toastContainer);
    }

    const toastEl = document.createElement("div");
    toastEl.className = `toast align-items-center text-bg-${type === 'danger' ? 'danger' : (type === 'success' ? 'success' : 'primary')} border-0 show`;
    toastEl.setAttribute("role", "alert");
    toastEl.innerHTML = `
        <div class="d-flex">
            <div class="toast-body"><i class="bi bi-info-circle me-2"></i>${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    toastContainer.appendChild(toastEl);
    setTimeout(() => {
        toastEl.classList.remove("show");
        toastEl.remove();
    }, 4000);
}

function initCopyButtons() {
    document.addEventListener("click", (e) => {
        const btn = e.target.closest(".btn-copy");
        if (btn) {
            const targetId = btn.getAttribute("data-copy-target");
            const targetEl = document.getElementById(targetId);
            if (targetEl) {
                const text = targetEl.textContent || targetEl.value;
                navigator.clipboard.writeText(text).then(() => {
                    showToast("Copied to clipboard!", "success");
                }).catch(() => {
                    showToast("Failed to copy.", "warning");
                });
            }
        }
    });
}
