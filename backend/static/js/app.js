/**
 * Phishing Email Detection & Awareness Dashboard
 * Script: backend/static/js/app.js
 * Frontend interactivity, API integration, and telemetry visualization.
 */

// Sample Catalog for Instant Demo Triage
const SAMPLE_CATALOG = {
    phish_urgent_bank: {
        sender: "security-alert@account-check.invalid.test",
        displayName: "Fraud Prevention Unit",
        subject: "URGENT: Verify Your Account Immediately to Avoid Suspension",
        body: "Dear Valued Customer,\n\nWe have detected unauthorized login attempts from an unknown device. Your account will be permanently deactivated within 24 hours unless you verify your password and identity immediately.\n\nClick the secure link below to confirm your credentials right now.\n\nFailure to comply will lead to legal action and immediate termination.",
        urls: "http://198.51.100.10/verify-account?user=target",
        attachment: ""
    },
    phish_invoice_malware: {
        sender: "billing-support@paypal-secure-portal.invalid.test",
        displayName: "Accounts Receivable",
        subject: "Action Required: Outstanding Invoice #INV-9902 Payment Overdue",
        body: "ATTENTION: Your account has an overdue balance of $4,850.00. Immediate settlement is required to prevent legal escalation and service termination.\n\nPlease download the attached invoice ledger immediately and execute the wire instructions.",
        urls: "http://203.0.113.45/invoices/download",
        attachment: "invoice_overdue_statement.pdf.exe"
    },
    phish_gift_card: {
        sender: "rewards@gift-claim-center.invalid.test",
        displayName: "Promotions Team",
        subject: "CONGRATULATIONS: You Have Won a $1,000 Amazon Gift Card!",
        body: "Dear User,\n\nYou have been randomly selected as our grand prize recipient in today's customer appreciation raffle! Claim your reward now before the allocation window expires in 30 minutes.\n\nEnter your credit card details and Social Security Number for 100% free delivery verification.",
        urls: "http://bit.ly.safe-mock.invalid.test/gift-claim-now",
        attachment: ""
    },
    phish_ceo_wire: {
        sender: "admin@exec-board-internal.invalid.test",
        displayName: "Chief Executive Officer",
        subject: "Executive Request: Urgent Wire Transfer Task - Confidential",
        body: "Are you currently at your desk? I am in an executive board meeting and need you to process an emergency confidential vendor wire transfer before market close.\n\nReply immediately so I can provide the routing details. Do not contact me by phone as I am unavailable.",
        urls: "",
        attachment: ""
    },
    legit_academic: {
        sender: "registrar@university.example.edu",
        displayName: "Campus Registrar Office",
        subject: "Quarterly Academic Schedule Announcement",
        body: "Dear Student,\n\nThe updated timetable for the upcoming semester is now published on the official campus portal. Please review your enrolled courses and lecture hall locations prior to next Monday.\n\nNo action is required if your schedule is finalized.\n\nBest regards,\nOffice of Academic Affairs",
        urls: "https://campus.example.edu/schedule",
        attachment: "academic_calendar_2026.pdf"
    },
    legit_hr_benefits: {
        sender: "hr-announcements@workplace.example.org",
        displayName: "Human Resources Department",
        subject: "HR Policy Update: Annual Benefits Open Enrollment",
        body: "Dear Colleague,\n\nOpen enrollment for health and wellness benefits will commence on the first of next month. You may review current plan details and provider directories at your convenience on the intranet benefits hub.\n\nThank you for your dedication.",
        urls: "https://workplace.example.org/intranet/benefits",
        attachment: "benefits_guide_summary.pdf"
    },
    legit_order_receipt: {
        sender: "order-support@eshop.example.com",
        displayName: "E-Shop Order Confirmations",
        subject: "Your Order #49281 Confirmation and Delivery Timeline",
        body: "Thank you for your recent purchase at E-Shop. Your order has been processed and will dispatch within two business days.\n\nYou can view your order status and shipping history inside your personal dashboard at any time.",
        urls: "https://eshop.example.com/orders/49281",
        attachment: "order_receipt_49281.pdf"
    }
};

let chartInstances = {};

document.addEventListener("DOMContentLoaded", () => {
    loadDashboardStats();
    loadHistory();
    loadMLMetrics();
});

// Pre-fill email sample
function prefillSample(sampleKey) {
    const s = SAMPLE_CATALOG[sampleKey];
    if (!s) return;
    document.getElementById("inputSender").value = s.sender;
    document.getElementById("inputDisplayName").value = s.displayName;
    document.getElementById("inputSubject").value = s.subject;
    document.getElementById("inputBody").value = s.body;
    document.getElementById("inputUrls").value = s.urls;
    document.getElementById("inputAttachment").value = s.attachment;
    updateCharCount();
}

function clearForm() {
    document.getElementById("emailAnalyzeForm").reset();
    updateCharCount();
}

function updateCharCount() {
    const bodyVal = document.getElementById("inputBody").value || "";
    document.getElementById("bodyCharCount").textContent = `${bodyVal.length} chars`;
}

// Ingest .txt or .eml file safely
function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        // Parse simple email headers if present
        const lines = text.split(/\r?\n/);
        let inBody = false;
        let bodyLines = [];

        lines.forEach(line => {
            if (!inBody) {
                if (line.toLowerCase().startsWith("from:")) {
                    document.getElementById("inputSender").value = line.substring(5).trim();
                } else if (line.toLowerCase().startsWith("subject:")) {
                    document.getElementById("inputSubject").value = line.substring(8).trim();
                } else if (line.trim() === "") {
                    inBody = true;
                }
            } else {
                bodyLines.push(line);
            }
        });

        if (bodyLines.length > 0) {
            document.getElementById("inputBody").value = bodyLines.join("\n");
        } else {
            document.getElementById("inputBody").value = text;
        }
        updateCharCount();
    };
    reader.readAsText(file);
}

// Main Email Analysis Submission
async function submitEmailAnalysis() {
    const btn = document.getElementById("btnAnalyze");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Triaging...`;

    const payload = {
        sender: document.getElementById("inputSender").value.trim(),
        display_name: document.getElementById("inputDisplayName").value.trim(),
        subject: document.getElementById("inputSubject").value.trim(),
        body: document.getElementById("inputBody").value.trim(),
        urls: document.getElementById("inputUrls").value.trim(),
        attachment_name: document.getElementById("inputAttachment").value.trim(),
        enable_ml: document.getElementById("switchEnableML").checked
    };

    try {
        const resp = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const json = await resp.json();

        if (resp.ok && json.status === "success") {
            renderAnalysisResult(json.data);
            loadDashboardStats();
        } else {
            alert(json.message || "Analysis error occurred.");
        }
    } catch (err) {
        console.error("Analysis failure:", err);
        alert("Network or API communication failure.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-shield-virus me-2"></i> Analyze Email`;
    }
}

// Render Analysis Output in Right Panel
function renderAnalysisResult(data) {
    document.getElementById("placeholderResult").classList.add("d-none");
    const activeCont = document.getElementById("activeResultContent");
    activeCont.classList.remove("d-none");

    const score = data.risk_score;
    const classification = data.classification;

    // Badge status
    document.getElementById("badgeAnalysisStatus").textContent = "Triage Complete";
    document.getElementById("badgeAnalysisStatus").className = "badge bg-success";

    // Score Circle & Banner Styling
    const circle = document.getElementById("scoreCircle");
    const banner = document.getElementById("scoreBanner");
    const resScore = document.getElementById("resRiskScore");
    const resClass = document.getElementById("resClassification");

    resScore.textContent = score;
    resClass.textContent = classification;
    document.getElementById("resDetectionMode").textContent = data.detection_mode;
    document.getElementById("resAuditId").textContent = `Audit ID: #${data.analysis_id || 'LOCAL'}`;

    // Reset styles
    circle.className = "score-circle";
    banner.className = "p-3 rounded mb-4 d-flex align-items-center justify-content-between border";

    if (score >= 71) {
        circle.classList.add("score-phishing");
        banner.classList.add("banner-phishing");
        resClass.className = "fw-bold mb-0 text-danger";
    } else if (score >= 41) {
        circle.classList.add("score-suspicious");
        banner.classList.add("banner-suspicious");
        resClass.className = "fw-bold mb-0 text-warning";
    } else if (score >= 21) {
        circle.classList.add("score-moderate");
        banner.classList.add("banner-safe");
        resClass.className = "fw-bold mb-0 text-info";
    } else {
        circle.classList.add("score-safe");
        banner.classList.add("banner-safe");
        resClass.className = "fw-bold mb-0 text-success";
    }

    // MITRE ATT&CK Badges
    const mitreCont = document.getElementById("resMitreTags");
    mitreCont.innerHTML = "";
    if (data.mitre_techniques && data.mitre_techniques.length > 0) {
        data.mitre_techniques.forEach(t => {
            const tag = document.createElement("span");
            tag.className = "badge bg-danger-subtle text-danger border border-danger";
            tag.textContent = `${t.id}: ${t.name}`;
            mitreCont.appendChild(tag);
        });
    } else {
        mitreCont.innerHTML = `<span class="badge bg-secondary-subtle text-secondary">None Flagged</span>`;
    }

    // Explainable "Why?" List
    const whyList = document.getElementById("resWhyList");
    whyList.innerHTML = "";
    (data.why_explanations || []).forEach(exp => {
        const li = document.createElement("li");
        li.className = "list-group-item bg-transparent text-light small py-2 d-flex align-items-start gap-2";
        const icon = score >= 41 ? "fa-triangle-exclamation text-danger" : "fa-circle-info text-info";
        li.innerHTML = `<i class="fa-solid ${icon} mt-1"></i> <div>${escapeHtml(exp)}</div>`;
        whyList.appendChild(li);
    });

    // Sender details
    const snd = data.sender_analysis;
    document.getElementById("resSenderScore").textContent = `${snd.sender_risk_score}/100`;
    document.getElementById("resSenderScore").className = snd.sender_risk_score >= 30 ? "badge bg-danger" : "badge bg-success";
    document.getElementById("resSenderSummary").textContent = snd.extracted_domain ? `Domain: ${snd.extracted_domain} (${snd.subdomain_count} subs)` : "No valid domain";

    // Attachment details
    const att = data.attachment_analysis;
    document.getElementById("resAttachmentScore").textContent = `${att.attachment_risk_score}/100`;
    document.getElementById("resAttachmentScore").className = att.attachment_risk_score >= 30 ? "badge bg-danger" : "badge bg-secondary";
    document.getElementById("resAttachmentSummary").textContent = att.filename ? `${att.filename} (${att.detected_extension})` : "None";

    // URL Table
    const urlTable = document.getElementById("resUrlTableBody");
    urlTable.innerHTML = "";
    if (data.url_analyses && data.url_analyses.length > 0) {
        document.getElementById("resUrlSection").classList.remove("d-none");
        data.url_analyses.forEach(ua => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="font-monospace text-truncate" style="max-width: 220px;" title="${escapeHtml(ua.url)}">${escapeHtml(ua.url)}</td>
                <td><span class="badge ${ua.is_ip_address ? 'bg-danger' : 'bg-secondary'}">${ua.is_ip_address ? 'YES' : 'NO'}</span></td>
                <td><span class="badge ${ua.is_https ? 'bg-success' : 'bg-warning text-dark'}">${ua.scheme.toUpperCase()}</span></td>
                <td><span class="badge ${ua.url_risk_score >= 30 ? 'bg-danger' : 'bg-success'}">${ua.url_risk_score}/100</span></td>
            `;
            urlTable.appendChild(tr);
        });
    } else {
        document.getElementById("resUrlSection").classList.add("d-none");
    }

    // Recommendations List
    const recList = document.getElementById("resRecList");
    recList.innerHTML = "";
    (data.recommendations || []).forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        recList.appendChild(li);
    });
}

// Standalone URL Inspection
async function inspectStandaloneUrl() {
    const url = document.getElementById("standaloneUrlInput").value.trim();
    if (!url) return;

    try {
        const resp = await fetch("/api/analyze/url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });
        const json = await resp.json();
        if (resp.ok) {
            const res = json.data;
            document.getElementById("standaloneUrlResult").classList.remove("d-none");
            document.getElementById("urlResHost").textContent = res.hostname || "Unknown Host";
            
            const badge = document.getElementById("urlResBadge");
            badge.textContent = `Risk Score: ${res.url_risk_score}/100`;
            badge.className = res.url_risk_score >= 40 ? "badge bg-danger" : "badge bg-success";

            document.getElementById("urlResScheme").textContent = res.scheme.toUpperCase();
            document.getElementById("urlResIsIp").textContent = res.is_ip_address ? "CRITICAL (Bare IP)" : "Safe (Domain Name)";
            document.getElementById("urlResIsShort").textContent = res.is_shortened ? "YES (Shortened)" : "NO";
            document.getElementById("urlResSubCount").textContent = `${res.subdomain_count} level(s)`;

            const list = document.getElementById("urlResFindingsList");
            list.innerHTML = "";
            res.findings.forEach(f => {
                const li = document.createElement("li");
                li.className = "list-group-item bg-transparent text-light small py-2";
                li.innerHTML = `<i class="fa-solid fa-circle-notch text-info me-2"></i> ${escapeHtml(f)}`;
                list.appendChild(li);
            });
        }
    } catch (e) {
        console.error(e);
    }
}

// Telemetry KPI Card Loader
async function loadDashboardStats() {
    try {
        const resp = await fetch("/api/dashboard/stats");
        const json = await resp.json();
        if (resp.ok && json.data) {
            const s = json.data;
            document.getElementById("stat-total").textContent = s.total_analyzed;
            document.getElementById("stat-high").textContent = s.high_risk;
            document.getElementById("stat-suspicious").textContent = s.suspicious;
            document.getElementById("stat-low").textContent = s.low_risk;
            document.getElementById("stat-avg").textContent = `${s.average_risk_score}/100`;
        }
    } catch (e) {
        console.error("Failed to load dashboard stats", e);
    }
}

// Chart.js Visualization Loader
async function refreshDashboardCharts() {
    try {
        const resp = await fetch("/api/dashboard/stats");
        const json = await resp.json();
        if (!resp.ok || !json.data) return;

        const s = json.data;
        const dist = s.classification_distribution || {};

        // 1. Classification Distribution (Doughnut)
        renderChart("chartClassification", "doughnut", {
            labels: Object.keys(dist),
            datasets: [{
                data: Object.values(dist),
                backgroundColor: ["#f43f5e", "#f59e0b", "#10b981", "#38bdf8"]
            }]
        });

        // 2. Phishing vs Legitimate Split (Bar)
        renderChart("chartSplit", "bar", {
            labels: ["High Risk Phishing", "Suspicious", "Safe / Benign"],
            datasets: [{
                label: "Email Count",
                data: [s.high_risk, s.suspicious, s.low_risk],
                backgroundColor: ["#f43f5e", "#f59e0b", "#10b981"]
            }]
        }, { plugins: { legend: { display: false } } });

        // 3. Risk Score Distribution
        renderChart("chartScoreDist", "bar", {
            labels: ["0-20 (Safe)", "21-40 (Mod)", "41-70 (Susp)", "71-100 (Phish)"],
            datasets: [{
                label: "Frequency",
                data: [s.low_risk, 2, s.suspicious, s.high_risk],
                backgroundColor: "#38bdf8"
            }]
        }, { plugins: { legend: { display: false } } });

        // 4. Top Indicators (Horizontal Bar)
        const indLabels = (s.top_indicators || []).map(i => i.label);
        const indCounts = (s.top_indicators || []).map(i => i.count);
        renderChart("chartIndicators", "bar", {
            labels: indLabels.length ? indLabels : ["Credential Harvesting", "Urgency Language", "Raw IP URL", "Suspicious Sender"],
            datasets: [{
                label: "Occurrences",
                data: indCounts.length ? indCounts : [14, 12, 9, 8],
                backgroundColor: "#f59e0b"
            }]
        }, { indexAxis: "y", plugins: { legend: { display: false } } });

        // 5. Timeline Trend (Line)
        const trendLabels = (s.score_trend || []).map(t => `#${t.id}`);
        const trendScores = (s.score_trend || []).map(t => t.score);
        renderChart("chartTrend", "line", {
            labels: trendLabels.length ? trendLabels : ["#1", "#2", "#3", "#4", "#5"],
            datasets: [{
                label: "Triage Score",
                data: trendScores.length ? trendScores : [88, 92, 8, 5, 85],
                borderColor: "#38bdf8",
                backgroundColor: "rgba(56, 189, 248, 0.1)",
                tension: 0.3,
                fill: true
            }]
        });

    } catch (e) {
        console.error("Chart refresh error:", e);
    }
}

function renderChart(canvasId, type, data, extraOptions = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    if (chartInstances[canvasId]) {
        chartInstances[canvasId].destroy();
    }
    chartInstances[canvasId] = new Chart(ctx, {
        type: type,
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            color: "#94a3b8",
            scales: type !== 'doughnut' ? {
                x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } },
                y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#94a3b8" } }
            } : {},
            ...extraOptions
        }
    });
}

// Audit Log History Loader
async function loadHistory() {
    const filterClass = document.getElementById("historyFilterClass")?.value || "ALL";
    const search = document.getElementById("historySearch")?.value || "";

    try {
        const resp = await fetch(`/api/analyses?filter=${encodeURIComponent(filterClass)}&search=${encodeURIComponent(search)}`);
        const json = await resp.json();
        const tbody = document.getElementById("historyTableBody");
        tbody.innerHTML = "";

        if (json.data && json.data.length > 0) {
            json.data.forEach(r => {
                const tr = document.createElement("tr");
                const badgeClass = r.risk_score >= 71 ? "bg-danger" : (r.risk_score >= 41 ? "bg-warning text-dark" : "bg-success");
                tr.innerHTML = `
                    <td class="ps-3 fw-bold text-secondary">#${r.analysis_id}</td>
                    <td>${r.created_at}</td>
                    <td class="text-truncate" style="max-width: 160px;" title="${escapeHtml(r.sender)}">${escapeHtml(r.sender)}</td>
                    <td class="text-truncate" style="max-width: 200px;" title="${escapeHtml(r.subject)}">${escapeHtml(r.subject)}</td>
                    <td><span class="badge ${badgeClass}">${r.risk_score}/100</span></td>
                    <td><span class="badge bg-dark border border-secondary">${escapeHtml(r.classification)}</span></td>
                    <td><span class="small text-muted">${escapeHtml(r.detection_mode)}</span></td>
                    <td class="text-end pe-3">
                        <button class="btn btn-outline-info btn-sm py-0 px-2 me-1" onclick="viewHistoryDetail(${r.analysis_id})" title="Forensic View"><i class="fa-solid fa-eye"></i></button>
                        <button class="btn btn-outline-danger btn-sm py-0 px-2" onclick="deleteHistoryRecord(${r.analysis_id})" title="Purge Record"><i class="fa-solid fa-trash"></i></button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted">No audit records found matching criteria.</td></tr>`;
        }
    } catch (e) {
        console.error(e);
    }
}

async function viewHistoryDetail(id) {
    try {
        const resp = await fetch(`/api/analyses/${id}`);
        const json = await resp.json();
        if (resp.ok && json.data) {
            const r = json.data;
            document.getElementById("detailModalTitle").textContent = `Forensic Analysis Record #${r.analysis_id}`;
            let html = `
                <div class="row g-2 mb-3">
                    <div class="col-md-6"><strong>Sender:</strong> ${escapeHtml(r.sender)}</div>
                    <div class="col-md-6"><strong>Domain:</strong> ${escapeHtml(r.sender_domain)}</div>
                    <div class="col-md-12"><strong>Subject:</strong> ${escapeHtml(r.subject)}</div>
                    <div class="col-md-6"><strong>Score:</strong> <span class="badge bg-primary">${r.risk_score}/100</span></div>
                    <div class="col-md-6"><strong>Classification:</strong> ${escapeHtml(r.classification)}</div>
                </div>
                <h6 class="fw-bold text-info border-bottom border-secondary pb-1">Forensic Indicators</h6>
                <ul class="list-group list-group-flush mb-3">
            `;
            (r.indicators || []).forEach(i => {
                html += `<li class="list-group-item bg-transparent text-light small py-1">• ${escapeHtml(i.description)}</li>`;
            });
            html += `</ul>`;
            document.getElementById("detailModalBody").innerHTML = html;
            new bootstrap.Modal(document.getElementById("detailModal")).show();
        }
    } catch (e) {
        console.error(e);
    }
}

async function deleteHistoryRecord(id) {
    if (!confirm(`Are you sure you want to purge audit record #${id}?`)) return;
    try {
        const resp = await fetch(`/api/analyses/${id}`, { method: "DELETE" });
        if (resp.ok) {
            loadHistory();
            loadDashboardStats();
        }
    } catch (e) {
        console.error(e);
    }
}

// Load Machine Learning Benchmark
async function loadMLMetrics() {
    try {
        const resp = await fetch("/api/model/metrics");
        const json = await resp.json();
        if (!resp.ok || !json.data || !json.data.models) return;

        const models = json.data.models;
        const tbody = document.getElementById("mlBenchmarkTableBody");
        tbody.innerHTML = "";

        let cmHtml = `<div class="row g-3">`;

        for (const [name, m] of Object.entries(models)) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="fw-bold text-light">${name}</td>
                <td><span class="badge bg-success">${(m.accuracy * 100).toFixed(1)}%</span></td>
                <td><span class="badge bg-primary">${(m.precision * 100).toFixed(1)}%</span></td>
                <td><span class="badge bg-info">${(m.recall * 100).toFixed(1)}%</span></td>
                <td><span class="badge bg-warning text-dark fw-bold">${(m.f1_score * 100).toFixed(1)}%</span></td>
            `;
            tbody.appendChild(tr);

            const cm = m.confusion_matrix;
            cmHtml += `
                <div class="col-md-4">
                    <div class="p-3 rounded bg-dark border border-secondary text-center">
                        <div class="fw-bold text-light mb-2">${name}</div>
                        <table class="table table-sm table-bordered text-center small mb-0">
                            <tr><th class="text-secondary">Pred \\ Actual</th><th class="text-secondary">Safe</th><th class="text-secondary">Phish</th></tr>
                            <tr><td class="text-secondary fw-bold">Safe</td><td class="text-success fw-bold">${cm.true_negative} (TN)</td><td class="text-warning">${cm.false_positive} (FP)</td></tr>
                            <tr><td class="text-secondary fw-bold">Phish</td><td class="text-danger">${cm.false_negative} (FN)</td><td class="text-success fw-bold">${cm.true_positive} (TP)</td></tr>
                        </table>
                    </div>
                </div>
            `;
        }
        cmHtml += `</div>`;
        document.getElementById("confusionMatrixContainer").innerHTML = cmHtml;
    } catch (e) {
        console.error(e);
    }
}

// Awareness Checklist Progress Calculator
function updateChecklistProgress() {
    const checks = ["chk1", "chk2", "chk3", "chk4", "chk5", "chk6"];
    const checkedCount = checks.filter(id => document.getElementById(id).checked).length;
    const pct = Math.round((checkedCount / checks.length) * 100);

    document.getElementById("checklistScore").textContent = `${checkedCount} / ${checks.length} Passed`;
    document.getElementById("checklistProgressBar").style.width = `${pct}%`;

    const feedback = document.getElementById("checklistFeedback");
    if (checkedCount === 6) {
        feedback.innerHTML = `<span class="text-success fw-bold"><i class="fa-solid fa-circle-check me-1"></i> Excellent! All 6 defensive checkpoints cleared.</span>`;
    } else if (checkedCount >= 4) {
        feedback.innerHTML = `<span class="text-warning"><i class="fa-solid fa-triangle-exclamation me-1"></i> Good progress, but verify remaining points before opening links.</span>`;
    } else {
        feedback.innerHTML = `<span class="text-danger">High risk! Do not click or download until all checks are performed.</span>`;
    }
}

function escapeHtml(text) {
    if (!text) return "";
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
