/**
 * DefendPass — Frontend Application Controller
 * Handles real-time password analysis, debouncing, UI animations,
 * Chart.js visualizations, policy audits, and CSPRNG generation.
 */

// Global Chart Instances for dynamic updates
let chartClassificationsInstance = null;
let chartScoresInstance = null;
let chartWeaknessesInstance = null;
let chartLengthsInstance = null;

// Debounce timer handle
let debounceTimer = null;

document.addEventListener("DOMContentLoaded", () => {
    initNavigationTabs();
    initPasswordInputControls();
    initContextAccordion();
    initDemoChips();
    initGenerators();
    initDashboardRefresh();

    // Trigger initial empty state evaluation
    evaluatePassword("");

    // Initial load of dashboard charts
    loadDashboardAnalytics();
});

/* ==========================================================================
   Navigation Tabs Controller
   ========================================================================== */
function initNavigationTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");

            tabButtons.forEach(b => b.classList.remove("active"));
            tabPanes.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.add("active");
            }

            // Refresh charts if switching to dashboard
            if (targetId === "tabDashboard") {
                loadDashboardAnalytics();
            }
        });
    });
}

/* ==========================================================================
   Password Input & Real-Time Analyzer
   ========================================================================== */
function initPasswordInputControls() {
    const passwordInput = document.getElementById("passwordInput");
    const btnToggle = document.getElementById("btnTogglePassword");
    const toggleIcon = document.getElementById("togglePasswordIcon");
    const btnClear = document.getElementById("btnClearPassword");

    // Real-time debounced evaluation
    passwordInput.addEventListener("input", () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            evaluatePassword(passwordInput.value);
        }, 120);
    });

    // Show/Hide toggle
    btnToggle.addEventListener("click", () => {
        if (passwordInput.type === "password") {
            passwordInput.type = "text";
            toggleIcon.classList.remove("fa-eye");
            toggleIcon.classList.add("fa-eye-slash");
            btnToggle.title = "Hide password";
        } else {
            passwordInput.type = "password";
            toggleIcon.classList.remove("fa-eye-slash");
            toggleIcon.classList.add("fa-eye");
            btnToggle.title = "Show password";
        }
    });

    // Clear input
    btnClear.addEventListener("click", () => {
        passwordInput.value = "";
        passwordInput.focus();
        evaluatePassword("");
    });
}

function initContextAccordion() {
    const btnToggleContext = document.getElementById("btnToggleContext");
    const contextBody = document.getElementById("contextBody");
    const arrow = document.getElementById("contextArrow");

    btnToggleContext.addEventListener("click", () => {
        const isHidden = contextBody.classList.contains("hidden");
        if (isHidden) {
            contextBody.classList.remove("hidden");
            arrow.classList.add("rotated");
        } else {
            contextBody.classList.add("hidden");
            arrow.classList.remove("rotated");
        }
    });

    // Re-evaluate if context changes
    ["ctxFirstName", "ctxBirthYear", "ctxCompany"].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener("input", () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    const pwd = document.getElementById("passwordInput").value;
                    evaluatePassword(pwd);
                }, 200);
            });
        }
    });
}

function initDemoChips() {
    const chips = document.querySelectorAll(".demo-chip");
    const passwordInput = document.getElementById("passwordInput");

    chips.forEach(chip => {
        chip.addEventListener("click", async () => {
            const demoVal = chip.getAttribute("data-val");
            if (demoVal) {
                passwordInput.value = demoVal;
                evaluatePassword(demoVal);
            } else if (chip.id === "demoChip6") {
                // Fetch random CSPRNG 20
                try {
                    const res = await fetch("/api/generate-password", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ length: 20 })
                    });
                    const data = await res.json();
                    if (data.status === "success") {
                        passwordInput.value = data.data.password;
                        evaluatePassword(data.data.password);
                    }
                } catch (e) {
                    showToast("Failed to generate demo password", "error");
                }
            }
        });
    });
}

/* ==========================================================================
   Evaluate Password via Backend API
   ========================================================================== */
async function evaluatePassword(password) {
    if (!password) {
        resetUI();
        return;
    }

    const context = {
        firstName: document.getElementById("ctxFirstName")?.value || "",
        birthYear: document.getElementById("ctxBirthYear")?.value || "",
        companyName: document.getElementById("ctxCompany")?.value || ""
    };

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                password: password,
                context: context,
                save_analytics: true
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error ${response.status}`);
        }

        const data = await response.json();
        updateUIWithResults(data);
    } catch (error) {
        // Fallback local visual update if backend is starting or offline
        console.warn("API request failed:", error);
    }
}

function resetUI() {
    document.getElementById("scoreNumber").textContent = "0";
    document.getElementById("classificationPill").textContent = "NO INPUT";
    document.getElementById("classificationPill").style.background = "rgba(255, 255, 255, 0.08)";
    document.getElementById("classificationPill").style.color = "var(--text-secondary)";
    document.getElementById("gradePill").textContent = "GRADE: -";
    document.getElementById("meterBarFill").style.width = "0%";
    document.getElementById("meterBarFill").style.background = "var(--text-muted)";
    document.getElementById("scoreCircle").style.borderColor = "var(--text-muted)";
    document.getElementById("scoreCircle").style.boxShadow = "none";
    document.getElementById("scoreSummaryText").textContent =
        "Enter a candidate password above to perform instant defensive inspection across length, randomness, sequences, and pattern resistance.";

    // Metric reset
    document.getElementById("valLength").textContent = "0";
    document.getElementById("badgeLengthBand").textContent = "No Input";
    document.getElementById("badgeLengthBand").className = "metric-band-badge";
    document.getElementById("captionLength").textContent = "Length is the primary exponential exponent in brute-force difficulty.";

    document.getElementById("valDiversityTypes").textContent = "0 / 4";
    ["pillLower", "pillUpper", "pillDigit", "pillSymbol"].forEach(p => {
        document.getElementById(p)?.classList.remove("active");
    });

    document.getElementById("valUniqueCount").textContent = "0";
    document.getElementById("valUniqueRatio").textContent = "0%";
    document.getElementById("varietyProgressFill").style.width = "0%";

    document.getElementById("valEffectiveBits").textContent = "0.0";
    document.getElementById("valTheoreticalBits").textContent = "0.0";
    document.getElementById("valPoolSize").textContent = "0";

    // Findings & Suggestions
    document.getElementById("findingsCountBadge").textContent = "0 Detected";
    document.getElementById("findingsList").innerHTML = `
        <div class="empty-state-notice">
            <i class="fa-solid fa-shield-cat"></i>
            <p>No weaknesses detected or no candidate password entered yet.</p>
        </div>
    `;

    document.getElementById("passphraseCallout").classList.add("hidden");
    document.getElementById("immediateActionsList").innerHTML = `
        <li>Enter a password to generate customized defensive recommendations.</li>
    `;

    // Policy reset
    document.getElementById("policyStatusTag").textContent = "Awaiting Evaluation";
    document.getElementById("policyStatusTag").className = "policy-status-tag";
    document.getElementById("policyRulesList").innerHTML = "";
}

function updateUIWithResults(data) {
    const score = data.score;
    const classification = data.classification;
    const color = data.color;
    const grade = data.grade;
    const metrics = data.metrics;
    const findings = data.findings;
    const suggestions = data.suggestions;

    // 1. Score & Hero Gauge
    document.getElementById("scoreNumber").textContent = score;
    const circle = document.getElementById("scoreCircle");
    circle.style.borderColor = color;
    circle.style.boxShadow = `0 0 25px ${color}44`;

    const pill = document.getElementById("classificationPill");
    pill.textContent = classification;
    pill.style.background = `${color}22`;
    pill.style.color = color;
    pill.style.borderColor = color;

    document.getElementById("gradePill").textContent = `GRADE: ${grade}`;

    const meterFill = document.getElementById("meterBarFill");
    meterFill.style.width = `${Math.max(4, score)}%`;
    meterFill.style.background = color;

    // Summary Text
    let summaryText = "";
    if (score <= 20) {
        summaryText = "Critical risk: Highly vulnerable to instant dictionary, sequence, or mask attacks. Immediate remediation required.";
    } else if (score <= 40) {
        summaryText = "Weak strength: Susceptible to standard rule-based cracking or dictionary expansion attacks.";
    } else if (score <= 60) {
        summaryText = "Moderate strength: Contains acceptable elements but possesses identifiable structural patterns or modest length.";
    } else if (score <= 80) {
        summaryText = "Strong password: Solid length and pattern resistance. Resilient against standard automated attacks.";
    } else {
        summaryText = "Exceptional defensive strength: Outstanding length, high entropy, and excellent unpredictability.";
    }
    document.getElementById("scoreSummaryText").textContent = summaryText;

    // 2. Length Metrics
    const lenMeta = metrics.length;
    document.getElementById("valLength").textContent = lenMeta.length;
    const lenBadge = document.getElementById("badgeLengthBand");
    lenBadge.textContent = lenMeta.band;
    lenBadge.className = `metric-band-badge band-${lenMeta.status}`;
    document.getElementById("captionLength").textContent = lenMeta.explanation;

    // 3. Character Diversity
    const charMeta = metrics.characters;
    document.getElementById("valDiversityTypes").textContent = `${charMeta.character_types_present} / 4`;
    togglePill("pillLower", charMeta.lowercase > 0);
    togglePill("pillUpper", charMeta.uppercase > 0);
    togglePill("pillDigit", charMeta.digits > 0);
    togglePill("pillSymbol", charMeta.symbols > 0);

    // 4. Variety & Uniqueness
    document.getElementById("valUniqueCount").textContent = charMeta.unique_count;
    const ratioPct = Math.round(charMeta.unique_character_ratio * 100);
    document.getElementById("valUniqueRatio").textContent = `${ratioPct}%`;
    document.getElementById("varietyProgressFill").style.width = `${ratioPct}%`;

    // 5. Entropy
    const entMeta = metrics.entropy;
    document.getElementById("valEffectiveBits").textContent = entMeta.effective_bits;
    document.getElementById("valTheoreticalBits").textContent = entMeta.theoretical_bits;
    document.getElementById("valPoolSize").textContent = entMeta.pool_size;

    // 6. Findings List
    const findingsList = document.getElementById("findingsList");
    document.getElementById("findingsCountBadge").textContent = `${findings.length} Detected`;

    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="empty-state-notice">
                <i class="fa-solid fa-shield-check" style="color: var(--emerald-primary);"></i>
                <p style="color: var(--emerald-primary); font-weight: 600;">Zero predictable patterns or dictionary sequences detected!</p>
            </div>
        `;
    } else {
        findingsList.innerHTML = findings.map(f => `
            <div class="finding-item sev-${f.severity}">
                <div class="finding-icon">
                    <i class="fa-solid ${getFindingIcon(f.type)}"></i>
                </div>
                <div class="finding-info">
                    <div class="finding-title">${f.pattern || f.type}</div>
                    <div class="finding-desc">${f.description}</div>
                </div>
            </div>
        `).join("");
    }

    // 7. Security Suggestions
    const immList = document.getElementById("immediateActionsList");
    if (suggestions.immediate_actions && suggestions.immediate_actions.length > 0) {
        immList.innerHTML = suggestions.immediate_actions.map(action => `<li>${action}</li>`).join("");
    } else {
        immList.innerHTML = `<li>No critical weaknesses found. Maintain unique credentials across all accounts.</li>`;
    }

    const passphraseCallout = document.getElementById("passphraseCallout");
    if (suggestions.passphrase_tip) {
        passphraseCallout.classList.remove("hidden");
        document.getElementById("passphraseTipText").textContent = suggestions.passphrase_tip;
    } else {
        passphraseCallout.classList.add("hidden");
    }

    // 8. Policy Evaluation View
    const policy = metrics.policy;
    if (policy) {
        updatePolicyView(policy);
    }
}

function togglePill(id, isActive) {
    const el = document.getElementById(id);
    if (!el) return;
    if (isActive) el.classList.add("active");
    else el.classList.remove("active");
}

function getFindingIcon(type) {
    switch (type) {
        case "common_password": return "fa-book-skull";
        case "numeric_sequence": return "fa-arrow-down-1-9";
        case "alphabetical_sequence": return "fa-arrow-down-a-z";
        case "keyboard_pattern": return "fa-keyboard";
        case "repeated_characters":
        case "repeated_substring": return "fa-clone";
        case "predictable_year": return "fa-calendar-xmark";
        case "predictable_formula": return "fa-cubes";
        case "personal_information": return "fa-id-card";
        default: return "fa-triangle-exclamation";
    }
}

function updatePolicyView(policy) {
    const tag = document.getElementById("policyStatusTag");
    if (policy.policy_passed) {
        tag.textContent = "POLICY PASSED";
        tag.className = "policy-status-tag passed";
    } else {
        tag.textContent = "POLICY FAILED";
        tag.className = "policy-status-tag failed";
    }

    const rulesList = document.getElementById("policyRulesList");
    rulesList.innerHTML = policy.rules.map(r => `
        <div class="policy-rule-row">
            <div class="rule-main-info">
                <div class="rule-check-icon ${r.passed ? 'passed' : 'failed'}">
                    <i class="fa-solid ${r.passed ? 'fa-check' : 'fa-xmark'}"></i>
                </div>
                <div>
                    <div class="rule-title">${r.rule}</div>
                    <div class="rule-detail">${r.detail}</div>
                </div>
            </div>
            <div class="rule-status-badge ${r.passed ? 'passed' : 'failed'}">
                ${r.passed ? 'PASSED' : 'VIOLATION'}
            </div>
        </div>
    `).join("");
}

/* ==========================================================================
   Generators: CSPRNG Password & Passphrase Studio
   ========================================================================== */
function initGenerators() {
    // Password Range Slider
    const pwdRange = document.getElementById("pwdLengthRange");
    const pwdVal = document.getElementById("pwdLengthVal");
    pwdRange.addEventListener("input", () => {
        pwdVal.textContent = pwdRange.value;
    });

    // Passphrase Range Slider
    const phraseRange = document.getElementById("phraseWordRange");
    const phraseVal = document.getElementById("phraseWordVal");
    phraseRange.addEventListener("input", () => {
        phraseVal.textContent = `${phraseRange.value} words`;
    });

    // Generate Password Button
    document.getElementById("btnGeneratePassword").addEventListener("click", async () => {
        const payload = {
            length: parseInt(pwdRange.value),
            use_upper: document.getElementById("chkUpper").checked,
            use_lower: document.getElementById("chkLower").checked,
            use_digits: document.getElementById("chkDigits").checked,
            use_symbols: document.getElementById("chkSymbols").checked
        };
        try {
            const res = await fetch("/api/generate-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const json = await res.json();
            if (json.status === "success") {
                document.getElementById("genPwdOutput").value = json.data.password;
            }
        } catch (e) {
            showToast("Error generating password", "error");
        }
    });

    // Generate Passphrase Button
    document.getElementById("btnGeneratePassphrase").addEventListener("click", async () => {
        const payload = {
            word_count: parseInt(phraseRange.value),
            separator: document.getElementById("phraseSeparator").value,
            capitalize: document.getElementById("chkCapitalize").checked
        };
        try {
            const res = await fetch("/api/generate-passphrase", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const json = await res.json();
            if (json.status === "success") {
                document.getElementById("genPassphraseOutput").value = json.data.passphrase;
            }
        } catch (e) {
            showToast("Error generating passphrase", "error");
        }
    });

    // Copy Buttons
    document.getElementById("btnCopyGenPwd").addEventListener("click", () => {
        const val = document.getElementById("genPwdOutput").value;
        if (val) copyToClipboard(val, "Password copied to clipboard!");
    });

    document.getElementById("btnCopyGenPassphrase").addEventListener("click", () => {
        const val = document.getElementById("genPassphraseOutput").value;
        if (val) copyToClipboard(val, "Passphrase copied to clipboard!");
    });

    // Send to Analyzer Buttons
    document.getElementById("btnTestGenerated").addEventListener("click", () => {
        const val = document.getElementById("genPwdOutput").value;
        if (val) transferToAnalyzer(val);
    });

    document.getElementById("btnTestPassphrase").addEventListener("click", () => {
        const val = document.getElementById("genPassphraseOutput").value;
        if (val) transferToAnalyzer(val);
    });
}

function transferToAnalyzer(text) {
    const input = document.getElementById("passwordInput");
    input.value = text;
    // Switch to analyzer tab
    document.getElementById("tabBtnAnalyzer").click();
    evaluatePassword(text);
    showToast("Sent to Live Analyzer!", "success");
}

function copyToClipboard(text, message) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(message, "success");
    }).catch(() => {
        showToast("Clipboard write permission denied", "error");
    });
}

/* ==========================================================================
   Privacy Analytics Dashboard (Chart.js)
   ========================================================================== */
function initDashboardRefresh() {
    document.getElementById("btnRefreshDashboard")?.addEventListener("click", () => {
        loadDashboardAnalytics();
        showToast("Telemetry data refreshed", "success");
    });
}

async function loadDashboardAnalytics() {
    try {
        // 1. Summary stats
        const statsRes = await fetch("/api/dashboard/stats");
        const statsData = (await statsRes.json()).data;

        document.getElementById("dashTotalAnalyses").textContent = statsData.total_analyses;
        document.getElementById("dashAvgScore").textContent = statsData.average_score;
        document.getElementById("dashAvgLength").textContent = statsData.average_length;
        document.getElementById("dashAvgEntropy").textContent = statsData.average_entropy;

        renderClassificationChart(statsData.classification_distribution);

        // 2. Score distribution
        const scoreRes = await fetch("/api/analytics/score-distribution");
        const scoreData = (await scoreRes.json()).data;
        renderScoresChart(scoreData);

        // 3. Weaknesses frequency
        const weakRes = await fetch("/api/analytics/weaknesses");
        const weakData = (await weakRes.json()).data;
        renderWeaknessesChart(weakData);

        // 4. Length distribution
        const lenRes = await fetch("/api/analytics/length-distribution");
        const lenData = (await lenRes.json()).data;
        renderLengthsChart(lenData);

    } catch (e) {
        console.warn("Dashboard analytics fetch notice:", e);
    }
}

function renderClassificationChart(dist) {
    const ctx = document.getElementById("chartClassifications");
    if (!ctx) return;

    const labels = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"];
    const values = labels.map(l => dist[l] || 0);

    if (chartClassificationsInstance) {
        chartClassificationsInstance.destroy();
    }

    chartClassificationsInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    '#ef4444',
                    '#f97316',
                    '#eab308',
                    '#10b981',
                    '#059669'
                ],
                borderColor: '#111827',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                }
            },
            cutout: '68%'
        }
    });
}

function renderScoresChart(data) {
    const ctx = document.getElementById("chartScores");
    if (!ctx) return;

    const labels = data.map(d => d.bucket);
    const values = data.map(d => d.count);

    if (chartScoresInstance) {
        chartScoresInstance.destroy();
    }

    chartScoresInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Analyses Count',
                data: values,
                backgroundColor: 'rgba(99, 102, 241, 0.7)',
                borderColor: '#6366f1',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
            }
        }
    });
}

function renderWeaknessesChart(data) {
    const ctx = document.getElementById("chartWeaknesses");
    if (!ctx) return;

    const labels = data.map(d => d.type.replace(/_/g, ' '));
    const values = data.map(d => d.frequency);

    if (chartWeaknessesInstance) {
        chartWeaknessesInstance.destroy();
    }

    chartWeaknessesInstance = new Chart(ctx, {
        type: 'bar',
        indexAxis: 'y',
        data: {
            labels: labels,
            datasets: [{
                label: 'Occurrences',
                data: values,
                backgroundColor: 'rgba(244, 63, 94, 0.7)',
                borderColor: '#f43f5e',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
                y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
            }
        }
    });
}

function renderLengthsChart(data) {
    const ctx = document.getElementById("chartLengths");
    if (!ctx) return;

    const labels = data.map(d => d.band);
    const values = data.map(d => d.count);

    if (chartLengthsInstance) {
        chartLengthsInstance.destroy();
    }

    chartLengthsInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
                data: values,
                backgroundColor: 'rgba(6, 182, 212, 0.7)',
                borderColor: '#06b6d4',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
            }
        }
    });
}

/* ==========================================================================
   Toast Notification Helper
   ========================================================================== */
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon = type === "success" ? "fa-circle-check" : "fa-circle-info";
    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
