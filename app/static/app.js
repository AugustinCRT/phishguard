const form = document.querySelector("#analyze-form");
const result = document.querySelector("#result");
const scoreEl = document.querySelector("#score");
const scoreMeterFillEl = document.querySelector("#score-meter-fill");
const riskLevelEl = document.querySelector("#risk-level");
const domainDetailsEl = document.querySelector("#domain-details");
const findingsEl = document.querySelector("#findings");
const explanationEl = document.querySelector("#explanation");
const jsonReportEl = document.querySelector("#json-report");
const copyJsonButton = document.querySelector("#copy-json");
const historyListEl = document.querySelector("#history-list");
const clearHistoryButton = document.querySelector("#clear-history");

const HISTORY_KEY = "phishguard-history";
const MAX_HISTORY_ITEMS = 8;
const DEMO_URLS = {
  lookalike: "https://onefimesecret.com/",
  phishing: "http://paypal-secure-login.example.com/account",
  shortener: "https://bit.ly/3demo",
};
const RISK_LABELS = {
  low: "Faible",
  medium: "Moyen",
  high: "Eleve",
  critical: "Critique",
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setRiskLevel(level) {
  riskLevelEl.textContent = RISK_LABELS[level] || level;
  riskLevelEl.className = `risk ${level}`;
  scoreMeterFillEl.className = level;
}

function setScore(score) {
  const safeScore = Number.isFinite(Number(score)) ? Number(score) : 0;
  scoreEl.textContent = score;
  scoreMeterFillEl.style.width = `${Math.min(Math.max(safeScore, 0), 100)}%`;
}

function renderDomain(domain, https, redirections, safety) {
  const rows = [
    ["Hote", domain.hostname],
    ["Domaine estime", domain.registered_domain_estimate],
    ["Label principal", domain.primary_label],
    ["Sous-domaines", domain.subdomain_count],
    ["HTTPS", https.uses_https ? "oui" : "non"],
    ["Redirections", redirections.redirect_count],
    ["Analyse reseau", safety.network_allowed ? "autorisee" : "bloquee"],
  ];

  domainDetailsEl.innerHTML = rows
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value ?? "n/a")}</dd>`)
    .join("");
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsEl.innerHTML = "<li>Aucun signal notable detecte.</li>";
    return;
  }

  findingsEl.innerHTML = findings
    .map(
      (finding) =>
        `<li><strong>+${escapeHtml(finding.risk_points)}</strong> ${escapeHtml(finding.explanation)}</li>`,
    )
    .join("");
}

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveHistoryItem(payload) {
  const item = {
    url: payload.normalized_url,
    score: payload.score,
    risk_level: payload.risk_level,
    demo_mode: payload.demo_mode,
    created_at: new Date().toISOString(),
  };
  const nextHistory = [item, ...loadHistory().filter((entry) => entry.url !== item.url)]
    .slice(0, MAX_HISTORY_ITEMS);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(nextHistory));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();
  if (!history.length) {
    historyListEl.innerHTML = '<p class="empty-state">Aucune analyse pour le moment.</p>';
    return;
  }

  historyListEl.innerHTML = history
    .map(
      (item) => `
        <button type="button" class="history-item" data-history-url="${escapeHtml(item.url)}">
          <span>${escapeHtml(item.url)}</span>
          <strong class="risk ${escapeHtml(item.risk_level)}">${escapeHtml(item.score)}</strong>
        </button>
      `,
    )
    .join("");
}

async function analyze(url, demoMode = false) {
  const button = form.querySelector("button");
  button.disabled = true;
  button.textContent = "Analyse...";

  document.querySelector("#url").value = url;

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, demo_mode: demoMode }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Analyse impossible.");
    }

    result.classList.remove("hidden");
    setScore(payload.score);
    setRiskLevel(payload.risk_level);
    renderDomain(payload.domain, payload.https, payload.redirections, payload.safety);
    renderFindings(payload.findings);
    explanationEl.textContent = payload.explanation;
    jsonReportEl.textContent = JSON.stringify(payload, null, 2);
    saveHistoryItem(payload);
  } catch (error) {
    result.classList.remove("hidden");
    setScore(0);
    scoreEl.textContent = "!";
    setRiskLevel("critical");
    domainDetailsEl.innerHTML = "";
    findingsEl.innerHTML = `<li>${escapeHtml(error.message)}</li>`;
    explanationEl.textContent = "Verifie le format de l'URL puis relance l'analyse.";
    jsonReportEl.textContent = "";
  } finally {
    button.disabled = false;
    button.textContent = "Analyser";
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await analyze(new FormData(form).get("url"));
});

document.querySelectorAll("[data-demo-url]").forEach((button) => {
  button.addEventListener("click", () => analyze(button.dataset.demoUrl, true));
});

historyListEl.addEventListener("click", (event) => {
  const item = event.target.closest("[data-history-url]");
  if (item) {
    analyze(item.dataset.historyUrl);
  }
});

clearHistoryButton.addEventListener("click", () => {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

copyJsonButton.addEventListener("click", async () => {
  if (!jsonReportEl.textContent) {
    return;
  }

  if (navigator.clipboard) {
    await navigator.clipboard.writeText(jsonReportEl.textContent);
  } else {
    const textarea = document.createElement("textarea");
    textarea.value = jsonReportEl.textContent;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }

  copyJsonButton.textContent = "Copie";
  setTimeout(() => {
    copyJsonButton.textContent = "Copier";
  }, 1200);
});

renderHistory();

const demoName = new URLSearchParams(window.location.search).get("demo");
if (demoName && DEMO_URLS[demoName]) {
  analyze(DEMO_URLS[demoName], true);
}
