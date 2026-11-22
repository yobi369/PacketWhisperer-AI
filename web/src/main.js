import "./style.css";
import { firebaseStatus, explainFindings, getAnalystIdToken } from "./firebase.js";

const $ = (id) => document.getElementById(id);
const state = { report: null, file: null };
const status = firebaseStatus();

$("system-status").textContent = status.configured ? "FIREBASE AI READY" : "CONFIGURATION REQUIRED";
$("inference-badge").textContent = status.configured ? "HYBRID READY" : "NOT CONFIGURED";
$("inference-badge").className = "tag " + (status.configured ? "good" : "neutral");

const apiUrl = $("api-url");
apiUrl.value = localStorage.getItem("pw_api_url") || "";
apiUrl.addEventListener("change", () => localStorage.setItem("pw_api_url", apiUrl.value.trim()));

$("evidence-file").addEventListener("change", (event) => {
  state.file = event.target.files?.[0] || null;
  $("analyze-btn").disabled = !state.file || !apiUrl.value.trim();
  $("ingest-message").textContent = state.file ? `${state.file.name} · ${formatBytes(state.file.size)}` : "Choose a supported file.";
});
apiUrl.addEventListener("input", () => {
  $("analyze-btn").disabled = !state.file || !apiUrl.value.trim();
});

$("analyze-btn").addEventListener("click", analyzeEvidence);
$("ask-btn").addEventListener("click", askAnalyst);

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
function safeText(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}
function setMessage(message, isError = false) {
  $("ingest-message").textContent = message;
  $("ingest-message").className = "notice " + (isError ? "error" : "");
}

async function analyzeEvidence() {
  const base = apiUrl.value.trim().replace(/\/$/, "");
  if (!base || !state.file) return;
  const token = $("api-token").value.trim();
  const isPcap = /\.(pcap|pcapng|cap)$/i.test(state.file.name);
  const endpoint = isPcap ? "/v1/analyze/pcap" : "/v1/analyze/flows";
  const form = new FormData();
  form.append("file", state.file);
  const headers = {};
  if (status.configured) {
    try {
      headers.Authorization = `Bearer ${await getAnalystIdToken()}`;
    } catch (error) {
      setMessage(`Firebase sign-in failed: ${error.message}`, true);
      return;
    }
  } else if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  $("analyze-btn").disabled = true;
  setMessage("Analyzing evidence…");
  try {
    const response = await fetch(base + endpoint, { method: "POST", headers, body: form });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || `Analysis API returned ${response.status}`);
    state.report = body;
    renderReport(body, state.file.size);
    $("analyst-prompt").disabled = !status.configured || !(body.findings?.length);
    $("ask-btn").disabled = !status.configured || !(body.findings?.length);
    setMessage("Analysis complete. Review the evidence and findings before drawing conclusions.");
  } catch (error) {
    setMessage(error.message || "Unable to reach the analysis API.", true);
  } finally {
    $("analyze-btn").disabled = false;
  }
}

function renderReport(report, fileSize) {
  $("empty-state").classList.add("hidden");
  $("report-view").classList.remove("hidden");
  $("evidence-state").textContent = "ANALYSIS COMPLETE";
  $("evidence-state").className = "tag good";
  $("metric-records").textContent = report.flow_count ?? report.capture?.packets_analyzed ?? "—";
  $("metric-findings").textContent = report.findings_count ?? report.findings?.length ?? 0;
  const critical = (report.findings || []).filter((item) => ["high", "critical"].includes(String(item.severity).toLowerCase())).length;
  $("metric-severity").textContent = critical;
  $("metric-size").textContent = formatBytes(fileSize);
  $("evidence-hash").textContent = report.evidence?.sha256 || "Fingerprint not returned";
  $("findings-count").textContent = `${report.findings?.length || 0} records`;
  $("findings-list").innerHTML = (report.findings || []).map((finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    return `<article class="finding"><div class="finding-top"><div><b>${safeText(finding.title || finding.rule_id || finding.rule || "Finding")}</b><small>${safeText(finding.rule_id || finding.rule || "RULE UNSPECIFIED")}</small></div><span class="severity ${safeText(severity)}">${safeText(severity)}</span></div><p>${safeText(finding.description || finding.summary || "No description supplied.")}</p></article>`;
  }).join("") || '<div class="empty-state compact">No findings were returned by the deterministic analysis engine.</div>';
}

async function askAnalyst() {
  const prompt = $("analyst-prompt").value.trim();
  if (!prompt || !state.report) return;
  $("ask-btn").disabled = true;
  $("ai-output").textContent = "Reviewing structured findings…";
  try {
    const result = await explainFindings(prompt, state.report);
    $("ai-output").textContent = result.answer;
    const local = result.source === "ON_DEVICE";
    $("inference-badge").textContent = local ? "ON-DEVICE INFERENCE" : result.source === "IN_CLOUD" ? "CLOUD FALLBACK" : "SOURCE UNKNOWN";
    $("inference-badge").className = "tag " + (local ? "good" : "cloud");
    $("ai-mode").textContent = `PREFER_ON_DEVICE · ${result.source}`;
  } catch (error) {
    $("ai-output").textContent = `Hybrid analysis could not complete: ${error.message}. Check Firebase configuration, App Check, model availability and network access.`;
  } finally {
    $("ask-btn").disabled = false;
  }
}

if (!status.configured) {
  const details = status.missing.length ? `Missing Firebase settings: ${status.missing.join(", ")}.` : "App Check or Firebase initialization is incomplete.";
  $("ai-output").textContent = details + " Configure web/.env.local using web/.env.example. Hybrid AI remains disabled until Firebase is configured.";
}
