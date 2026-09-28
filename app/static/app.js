// Small vanilla JS dashboard - talks to the same API the analysts use.

const $ = (id) => document.getElementById(id);
let apiKey = sessionStorage.getItem("sf-key") || "";

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-API-Key": apiKey, ...(options.headers || {}) },
  });
  if (res.status === 401) throw new Error("That key was rejected");
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return res.status === 204 ? null : res.json();
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text ?? "";
  return div.innerHTML;
}

function timeLeft(dueIso) {
  const mins = Math.round((new Date(dueIso) - Date.now()) / 60000);
  if (mins < 0) return `<span class="late">${Math.abs(mins)}m late</span>`;
  if (mins < 60) return `${mins}m left`;
  return `${Math.round(mins / 60)}h left`;
}

async function checkHealth() {
  try {
    const h = await (await fetch("/health")).json();
    $("health-dot").className = "dot " + (h.status === "healthy" ? "ok" : "bad");
    $("env-label").textContent = `${h.environment} · v${h.version}`;
  } catch {
    $("health-dot").className = "dot bad";
    $("env-label").textContent = "unreachable";
  }
}

async function loadStats() {
  const s = await api("/stats");
  const open = Object.values(s.open_by_severity).reduce((a, b) => a + b, 0);
  $("c-open").textContent = open;
  $("c-critical").textContent = s.open_by_severity.CRITICAL || 0;
  $("c-overdue").textContent = s.overdue;
  $("c-auto").textContent = s.auto_detected;
}

async function loadIncidents() {
  const params = new URLSearchParams();
  if ($("f-severity").value) params.set("severity", $("f-severity").value);
  if ($("f-status").value) params.set("status", $("f-status").value);

  const incidents = await api(`/incidents?${params}`);
  const rows = incidents.map((i) => `
    <tr class="${i.is_overdue ? "overdue" : ""}">
      <td>${i.id}</td>
      <td>${escapeHtml(i.title)}
          ${i.detected_by === "auto" ? '<span class="tag">AUTO</span>' : ""}
          <span class="sub">${escapeHtml(i.description).slice(0, 90)}</span></td>
      <td><span class="pill ${i.severity}">${i.severity}</span></td>
      <td>${i.status}</td>
      <td>${escapeHtml(i.source)}${i.attacker_ip ? `<span class="sub">${escapeHtml(i.attacker_ip)}</span>` : ""}</td>
      <td>${i.risk_score}</td>
      <td>${i.status === "RESOLVED" ? "-" : timeLeft(i.sla_due_at)}</td>
      <td>${i.status === "RESOLVED" ? "" : `<button class="small" data-resolve="${i.id}">Resolve</button>`}</td>
    </tr>`);
  $("incident-rows").innerHTML = rows.join("") ||
    '<tr><td colspan="8" class="empty">No incidents match these filters.</td></tr>';

  const auto = incidents.filter((i) => i.detected_by === "auto").slice(0, 12);
  $("detections").innerHTML = auto.map((i) => `
    <li><span class="pill ${i.severity}">${i.severity}</span> ${escapeHtml(i.title)}
        <span class="sub">from ${escapeHtml(i.attacker_ip || "?")} · ${new Date(i.created_at).toLocaleTimeString()}</span></li>`
  ).join("") || '<li class="muted">Nothing detected yet.</li>';
}

async function refresh() {
  checkHealth();
  if (!apiKey) return;
  try {
    await Promise.all([loadStats(), loadIncidents()]);
    $("key-msg").textContent = "connected";
  } catch (err) {
    $("key-msg").textContent = err.message;
  }
}

$("save-key").addEventListener("click", () => {
  apiKey = $("api-key").value.trim();
  sessionStorage.setItem("sf-key", apiKey);
  refresh();
});

$("f-severity").addEventListener("change", refresh);
$("f-status").addEventListener("change", refresh);

$("incident-rows").addEventListener("click", async (e) => {
  const id = e.target.dataset.resolve;
  if (!id) return;
  await api(`/incidents/${id}`, { method: "PUT", body: JSON.stringify({ status: "RESOLVED" }) });
  refresh();
});

$("new-incident").addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  try {
    await api("/incidents", { method: "POST", body: JSON.stringify(data) });
    e.target.reset();
    refresh();
  } catch (err) {
    $("key-msg").textContent = err.message;
  }
});

if (apiKey) $("api-key").value = apiKey;
refresh();
setInterval(refresh, 5000);
