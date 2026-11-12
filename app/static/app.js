// Backup console: trigger transfers and poll job / zone state.
//
// Normal scenarios use the asynchronous endpoint (network wait happens in a
// server-side thread). The stale-serial demo uses the synchronous endpoint so
// the browser visibly waits for the delayed transfer and then shows the RFC
// 1982 rejection in one request/response.

const SYNC_TARGETS = new Set(["stale"]);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

async function refreshZones() {
  const resp = await fetch("/api/zones");
  const zones = await resp.json();
  const tbody = document.querySelector("#zones-table tbody");
  if (!zones.length) {
    tbody.innerHTML = '<tr class="empty"><td colspan="6">尚无已保存副本</td></tr>';
    return;
  }
  tbody.innerHTML = zones.map((z) => `
    <tr>
      <td class="mono">${esc(z.name)}</td>
      <td class="mono">${esc(z.serial)}</td>
      <td>${esc(z.record_count)}</td>
      <td>${esc(z.message_count)}</td>
      <td class="mono">${esc(z.updated_at)}</td>
      <td><a class="btn small" href="/api/zones/${encodeURIComponent(z.name)}/download">下载 zone 文件</a></td>
    </tr>`).join("");
}

function reasonClass(job) {
  if (job.state === "success") return "reason-ok";
  if (job.state === "running") return "reason-warn";
  return "reason-err";
}

async function refreshJobs() {
  const resp = await fetch("/api/jobs");
  const jobs = await resp.json();
  const tbody = document.querySelector("#jobs-table tbody");
  if (!jobs.length) {
    tbody.innerHTML = '<tr class="empty"><td colspan="8">尚未执行备份任务</td></tr>';
    return;
  }
  tbody.innerHTML = jobs.map((j) => {
    const reason = j.state === "running"
      ? "传输进行中（最多 5 秒）…"
      : esc(j.reason || "");
    return `
    <tr>
      <td>${esc(j.label)}<br><span class="mono" style="color:var(--muted)">${esc(j.target_id)}</span></td>
      <td><span class="badge ${esc(j.state)}">${esc(j.state)}</span></td>
      <td class="mono">${esc(j.serial ?? "—")}</td>
      <td>${esc(j.record_count ?? "—")}</td>
      <td>${esc(j.message_count ?? "—")}</td>
      <td class="mono">${esc(j.started_at)}</td>
      <td class="mono">${esc(j.finished_at ?? "—")}</td>
      <td class="${reasonClass(j)}">${reason}</td>
    </tr>`;
  }).join("");
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll("[data-backup]").forEach((btn) => {
    btn.disabled = disabled;
    btn.textContent = disabled ? "备份进行中…" : "立即备份";
  });
}

async function runBackup(targetId, button) {
  setButtonsDisabled(true);
  try {
    if (SYNC_TARGETS.has(targetId)) {
      const resp = await fetch(`/api/backups/${encodeURIComponent(targetId)}/sync`, {
        method: "POST",
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    } else {
      const resp = await fetch(`/api/backups/${encodeURIComponent(targetId)}`, {
        method: "POST",
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      // Give the background thread a moment, then poll until it settles.
      await new Promise((resolve) => setTimeout(resolve, 300));
      for (let i = 0; i < 30; i += 1) {
        await refreshJobs();
        const latest = await (await fetch("/api/jobs")).json();
        const mine = latest.find((j) => j.target_id === targetId);
        if (!mine || mine.state !== "running") break;
        await new Promise((resolve) => setTimeout(resolve, 400));
      }
    }
  } catch (err) {
    alert(`备份请求失败：${err}`);
  } finally {
    setButtonsDisabled(false);
    await Promise.all([refreshJobs(), refreshZones()]);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-backup]").forEach((btn) => {
    btn.addEventListener("click", () => runBackup(btn.dataset.backup, btn));
  });
  refreshJobs();
  refreshZones();
  // Keep the view fresh if another worker process finished a job.
  setInterval(() => {
    refreshJobs();
    refreshZones();
  }, 4000);
});
