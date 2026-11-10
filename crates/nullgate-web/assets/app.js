"use strict";
const feedback = document.getElementById("feedback");
const storageKey = "nullgate:last-outcome";
function describe(data) {
  const report = data.import || data.diagnostics;
  let message = data.message || (data.revision !== undefined ? `Saved revision ${data.revision}.` : "Done.");
  if (report) {
    message += `\n${report.accepted} accepted; ${report.duplicates} duplicates; ${report.malformed_total} malformed.`;
    for (const item of report.malformed) message += `\nLine ${item.line}: ${item.message}`;
    if (report.diagnostics_truncated) message += "\nShowing the first 1,000 diagnostics. Fix these entries before reimporting.";
  }
  return message;
}
function show(message, failed = false) {
  feedback.textContent = message;
  feedback.className = failed ? "feedback error" : "feedback success";
}
try {
  const previous = sessionStorage.getItem(storageKey);
  if (previous) { show(previous); sessionStorage.removeItem(storageKey); }
} catch (_) { /* Outcomes remain visible when session storage is unavailable. */ }
if (document.body.dataset.page === "login") {
  fetch("/api/v1/auth/me", {credentials: "same-origin"}).then(response => { if (response.ok) location.replace("/"); }).catch(() => {});
}
let submitting = false;
for (const form of document.querySelectorAll("form[action]")) {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submitting || (form.dataset.confirm && !confirm(form.dataset.confirm))) return;
    submitting = true;
    show(form.dataset.kind === "login" ? "Signing in…" : form.dataset.kind === "logout" ? "Signing out…" : "Saving changes…");
    const buttons = document.querySelectorAll("button[type=submit]");
    buttons.forEach(button => { button.disabled = true; });
    try {
      const tokenResponse = await fetch("/api/v1/auth/csrf", {credentials: "same-origin"});
      if (!tokenResponse.ok) throw new Error("Authentication is unavailable. Sign in again or retry after checking service health.");
      const token = await tokenResponse.json();
      const fields = new FormData(form);
      const values = {};
      for (const [key, value] of fields) if (typeof value === "string") values[key] = key === "expected_revision" ? Number(value) : value;
      let url = form.getAttribute("action");
      let body;
      const headers = {"X-CSRF-Token": token.csrf};
      if (form.dataset.file) {
        const file = fields.get("rules_file");
        if (!(file instanceof File) || file.size > 4 * 1024 * 1024) throw new Error("Choose a UTF-8 text file no larger than 4 MiB.");
        body = await file.arrayBuffer();
        new TextDecoder("utf-8", {fatal: true}).decode(body);
        url += "?" + new URLSearchParams({expected_revision: String(values.expected_revision), filename: file.name});
        headers["Content-Type"] = "text/plain; charset=utf-8";
      } else {
        if (typeof values.text === "string" && new TextEncoder().encode(values.text).length > 4 * 1024 * 1024) throw new Error("Rules exceed the 4 MiB limit.");
        body = JSON.stringify(values);
        headers["Content-Type"] = "application/json";
      }
      const response = await fetch(url, {method: form.dataset.method || "POST", headers, body, credentials: "same-origin"});
      const text = await response.text();
      let result;
      try { result = text ? JSON.parse(text) : {}; } catch (_) { result = {message: text}; }
      if (!response.ok) {
        let message = describe(result);
        if (response.status === 409) message += "\nReload and review the latest state before retrying. Your inputs have been kept.";
        if (response.status === 401) message = form.dataset.kind === "login" ? "Username or password not accepted." : "Your session expired. Sign in again before retrying.";
        throw new Error(message);
      }
      if (form.dataset.kind === "login") { form.reset(); location.assign("/"); return; }
      if (form.dataset.kind === "logout") { location.assign("/login"); return; }
      const message = describe(result);
      try { sessionStorage.setItem(storageKey, message); } catch (_) { show(message); return; }
      location.reload();
    } catch (error) { show(error instanceof Error ? error.message : "Request failed. Reload current state before retrying.", true); }
    finally { submitting = false; buttons.forEach(button => { button.disabled = false; }); }
  });
}
