/* HTTP layer: JSON calls, uploads with progress, authenticated downloads.

   When the server gates /api/* behind SENTRYD_API_TOKEN, the first 401 asks
   the user for the token (once, however many requests failed together),
   then retries. The token lives in sessionStorage, or localStorage when the
   user ticks "remember". */

const TOKEN_KEY = "sentryd-token";

function storage(kind) {
  try { return kind === "local" ? localStorage : sessionStorage; } catch { return null; }
}

let token = storage("session")?.getItem(TOKEN_KEY) || storage("local")?.getItem(TOKEN_KEY) || "";
let authHandler = null;
let pendingAuth = null;

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

/** Register the UI that collects a token:
    async (reason, { rejected }) => token | null. `rejected` means the
    token currently in use was refused (wrong or revoked). */
export function onAuthRequired(fn) { authHandler = fn; }

export function hasToken() { return Boolean(token); }

export function setToken(value, remember = false) {
  token = value || "";
  for (const kind of ["session", "local"]) storage(kind)?.removeItem(TOKEN_KEY);
  if (token) storage(remember ? "local" : "session")?.setItem(TOKEN_KEY, token);
}

async function reauthenticate(reason) {
  if (!authHandler) throw new ApiError(reason, 401);
  pendingAuth ??= authHandler(reason, { rejected: Boolean(token) }).finally(() => { pendingAuth = null; });
  const value = await pendingAuth;
  if (!value) throw new ApiError("API token required", 401);
}

function authHeaders(extra = {}) {
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

async function errorDetail(res) {
  let detail = `${res.status} ${res.statusText}`;
  try {
    const body = await res.json();
    if (typeof body.detail === "string") detail = body.detail;
    else if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join("; ");
  } catch { /* keep the status line */ }
  return detail;
}

/**
 * fetch + JSON with auth. `json` sends a JSON body; `body` sends as-is
 * (FormData); `signal` aborts superseded requests.
 */
export async function api(path, { method = "GET", json, body, signal, raw = false } = {}) {
  const headers = authHeaders(json !== undefined ? { "Content-Type": "application/json" } : {});
  const res = await fetch(path, {
    method,
    headers,
    body: json !== undefined ? JSON.stringify(json) : body,
    signal,
  });
  if (res.status === 401) {
    await reauthenticate(await errorDetail(res));
    return api(path, { method, json, body, signal, raw });
  }
  if (!res.ok) throw new ApiError(await errorDetail(res), res.status);
  return raw ? res : res.json();
}

/** Multipart upload via XHR (fetch has no upload progress). */
export function upload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", file);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", path);
    for (const [k, v] of Object.entries(authHeaders())) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (ev) => { if (ev.lengthComputable) onProgress?.(ev.loaded / ev.total); };
    xhr.onerror = () => reject(new ApiError("network error during upload", 0));
    xhr.onload = async () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch { /* non-JSON error page */ }
      if (xhr.status === 401) {
        try {
          await reauthenticate(data?.detail || "API token required");
          resolve(await upload(path, file, onProgress));
        } catch (err) { reject(err); }
        return;
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        const detail = typeof data?.detail === "string" ? data.detail : `${xhr.status} ${xhr.statusText}`;
        reject(new ApiError(detail, xhr.status));
        return;
      }
      resolve(data);
    };
    xhr.send(form);
  });
}

/** Save a server file. Plain navigation works without a token; with one,
    the download goes through fetch so the Authorization header rides along. */
export async function download(path, filename) {
  const link = document.createElement("a");
  link.download = filename || "";
  if (!token) {
    link.href = path;
    link.click();
    return;
  }
  const res = await api(path, { raw: true });
  const url = URL.createObjectURL(await res.blob());
  link.href = url;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
