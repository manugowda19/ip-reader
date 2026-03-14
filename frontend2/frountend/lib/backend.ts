function getBackendBaseUrl() {
  // Server-side only: used by Next route handlers to talk to Flask.
  // Default matches backend/api.py
  return process.env.BACKEND_URL ?? "http://127.0.0.1:5000";
}

export async function backendFetch(path: string, init?: RequestInit) {
  const base = getBackendBaseUrl();
  const url = new URL(path.replace(/^\//, ""), base.endsWith("/") ? base : `${base}/`);

  const res = await fetch(url, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      accept: "application/json",
    },
    // Avoid Next caching API responses by default in dev/dashboard.
    cache: "no-store",
  });

  return res;
}

