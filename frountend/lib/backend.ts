const BACKEND_URL = "/api";

export async function backendFetch(path: string, init?: RequestInit) {
  const url = `${BACKEND_URL}/${path.replace(/^\//, "")}`;

  const res = await fetch(url, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      accept: "application/json",
    },
  });

  return res;
}
