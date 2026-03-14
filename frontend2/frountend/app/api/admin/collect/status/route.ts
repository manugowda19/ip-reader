import { backendFetch } from "@/lib/backend";

export async function GET() {
  const res = await backendFetch("/admin/collect/status");
  const body = await res.text();
  return new Response(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" },
  });
}
