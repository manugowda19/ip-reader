import { backendFetch } from "@/lib/backend";
import { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
  const body = await req.text();
  const res = await backendFetch("/admin/bulk/submit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  const data = await res.text();
  return new Response(data, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" },
  });
}
