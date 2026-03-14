import { backendFetch } from "@/lib/backend";
import { NextRequest } from "next/server";

// Step 1: Extract IPs
export async function POST(req: NextRequest) {
  const body = await req.text();
  const res = await backendFetch("/admin/bulk/extract", {
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
