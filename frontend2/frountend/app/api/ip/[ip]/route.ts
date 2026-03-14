import { backendFetch } from "@/lib/backend";

export async function GET(
  _req: Request,
  context: { params: { ip: string } | Promise<{ ip: string }> }
) {
  const params =
    typeof (context.params as any)?.then === "function"
      ? await (context.params as Promise<{ ip: string }>)
      : (context.params as { ip: string });

  const { ip } = params;
  const res = await backendFetch(`/ip/${encodeURIComponent(ip)}`);
  const body = await res.text();

  return new Response(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") ?? "application/json",
    },
  });
}

