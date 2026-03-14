import { backendFetch } from "@/lib/backend";

export async function DELETE(
  _req: Request,
  context: { params: { name: string } | Promise<{ name: string }> }
) {
  const params =
    typeof (context.params as any)?.then === "function"
      ? await (context.params as Promise<{ name: string }>)
      : (context.params as { name: string });

  const res = await backendFetch(`/admin/manual_feeds/${encodeURIComponent(params.name)}`, {
    method: "DELETE",
  });
  const body = await res.text();
  return new Response(body, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" },
  });
}
