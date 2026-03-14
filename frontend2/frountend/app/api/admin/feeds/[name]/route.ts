import { backendFetch } from "@/lib/backend";

export async function DELETE(
  _req: Request,
  context: { params: { name: string } | Promise<{ name: string }> }
) {
  const params = typeof (context.params as Promise<{ name: string }>).then === "function"
    ? await (context.params as Promise<{ name: string }>)
    : (context.params as { name: string });
  const name = encodeURIComponent(params.name);
  const res = await backendFetch(`/admin/feeds/${name}`, { method: "DELETE" });
  const text = await res.text();
  return new Response(text, {
    status: res.status,
    headers: { "content-type": res.headers.get("content-type") ?? "application/json" },
  });
}
