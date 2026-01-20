import { NextRequest } from "next/server";

async function getPathParts(ctx: any): Promise<string[]> {

 const p = await ctx.params;
 return (p?.path ?? []) as string[];
}

async function proxy(req: NextRequest, ctx: any) {
 const parts = await getPathParts(ctx);
 const url = new URL(req.url);
 const target = `http://api:8000/${parts.join("/")}${url.search}`;

 const headers = new Headers(req.headers);

 headers.delete("host");
 headers.delete("connection");
 headers.set("accept", headers.get("accept") ?? "application/json");

 let body: any = undefined;
 if (req.method !== "GET" && req.method !== "HEAD") {
   body = await req.arrayBuffer();
 }

 const upstream = await fetch(target, {
   method: req.method,
   headers,
   body,
 });

 const outHeaders = new Headers(upstream.headers);

 return new Response(upstream.body, {
   status: upstream.status,
   headers: outHeaders,
 });
}

export async function GET(req: NextRequest, ctx: any) {
 return proxy(req, ctx);
}
export async function POST(req: NextRequest, ctx: any) {
 return proxy(req, ctx);
}
export async function PUT(req: NextRequest, ctx: any) {
 return proxy(req, ctx);
}
export async function DELETE(req: NextRequest, ctx: any) {
 return proxy(req, ctx);
}
export async function PATCH(req: NextRequest, ctx: any) {
 return proxy(req, ctx);
}
