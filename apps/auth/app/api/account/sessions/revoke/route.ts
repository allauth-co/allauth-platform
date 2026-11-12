import { withPortalAuthEngine } from "@/lib/domains/hosting";

export async function POST(request: Request) {
	return withPortalAuthEngine(request,async (engine,_env,request)=>{
	const length = request.headers.get("content-length");
	if (length && Number(length) > 1024) return Response.json({ error: "Request too large." }, { status: 413 });
	const reader = request.body?.getReader();
	let total = 0;
	const chunks: Uint8Array[] = [];
	if (reader) {
		try {
			for (;;) {
				const { done, value } = await reader.read();
				if (done) break;
				total += value.byteLength;
				if (total > 1024) { await reader.cancel(); return Response.json({ error: "Request too large." }, { status: 413 }); }
				chunks.push(value);
			}
		} catch { return Response.json({ error: "Invalid request." }, { status: 400 }); }
	}
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
	const text = new TextDecoder().decode(bytes);
	let body: unknown;
	try { body = JSON.parse(text); }
	catch { return Response.json({ error: "Invalid request." }, { status: 400 }); }
	return engine.revokeAccountSession(request.headers, body as { id: string });
	});
}
