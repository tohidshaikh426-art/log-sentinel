import { authenticateCollector } from "../_shared/auth.ts";
import { corsHeaders, errorResponse, jsonResponse } from "../_shared/cors.ts";
import { checkRateLimit, sanitizeOptional } from "../_shared/validation.ts";

export async function handleHeartbeatRequest(
  req: Request,
  // deno-lint-ignore no-explicit-any
  adminClient: any,
): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  const auth = await authenticateCollector(req, adminClient);
  if (!auth.ok || !auth.device) {
    return errorResponse(auth.error ?? "Unauthorized", auth.status);
  }

  const rate = checkRateLimit(`hb:${auth.device.id}`, 60, 60_000);
  if (!rate.allowed) {
    return errorResponse("Rate limit exceeded", 429, {
      "Retry-After": String(rate.retryAfterSeconds),
    });
  }

  let body: Record<string, unknown> = {};
  const rawText = await req.text();
  if (rawText.trim()) {
    try {
      body = JSON.parse(rawText);
    } catch {
      return errorResponse("Malformed JSON payload", 400);
    }
  }

  const nowIso = new Date().toISOString();
  const updates: Record<string, unknown> = {
    status: "online",
    last_heartbeat: nowIso,
  };

  const version = sanitizeOptional(body.collector_version, 40);
  const osInfo = sanitizeOptional(body.os_info, 160);
  if (version) updates.collector_version = version;
  if (osInfo) updates.os_info = osInfo;

  const { error: updateErr } = await adminClient
    .from("monitored_devices")
    .update(updates)
    .eq("id", auth.device.id);

  if (updateErr) {
    return errorResponse("Failed to update device heartbeat", 500);
  }

  return jsonResponse({
    status: "ok",
    device_id: auth.device.id,
    server_time: nowIso,
  });
}
