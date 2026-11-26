import { authenticateCollector } from "../_shared/auth.ts";
import { corsHeaders, errorResponse, jsonResponse } from "../_shared/cors.ts";
import {
  checkRateLimit,
  MAX_PAYLOAD_BYTES,
  sanitizeOptional,
  validateEventsBatch,
  validateIncidentsBatch,
} from "../_shared/validation.ts";

export async function handleIngestRequest(
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

  const rate = checkRateLimit(`ingest:${auth.device.id}`, 120, 60_000);
  if (!rate.allowed) {
    return errorResponse("Rate limit exceeded", 429, {
      "Retry-After": String(rate.retryAfterSeconds),
    });
  }

  const rawBody = await req.text();
  if (new TextEncoder().encode(rawBody).length > MAX_PAYLOAD_BYTES) {
    return errorResponse("Payload exceeds maximum allowed size", 413);
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return errorResponse("Malformed JSON payload", 400);
  }

  const eventsCheck = validateEventsBatch(
    body?.events,
    auth.device.id,
    auth.device.is_simulated,
  );
  if (!eventsCheck.ok) {
    return errorResponse(eventsCheck.error, 400);
  }

  const incidentsCheck = validateIncidentsBatch(
    body?.incidents,
    auth.device.id,
    auth.device.is_simulated,
  );
  if (!incidentsCheck.ok) {
    return errorResponse(incidentsCheck.error, 400);
  }

  const events = eventsCheck.events;
  const incidents = incidentsCheck.incidents;

  // Deduplicated insert via UNIQUE(event_fingerprint)
  const { data: insertedEvents, error: insertErr } = await adminClient
    .from("authentication_events")
    .upsert(events, { onConflict: "event_fingerprint", ignoreDuplicates: true })
    .select("id, event_fingerprint");

  if (insertErr) {
    return errorResponse("Failed to persist authentication events", 500);
  }

  const fpToId = new Map<string, string>();
  for (const row of insertedEvents ?? []) {
    fpToId.set(String(row.event_fingerprint), String(row.id));
  }

  const acceptedCount = fpToId.size;
  const duplicateCount = Math.max(0, events.length - acceptedCount);

  // Resolve IDs for any supporting fingerprints that were already stored earlier
  if (incidents.length > 0) {
    const missingFps = Array.from(
      new Set(
        incidents.flatMap((inc) =>
          inc.supporting_fingerprints.filter((fp) => !fpToId.has(fp)),
        ),
      ),
    ).slice(0, 200);

    if (missingFps.length > 0) {
      const { data: existingRows } = await adminClient
        .from("authentication_events")
        .select("id, event_fingerprint")
        .in("event_fingerprint", missingFps);
      for (const row of existingRows ?? []) {
        fpToId.set(String(row.event_fingerprint), String(row.id));
      }
    }
  }

  let incidentsUpserted = 0;
  for (const inc of incidents) {
    const eventIds = inc.supporting_fingerprints
      .map((fp) => fpToId.get(fp))
      .filter((id): id is string => Boolean(id));

    const { error: rpcErr } = await adminClient.rpc("upsert_security_incident", {
      p_device_id: inc.device_id,
      p_rule_id: inc.rule_id,
      p_incident_title: inc.incident_title,
      p_description: inc.description,
      p_source_ip: inc.source_ip,
      p_username: inc.username,
      p_severity: inc.severity,
      p_risk_score: inc.risk_score,
      p_dedup_key: inc.dedup_key,
      p_first_observed: inc.first_observed,
      p_last_observed: inc.last_observed,
      p_event_count: inc.event_count,
      p_evidence: inc.evidence,
      p_is_simulated: inc.is_simulated,
      p_event_ids: eventIds,
    });

    if (rpcErr) {
      return errorResponse("Failed to correlate security incident", 500);
    }
    incidentsUpserted += 1;
  }

  const latestEventAt = events.reduce(
    (maxTs, ev) => (ev.event_timestamp > maxTs ? ev.event_timestamp : maxTs),
    events[0].event_timestamp,
  );
  const nowIso = new Date().toISOString();
  const collectorVersion = sanitizeOptional(body?.collector_version, 40);

  const deviceUpdate: Record<string, unknown> = {
    status: "online",
    last_heartbeat: nowIso,
    last_event_at: latestEventAt,
    events_received_count: Number(auth.device.events_received_count ?? 0) + acceptedCount,
  };
  if (collectorVersion) {
    deviceUpdate.collector_version = collectorVersion;
  }

  await adminClient
    .from("monitored_devices")
    .update(deviceUpdate)
    .eq("id", auth.device.id);

  return jsonResponse({
    status: "ok",
    accepted_count: acceptedCount,
    duplicate_count: duplicateCount,
    incidents_upserted: incidentsUpserted,
  });
}
