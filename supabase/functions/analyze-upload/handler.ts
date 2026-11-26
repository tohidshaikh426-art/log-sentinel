import { authenticateAdminUser, sha256Hex } from "../_shared/auth.ts";
import { corsHeaders, errorResponse, jsonResponse } from "../_shared/cors.ts";
import { detectIncidents } from "../_shared/detection.ts";
import { parseCsvContent, parseSyslogLines } from "../_shared/parser.ts";
import {
  checkRateLimit,
  MAX_UPLOAD_BYTES,
  sanitizeText,
} from "../_shared/validation.ts";

const ALLOWED_FORMATS = new Set(["auth_log", "journal", "csv"]);
const ANALYZER_HOST_ID = "historical-log-analyzer";

export async function handleAnalyzeUploadRequest(
  req: Request,
  // deno-lint-ignore no-explicit-any
  adminClient: any,
  // deno-lint-ignore no-explicit-any
  anonClient: any,
): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  const auth = await authenticateAdminUser(req, anonClient);
  if (!auth.ok || !auth.userId) {
    return errorResponse(auth.error ?? "Unauthorized", auth.status);
  }

  const rate = checkRateLimit(`upload:${auth.userId}`, 20, 60_000);
  if (!rate.allowed) {
    return errorResponse("Upload rate limit exceeded", 429, {
      "Retry-After": String(rate.retryAfterSeconds),
    });
  }

  const rawBody = await req.text();
  if (new TextEncoder().encode(rawBody).length > MAX_UPLOAD_BYTES) {
    return errorResponse("Uploaded payload exceeds 2 MB limit", 413);
  }

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return errorResponse("Malformed JSON payload", 400);
  }

  const filename = sanitizeText(body.filename, 255);
  const fileFormat =
    typeof body.file_format === "string" ? body.file_format.trim() : "";
  const content = typeof body.content === "string" ? body.content : "";

  if (!filename) {
    return errorResponse("Missing filename", 400);
  }
  if (!ALLOWED_FORMATS.has(fileFormat)) {
    return errorResponse("Unsupported file_format; expected auth_log, journal, or csv", 400);
  }
  if (!content.trim()) {
    return errorResponse("Uploaded file content is empty", 400);
  }
  if (content.includes("\u0000")) {
    return errorResponse("Rejected unsafe binary content", 400);
  }

  // Ensure a stable device record exists for historical log uploads
  let deviceId: string;
  const { data: existingDevice } = await adminClient
    .from("monitored_devices")
    .select("id")
    .eq("host_identifier", ANALYZER_HOST_ID)
    .maybeSingle();

  if (existingDevice?.id) {
    deviceId = String(existingDevice.id);
  } else {
    const { data: createdDevice, error: createDevErr } = await adminClient
      .from("monitored_devices")
      .insert({
        device_name: "Historical Log Analyzer",
        host_identifier: ANALYZER_HOST_ID,
        os_info: "Uploaded Dataset",
        status: "offline",
        is_simulated: false,
      })
      .select("id")
      .single();

    if (createDevErr || !createdDevice?.id) {
      return errorResponse("Failed to initialize analyzer target device", 500);
    }
    deviceId = String(createdDevice.id);
    const placeholderHash = await sha256Hex(`internal-analyzer-${deviceId}`);
    await adminClient
      .from("device_credentials")
      .upsert({ device_id: deviceId, token_hash: placeholderHash });
  }

  const parsed =
    fileFormat === "csv"
      ? await parseCsvContent(content, deviceId, false)
      : await parseSyslogLines(
          content.split(/\r?\n/),
          deviceId,
          fileFormat as "auth_log" | "journal",
          false,
        );

  const incidents = detectIncidents(parsed.events);

  const fpToId = new Map<string, string>();
  let acceptedCount = 0;

  // Insert in chunks of 100 for safe PostgREST batch sizes
  for (let i = 0; i < parsed.events.length; i += 100) {
    const chunk = parsed.events.slice(i, i + 100);
    const { data: insertedRows, error: insertErr } = await adminClient
      .from("authentication_events")
      .upsert(chunk, { onConflict: "event_fingerprint", ignoreDuplicates: true })
      .select("id, event_fingerprint");

    if (insertErr) {
      return errorResponse("Failed to save parsed authentication events", 500);
    }
    for (const row of insertedRows ?? []) {
      fpToId.set(String(row.event_fingerprint), String(row.id));
      acceptedCount += 1;
    }
  }

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

  let incidentsCreated = 0;
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
      p_is_simulated: false,
      p_event_ids: eventIds,
    });

    if (rpcErr) {
      return errorResponse("Failed to store detected incidents", 500);
    }
    incidentsCreated += 1;
  }

  const duplicateCount = Math.max(0, parsed.events.length - acceptedCount);
  const summaryPayload = {
    ignored_count: parsed.ignored_count,
    accepted_count: acceptedCount,
    duplicate_count: duplicateCount,
    malformed_samples: parsed.malformed_records.slice(0, 20),
    rule_ids: Array.from(new Set(incidents.map((i) => i.rule_id))),
  };

  const { data: uploadRow, error: uploadErr } = await adminClient
    .from("analysis_uploads")
    .insert({
      uploaded_by: auth.userId,
      filename,
      file_format: fileFormat,
      total_lines: parsed.total_lines,
      parsed_count: parsed.events.length,
      malformed_count: parsed.malformed_records.length,
      incidents_created: incidentsCreated,
      summary: summaryPayload,
    })
    .select("id")
    .single();

  if (uploadErr) {
    return errorResponse("Failed to save upload summary", 500);
  }

  return jsonResponse({
    status: "ok",
    upload_id: uploadRow?.id ?? null,
    filename,
    file_format: fileFormat,
    total_lines: parsed.total_lines,
    parsed_count: parsed.events.length,
    accepted_count: acceptedCount,
    duplicate_count: duplicateCount,
    ignored_count: parsed.ignored_count,
    malformed_count: parsed.malformed_records.length,
    malformed_samples: parsed.malformed_records.slice(0, 20),
    incidents_created: incidentsCreated,
    incidents,
  });
}
