import { authenticateAdminUser, sha256Hex } from "../_shared/auth.ts";
import { corsHeaders, errorResponse, jsonResponse } from "../_shared/cors.ts";
import { detectIncidents } from "../_shared/detection.ts";
import type { ParsedEvent } from "../_shared/parser.ts";
import { checkRateLimit } from "../_shared/validation.ts";

export type DemoScenario =
  | "normal"
  | "brute_force"
  | "password_spraying"
  | "suspicious_success"
  | "repeat_offender"
  | "collector_offline";

const ALLOWED_SCENARIOS = new Set<DemoScenario>([
  "normal",
  "brute_force",
  "password_spraying",
  "suspicious_success",
  "repeat_offender",
  "collector_offline",
]);

const DEMO_HOST_ID = "demo-ubuntu-sim-01";

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function buildScenarioEvents(
  scenario: DemoScenario,
  deviceId: string,
  runNonce: string,
): Promise<ParsedEvent[]> {
  const now = Date.now();
  const events: ParsedEvent[] = [];

  const pushEvent = async (opts: {
    offsetMs: number;
    username: string;
    sourceIp: string;
    eventType: string;
    authResult: "success" | "failure";
    authMethod: string;
    rawMsg: string;
    idx: number;
  }) => {
    const ts = new Date(now + opts.offsetMs).toISOString().replace(/\.\d{3}Z$/, "Z");
    const rawEvent = `[SIMULATED] ${opts.rawMsg}`;
    const fp = await sha256Hex(
      `sim|${deviceId}|${runNonce}|${opts.idx}|${ts}|${opts.username}|${opts.sourceIp}|${opts.eventType}`,
    );
    events.push({
      device_id: deviceId,
      event_timestamp: ts,
      username: opts.username,
      source_ip: opts.sourceIp,
      event_type: opts.eventType,
      auth_result: opts.authResult,
      auth_method: opts.authMethod,
      service: "sshd",
      raw_event: rawEvent,
      event_fingerprint: fp,
      is_simulated: true,
    });
  };

  if (scenario === "normal") {
    await pushEvent({
      offsetMs: -40_000,
      username: "deploy",
      sourceIp: "198.51.100.14",
      eventType: "ssh_accepted_login",
      authResult: "success",
      authMethod: "publickey",
      rawMsg: "Accepted publickey for deploy from 198.51.100.14 port 51200 ssh2",
      idx: 1,
    });
    await pushEvent({
      offsetMs: -25_000,
      username: "ops",
      sourceIp: "198.51.100.15",
      eventType: "ssh_failed_password",
      authResult: "failure",
      authMethod: "password",
      rawMsg: "Failed password for ops from 198.51.100.15 port 51204 ssh2",
      idx: 2,
    });
    await pushEvent({
      offsetMs: -15_000,
      username: "ops",
      sourceIp: "198.51.100.15",
      eventType: "ssh_accepted_login",
      authResult: "success",
      authMethod: "password",
      rawMsg: "Accepted password for ops from 198.51.100.15 port 51205 ssh2",
      idx: 3,
    });
    await pushEvent({
      offsetMs: -5_000,
      username: "auditor",
      sourceIp: "198.51.100.18",
      eventType: "ssh_accepted_login",
      authResult: "success",
      authMethod: "publickey",
      rawMsg: "Accepted publickey for auditor from 198.51.100.18 port 51210 ssh2",
      idx: 4,
    });
  } else if (scenario === "brute_force") {
    for (let i = 0; i < 7; i++) {
      await pushEvent({
        offsetMs: -(35_000 - i * 4_000),
        username: "admin",
        sourceIp: "203.0.113.55",
        eventType: "ssh_failed_password",
        authResult: "failure",
        authMethod: "password",
        rawMsg: `Failed password for admin from 203.0.113.55 port ${41000 + i} ssh2`,
        idx: i + 1,
      });
    }
  } else if (scenario === "password_spraying") {
    const users = ["alice", "bob", "charlie", "oracle", "postgres"];
    for (let i = 0; i < users.length; i++) {
      await pushEvent({
        offsetMs: -(40_000 - i * 6_000),
        username: users[i],
        sourceIp: "192.0.2.88",
        eventType: "ssh_invalid_user",
        authResult: "failure",
        authMethod: "password",
        rawMsg: `Failed password for invalid user ${users[i]} from 192.0.2.88 port ${53100 + i} ssh2`,
        idx: i + 1,
      });
    }
  } else if (scenario === "suspicious_success") {
    for (let i = 0; i < 4; i++) {
      await pushEvent({
        offsetMs: -(45_000 - i * 6_000),
        username: "backup_admin",
        sourceIp: "203.0.113.99",
        eventType: "ssh_failed_password",
        authResult: "failure",
        authMethod: "password",
        rawMsg: `Failed password for backup_admin from 203.0.113.99 port ${44100 + i} ssh2`,
        idx: i + 1,
      });
    }
    await pushEvent({
      offsetMs: -5_000,
      username: "backup_admin",
      sourceIp: "203.0.113.99",
      eventType: "ssh_accepted_login",
      authResult: "success",
      authMethod: "password",
      rawMsg: "Accepted password for backup_admin from 203.0.113.99 port 44199 ssh2",
      idx: 5,
    });
  } else if (scenario === "repeat_offender") {
    // Episode 1 (12 minutes ago) -> triggers RULE_001 and marks offender IP
    for (let i = 0; i < 5; i++) {
      await pushEvent({
        offsetMs: -(720_000 - i * 5_000),
        username: "root",
        sourceIp: "198.51.100.200",
        eventType: "ssh_failed_password",
        authResult: "failure",
        authMethod: "password",
        rawMsg: `Failed password for root from 198.51.100.200 port ${48000 + i} ssh2`,
        idx: i + 1,
      });
    }
    // Episode 2 (now, well after 300s cooldown) -> triggers RULE_005 Repeat Offender
    for (let i = 0; i < 4; i++) {
      await pushEvent({
        offsetMs: -(20_000 - i * 4_000),
        username: "root",
        sourceIp: "198.51.100.200",
        eventType: "ssh_failed_password",
        authResult: "failure",
        authMethod: "password",
        rawMsg: `Failed password for root from 198.51.100.200 port ${49000 + i} ssh2`,
        idx: 10 + i,
      });
    }
  }

  return events;
}

export async function handleRunSimulationRequest(
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

  const rate = checkRateLimit(`sim:${auth.userId}`, 30, 60_000);
  if (!rate.allowed) {
    return errorResponse("Simulation rate limit exceeded", 429, {
      "Retry-After": String(rate.retryAfterSeconds),
    });
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return errorResponse("Malformed JSON payload", 400);
  }

  const scenario = typeof body.scenario === "string" ? body.scenario.trim() : "";
  if (!ALLOWED_SCENARIOS.has(scenario as DemoScenario)) {
    return errorResponse("Unsupported demo scenario", 400);
  }

  const rawPace = Number(body.pace_ms ?? 0);
  const paceMs = Number.isFinite(rawPace) ? Math.max(0, Math.min(700, rawPace)) : 0;

  // Ensure simulated demo device exists
  let deviceId: string;
  let prevCount = 0;
  const { data: existingDev } = await adminClient
    .from("monitored_devices")
    .select("id, events_received_count")
    .eq("host_identifier", DEMO_HOST_ID)
    .maybeSingle();

  if (existingDev?.id) {
    deviceId = String(existingDev.id);
    prevCount = Number(existingDev.events_received_count ?? 0);
  } else {
    const { data: createdDev, error: devErr } = await adminClient
      .from("monitored_devices")
      .insert({
        device_name: "Demo Simulated Host",
        host_identifier: DEMO_HOST_ID,
        os_info: "Ubuntu 24.04 LTS (Simulated)",
        collector_version: "1.0.0-sim",
        is_simulated: true,
        status: "online",
        last_heartbeat: new Date().toISOString(),
      })
      .select("id")
      .single();

    if (devErr || !createdDev?.id) {
      return errorResponse("Failed to initialize simulated demo device", 500);
    }
    deviceId = String(createdDev.id);
    const placeholderHash = await sha256Hex(`demo-only-${deviceId}`);
    await adminClient
      .from("device_credentials")
      .upsert({ device_id: deviceId, token_hash: placeholderHash });
  }

  if (scenario === "collector_offline") {
    const staleIso = new Date(Date.now() - 180_000).toISOString();
    const { error: offErr } = await adminClient
      .from("monitored_devices")
      .update({
        status: "offline",
        last_heartbeat: staleIso,
      })
      .eq("id", deviceId);

    if (offErr) {
      return errorResponse("Failed to simulate offline collector", 500);
    }

    return jsonResponse({
      status: "ok",
      scenario,
      is_simulated: true,
      device_id: deviceId,
      events_generated: 0,
      incidents_generated: 0,
      message: "Simulated collector heartbeat set to 3 minutes ago (>90s offline threshold).",
    });
  }

  const runNonce = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  const events = await buildScenarioEvents(scenario as DemoScenario, deviceId, runNonce);
  const fpToId = new Map<string, string>();
  const accumulated: ParsedEvent[] = [];
  let latestIncidents = detectIncidents(events);

  if (paceMs > 0) {
    // Stream events incrementally so Realtime updates appear live step-by-step
    for (const ev of events) {
      const { data: insRow, error: insErr } = await adminClient
        .from("authentication_events")
        .upsert([ev], { onConflict: "event_fingerprint", ignoreDuplicates: true })
        .select("id, event_fingerprint");
      if (insErr) {
        return errorResponse("Failed to persist simulated event", 500);
      }
      for (const r of insRow ?? []) {
        fpToId.set(String(r.event_fingerprint), String(r.id));
      }
      accumulated.push(ev);
      latestIncidents = detectIncidents(accumulated);
      for (const inc of latestIncidents) {
        const eventIds = inc.supporting_fingerprints
          .map((fp) => fpToId.get(fp))
          .filter((id): id is string => Boolean(id));
        await adminClient.rpc("upsert_security_incident", {
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
          p_is_simulated: true,
          p_event_ids: eventIds,
        });
      }
      await sleep(paceMs);
    }
  } else {
    const { data: insertedRows, error: insertErr } = await adminClient
      .from("authentication_events")
      .upsert(events, { onConflict: "event_fingerprint", ignoreDuplicates: true })
      .select("id, event_fingerprint");

    if (insertErr) {
      return errorResponse("Failed to store simulated events", 500);
    }
    for (const r of insertedRows ?? []) {
      fpToId.set(String(r.event_fingerprint), String(r.id));
    }
    for (const inc of latestIncidents) {
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
        p_is_simulated: true,
        p_event_ids: eventIds,
      });
      if (rpcErr) {
        return errorResponse("Failed to store simulated incident", 500);
      }
    }
  }

  const nowIso = new Date().toISOString();
  await adminClient
    .from("monitored_devices")
    .update({
      status: "online",
      last_heartbeat: nowIso,
      last_event_at: events[events.length - 1]?.event_timestamp ?? nowIso,
      events_received_count: prevCount + events.length,
    })
    .eq("id", deviceId);

  return jsonResponse({
    status: "ok",
    scenario,
    is_simulated: true,
    device_id: deviceId,
    events_generated: events.length,
    incidents_generated: latestIncidents.length,
    rule_ids: latestIncidents.map((i) => i.rule_id),
  });
}
