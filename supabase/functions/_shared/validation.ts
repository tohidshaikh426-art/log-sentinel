export const MAX_EVENTS_PER_BATCH = 100;
export const MAX_INCIDENTS_PER_BATCH = 25;
export const MAX_PAYLOAD_BYTES = 512 * 1024;
export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;

const HEX64_RE = /^[0-9a-f]{64}$/i;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_AUTH_RESULTS = new Set(["success", "failure", "unknown"]);
const ALLOWED_SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const ANSI_RE = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07/g;
const CTRL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
const WS_RUN_RE = /[\r\n\t]+/g;

// Best-effort per-isolate rate limiter (zero-cost protection against burst abuse)
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(
  key: string,
  maxRequests = 60,
  windowMs = 60_000,
): { allowed: boolean; retryAfterSeconds: number } {
  const now = Date.now();
  const entry = rateBuckets.get(key);
  if (!entry || now >= entry.resetAt) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSeconds: 0 };
  }
  if (entry.count >= maxRequests) {
    const retryAfterSeconds = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    return { allowed: false, retryAfterSeconds };
  }
  entry.count += 1;
  return { allowed: true, retryAfterSeconds: 0 };
}

export function sanitizeText(value: unknown, maxLength = 512): string {
  if (typeof value !== "string") return "";
  const cleaned = value
    .replace(ANSI_RE, "")
    .replace(WS_RUN_RE, " ")
    .replace(CTRL_RE, "")
    .trim();
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned;
}

export function sanitizeOptional(value: unknown, maxLength = 128): string | null {
  if (value === null || value === undefined) return null;
  const cleaned = sanitizeText(String(value), maxLength);
  return cleaned ? cleaned : null;
}

export function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

export function isValidIpv6(ip: string): boolean {
  if (!ip.includes(":") || ip.length > 45) return false;
  // Rely on URL host parsing for strict RFC IPv6 validation without external dependencies
  try {
    const u = new URL(`http://[${ip}]/`);
    return u.hostname.startsWith("[") && u.hostname.endsWith("]");
  } catch {
    return false;
  }
}

export function validateIp(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  const candidate = sanitizeText(String(value), 64).replace(/^\[|\]$/g, "");
  if (!candidate) return null;
  const clean = candidate.includes("%") ? candidate.split("%", 1)[0] : candidate;
  if (isValidIpv4(clean) || isValidIpv6(clean)) {
    return clean;
  }
  return null;
}

export function isValidIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !value.trim()) return false;
  const ms = Date.parse(value);
  return Number.isFinite(ms);
}

export interface ValidatedEventRow {
  device_id: string;
  event_timestamp: string;
  username: string | null;
  source_ip: string | null;
  event_type: string;
  auth_result: "success" | "failure" | "unknown";
  auth_method: string | null;
  service: string | null;
  raw_event: string | null;
  event_fingerprint: string;
  is_simulated: boolean;
}

export interface ValidatedIncidentPayload {
  device_id: string;
  rule_id: string;
  incident_title: string;
  description: string;
  source_ip: string | null;
  username: string | null;
  severity: "low" | "medium" | "high" | "critical";
  risk_score: number;
  dedup_key: string;
  first_observed: string;
  last_observed: string;
  event_count: number;
  evidence: Record<string, unknown>;
  supporting_fingerprints: string[];
  is_simulated: boolean;
}

export function validateEventsBatch(
  rawEvents: unknown,
  authDeviceId: string,
  deviceIsSimulated: boolean,
): { ok: true; events: ValidatedEventRow[] } | { ok: false; error: string } {
  if (!Array.isArray(rawEvents) || rawEvents.length === 0) {
    return { ok: false, error: "Request must include a non-empty 'events' array" };
  }
  if (rawEvents.length > MAX_EVENTS_PER_BATCH) {
    return {
      ok: false,
      error: `Batch exceeds maximum of ${MAX_EVENTS_PER_BATCH} events`,
    };
  }

  const validated: ValidatedEventRow[] = [];
  for (let i = 0; i < rawEvents.length; i++) {
    const item = rawEvents[i] as Record<string, unknown>;
    if (!item || typeof item !== "object") {
      return { ok: false, error: `Event at index ${i} must be an object` };
    }

    const deviceId = typeof item.device_id === "string" ? item.device_id.trim() : "";
    if (!UUID_RE.test(deviceId) || deviceId !== authDeviceId) {
      return {
        ok: false,
        error: `Event at index ${i} has invalid or mismatched device_id`,
      };
    }

    if (!isValidIsoTimestamp(item.event_timestamp)) {
      return {
        ok: false,
        error: `Event at index ${i} has invalid event_timestamp`,
      };
    }

    const eventType = sanitizeText(item.event_type, 64);
    if (!eventType) {
      return { ok: false, error: `Event at index ${i} is missing event_type` };
    }

    const authResult =
      typeof item.auth_result === "string" ? item.auth_result.trim().toLowerCase() : "";
    if (!ALLOWED_AUTH_RESULTS.has(authResult)) {
      return {
        ok: false,
        error: `Event at index ${i} has invalid auth_result`,
      };
    }

    let sourceIp: string | null = null;
    if (item.source_ip !== null && item.source_ip !== undefined && item.source_ip !== "") {
      sourceIp = validateIp(item.source_ip);
      if (sourceIp === null) {
        return { ok: false, error: `Event at index ${i} has invalid source_ip` };
      }
    }

    const fingerprint =
      typeof item.event_fingerprint === "string" ? item.event_fingerprint.trim().toLowerCase() : "";
    if (!HEX64_RE.test(fingerprint)) {
      return {
        ok: false,
        error: `Event at index ${i} has invalid event_fingerprint`,
      };
    }

    validated.push({
      device_id: authDeviceId,
      event_timestamp: new Date(item.event_timestamp).toISOString(),
      username: sanitizeOptional(item.username, 128),
      source_ip: sourceIp,
      event_type: eventType,
      auth_result: authResult as "success" | "failure" | "unknown",
      auth_method: sanitizeOptional(item.auth_method, 40),
      service: sanitizeOptional(item.service, 40),
      raw_event: sanitizeOptional(item.raw_event, 512),
      event_fingerprint: fingerprint,
      is_simulated: deviceIsSimulated || Boolean(item.is_simulated),
    });
  }

  return { ok: true, events: validated };
}

export function validateIncidentsBatch(
  rawIncidents: unknown,
  authDeviceId: string,
  deviceIsSimulated: boolean,
): { ok: true; incidents: ValidatedIncidentPayload[] } | { ok: false; error: string } {
  if (rawIncidents === undefined || rawIncidents === null) {
    return { ok: true, incidents: [] };
  }
  if (!Array.isArray(rawIncidents)) {
    return { ok: false, error: "'incidents' must be an array when provided" };
  }
  if (rawIncidents.length > MAX_INCIDENTS_PER_BATCH) {
    return {
      ok: false,
      error: `Incidents batch exceeds maximum of ${MAX_INCIDENTS_PER_BATCH}`,
    };
  }

  const validated: ValidatedIncidentPayload[] = [];
  for (let i = 0; i < rawIncidents.length; i++) {
    const inc = rawIncidents[i] as Record<string, unknown>;
    if (!inc || typeof inc !== "object") {
      return { ok: false, error: `Incident at index ${i} must be an object` };
    }

    const deviceId = typeof inc.device_id === "string" ? inc.device_id.trim() : "";
    if (!UUID_RE.test(deviceId) || deviceId !== authDeviceId) {
      return {
        ok: false,
        error: `Incident at index ${i} has invalid or mismatched device_id`,
      };
    }

    const ruleId = sanitizeText(inc.rule_id, 32);
    const title = sanitizeText(inc.incident_title, 200);
    const description = sanitizeText(inc.description, 2000);
    const dedupKey = sanitizeText(inc.dedup_key, 255);
    const severity =
      typeof inc.severity === "string" ? inc.severity.trim().toLowerCase() : "";
    const riskScore = Number(inc.risk_score);
    const eventCount = Number(inc.event_count ?? 1);

    if (!ruleId || !title || !description || !dedupKey) {
      return {
        ok: false,
        error: `Incident at index ${i} is missing required text fields`,
      };
    }
    if (!ALLOWED_SEVERITIES.has(severity)) {
      return { ok: false, error: `Incident at index ${i} has invalid severity` };
    }
    if (!Number.isInteger(riskScore) || riskScore < 0 || riskScore > 100) {
      return { ok: false, error: `Incident at index ${i} has invalid risk_score` };
    }
    if (!Number.isInteger(eventCount) || eventCount < 1) {
      return { ok: false, error: `Incident at index ${i} has invalid event_count` };
    }
    if (!isValidIsoTimestamp(inc.first_observed) || !isValidIsoTimestamp(inc.last_observed)) {
      return { ok: false, error: `Incident at index ${i} has invalid timestamps` };
    }

    let sourceIp: string | null = null;
    if (inc.source_ip !== null && inc.source_ip !== undefined && inc.source_ip !== "") {
      sourceIp = validateIp(inc.source_ip);
      if (sourceIp === null) {
        return { ok: false, error: `Incident at index ${i} has invalid source_ip` };
      }
    }

    const fps = Array.isArray(inc.supporting_fingerprints)
      ? inc.supporting_fingerprints
          .filter((f): f is string => typeof f === "string" && HEX64_RE.test(f.trim()))
          .map((f) => f.trim().toLowerCase())
          .slice(0, 200)
      : [];

    validated.push({
      device_id: authDeviceId,
      rule_id: ruleId,
      incident_title: title,
      description,
      source_ip: sourceIp,
      username: sanitizeOptional(inc.username, 128),
      severity: severity as "low" | "medium" | "high" | "critical",
      risk_score: riskScore,
      dedup_key: dedupKey,
      first_observed: new Date(inc.first_observed).toISOString(),
      last_observed: new Date(inc.last_observed).toISOString(),
      event_count: eventCount,
      evidence:
        inc.evidence && typeof inc.evidence === "object" && !Array.isArray(inc.evidence)
          ? (inc.evidence as Record<string, unknown>)
          : {},
      supporting_fingerprints: fps,
      is_simulated: deviceIsSimulated || Boolean(inc.is_simulated),
    });
  }

  return { ok: true, incidents: validated };
}
