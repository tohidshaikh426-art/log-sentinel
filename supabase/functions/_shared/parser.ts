import { sha256Hex } from "./auth.ts";
import { sanitizeOptional, sanitizeText, validateIp } from "./validation.ts";

export interface ParsedEvent {
  device_id: string;
  event_timestamp: string;
  username: string | null;
  source_ip: string | null;
  event_type: string;
  auth_result: "success" | "failure" | "unknown";
  auth_method: string | null;
  service: string | null;
  raw_event: string;
  event_fingerprint: string;
  is_simulated: boolean;
}

export interface MalformedLine {
  line_number: number;
  reason: string;
  raw_snippet: string;
}

export interface ParseSummary {
  source_format: string;
  total_lines: number;
  events: ParsedEvent[];
  ignored_count: number;
  malformed_records: MalformedLine[];
}

const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

const RFC3164_RE = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/;
const COMPACT_OFFSET_RE = /([+-]\d{2})(\d{2})$/;

const SYSLOG_HEADER_RE =
  /^((?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+(\S+)\s+([A-Za-z0-9_.\-/]+(?:\([^)]+\))?)(?:\[(\d+)\])?:\s+(.+)$/;

const AUTH_PREFIXES = ["sshd", "sudo", "su", "login", "pam_unix", "passwd", "chsh"];
const BENIGN_PREFIXES = [
  "Server listening on ",
  "Received signal ",
  "pam_unix(",
  "session opened for user ",
  "session closed for user ",
  "Connection closed by ",
  "Disconnected from ",
  "Connection reset by ",
  "Accepted none for ",
  "Did not receive identification string",
  "banner exchange:",
  "Unable to negotiate with ",
];

const SSH_ACCEPTED_RE =
  /^Accepted\s+(password|publickey|keyboard-interactive\/pam|keyboard-interactive)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+/;
const SSH_FAILED_INVALID_RE =
  /^Failed\s+(password|publickey|keyboard-interactive\/pam|none)\s+for\s+invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+/;
const SSH_FAILED_VALID_RE =
  /^Failed\s+(password|publickey|keyboard-interactive\/pam|none)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+/;
const SSH_INVALID_USER_RE = /^Invalid\s+user\s+(\S+)\s+from\s+(\S+)(?:\s+port\s+\d+)?/;
const SSH_MAX_AUTH_RE =
  /^error:\s+maximum\s+authentication\s+attempts\s+exceeded\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+\d+/;
const SSH_DISCONNECT_AUTH_RE =
  /^(?:Disconnected\s+from|Connection\s+closed\s+by)\s+(authenticating|invalid)\s+user\s+(\S+)\s+(\S+)\s+port\s+\d+/;

const PAM_RHOST_RE = /\brhost=([^\s;]+)/;
const PAM_USER_RE = /\buser=([^\s;]+)/;
const SUDO_FAILED_RE = /^(\S+)\s*:\s*\d+\s+incorrect\s+password\s+attempts\b/;
const SUDO_SUCCESS_RE = /^(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=.*;\s*USER=\S+\s*;\s*COMMAND=/;
const LOGIN_FAILED_RE =
  /^FAILED\s+LOGIN\s+\(\d+\)\s+on\s+.+?\s+FOR\s+['"]?([^'",\s]+)['"]?,\s+Authentication\s+failure/;
const SU_FAILED_RE = /^FAILED\s+su\s+for\s+(\S+)\s+by\s+(\S+)/;

function cleanUsername(value: string | null | undefined): string | null {
  const cleaned = sanitizeOptional(value, 128);
  if (!cleaned || cleaned === "-" || cleaned === "(unknown)" || cleaned === "unknown") {
    return null;
  }
  return cleaned;
}

export function parseTimestampToUtcIso(rawTs: string, refNow = new Date()): string | null {
  const ts = rawTs.trim();
  if (!ts) return null;

  const rfc = RFC3164_RE.exec(ts);
  if (rfc) {
    const month = MONTHS[rfc[1]];
    if (month === undefined) return null;
    const day = Number(rfc[2]);
    const hour = Number(rfc[3]);
    const minute = Number(rfc[4]);
    const second = Number(rfc[5]);
    if (day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return null;

    let year = refNow.getUTCFullYear();
    let candidate = new Date(Date.UTC(year, month, day, hour, minute, second));
    if (candidate.getUTCMonth() !== month || candidate.getUTCDate() !== day) {
      return null;
    }
    if (candidate.getTime() - refNow.getTime() > 7 * 86400 * 1000) {
      year -= 1;
      candidate = new Date(Date.UTC(year, month, day, hour, minute, second));
    }
    return candidate.toISOString().replace(".000Z", "Z");
  }

  let normalized = ts;
  if (COMPACT_OFFSET_RE.test(normalized)) {
    normalized = normalized.replace(COMPACT_OFFSET_RE, "$1:$2");
  }
  if (!/[zZ]|[+-]\d{2}:\d{2}$/.test(normalized)) {
    normalized = `${normalized}Z`;
  }
  const ms = Date.parse(normalized);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString().replace(".000Z", "Z");
}

function isBenignNoise(msg: string): boolean {
  if (msg.startsWith("pam_unix(") && msg.includes("authentication failure;")) {
    return false;
  }
  return BENIGN_PREFIXES.some((prefix) => msg.startsWith(prefix));
}

function normalizeProc(proc: string): string {
  const base = proc.split("(", 1)[0].toLowerCase();
  return base.startsWith("sshd") ? "sshd" : base;
}

export async function parseSyslogLines(
  lines: string[],
  deviceId: string,
  sourceFormat: "auth_log" | "journal",
  isSimulated = false,
): Promise<ParseSummary> {
  const summary: ParseSummary = {
    source_format: sourceFormat,
    total_lines: 0,
    events: [],
    ignored_count: 0,
    malformed_records: [],
  };

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNumber = idx + 1;
    const rawLine = lines[idx] ?? "";
    summary.total_lines += 1;
    const trimmed = rawLine.trim();
    if (!trimmed) {
      summary.ignored_count += 1;
      continue;
    }

    const header = SYSLOG_HEADER_RE.exec(trimmed);
    if (!header) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: "Line does not match supported syslog or journald header format",
        raw_snippet: sanitizeText(rawLine, 160),
      });
      continue;
    }

    const eventTimestamp = parseTimestampToUtcIso(header[1]);
    if (!eventTimestamp) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: `Unrecognized timestamp format: ${header[1]}`,
        raw_snippet: sanitizeText(rawLine, 160),
      });
      continue;
    }

    const procRaw = header[3];
    const msg = header[5].trim();
    if (!AUTH_PREFIXES.some((p) => procRaw.toLowerCase().startsWith(p))) {
      summary.ignored_count += 1;
      continue;
    }

    const service = sanitizeOptional(normalizeProc(procRaw), 40);
    const rawEvent = sanitizeText(trimmed, 512);
    let username: string | null = null;
    let sourceIp: string | null = null;
    let eventType: string | null = null;
    let authResult: "success" | "failure" | "unknown" | null = null;
    let authMethod: string | null = null;
    let errReason: string | null = null;

    let m: RegExpExecArray | null;
    if ((m = SSH_ACCEPTED_RE.exec(msg))) {
      username = cleanUsername(m[2]);
      sourceIp = validateIp(m[3]);
      if (!sourceIp) errReason = "Invalid IP address in SSH accepted log";
      eventType = "ssh_accepted_login";
      authResult = "success";
      authMethod = m[1].startsWith("keyboard-interactive") ? "keyboard-interactive" : m[1];
    } else if ((m = SSH_FAILED_INVALID_RE.exec(msg))) {
      username = cleanUsername(m[2]);
      sourceIp = validateIp(m[3]);
      if (!sourceIp) errReason = "Invalid IP address in SSH invalid user log";
      eventType = "ssh_invalid_user";
      authResult = "failure";
      authMethod = m[1];
    } else if ((m = SSH_FAILED_VALID_RE.exec(msg))) {
      username = cleanUsername(m[2]);
      sourceIp = validateIp(m[3]);
      if (!sourceIp) errReason = "Invalid IP address in SSH failed log";
      eventType = m[1] === "password" ? "ssh_failed_password" : "ssh_auth_failure";
      authResult = "failure";
      authMethod = m[1];
    } else if ((m = SSH_INVALID_USER_RE.exec(msg))) {
      username = cleanUsername(m[1]);
      sourceIp = validateIp(m[2]);
      if (!sourceIp) errReason = "Invalid IP address in invalid user log";
      eventType = "ssh_invalid_user";
      authResult = "failure";
      authMethod = "ssh";
    } else if ((m = SSH_MAX_AUTH_RE.exec(msg))) {
      username = cleanUsername(m[1]);
      sourceIp = validateIp(m[2]);
      if (!sourceIp) errReason = "Invalid IP address in max auth log";
      eventType = "ssh_auth_failure";
      authResult = "failure";
      authMethod = "ssh";
    } else if ((m = SSH_DISCONNECT_AUTH_RE.exec(msg))) {
      username = cleanUsername(m[2]);
      sourceIp = validateIp(m[3]);
      if (!sourceIp) errReason = "Invalid IP address in disconnect auth log";
      eventType = m[1] === "invalid" ? "ssh_invalid_user" : "ssh_auth_failure";
      authResult = "failure";
      authMethod = "ssh";
    } else if (msg.includes("authentication failure;")) {
      const rhost = PAM_RHOST_RE.exec(msg);
      const user = PAM_USER_RE.exec(msg);
      sourceIp = rhost ? validateIp(rhost[1]) : null;
      username = user ? cleanUsername(user[1]) : null;
      eventType = "pam_auth_failure";
      authResult = "failure";
      authMethod = "pam";
    } else if (service === "sudo" && (m = SUDO_FAILED_RE.exec(msg))) {
      username = cleanUsername(m[1]);
      eventType = "sudo_auth_failure";
      authResult = "failure";
      authMethod = "sudo";
    } else if (service === "sudo" && (m = SUDO_SUCCESS_RE.exec(msg))) {
      username = cleanUsername(m[1]);
      eventType = "sudo_auth_success";
      authResult = "success";
      authMethod = "sudo";
    } else if ((m = LOGIN_FAILED_RE.exec(msg))) {
      username = cleanUsername(m[1]);
      eventType = "local_auth_failure";
      authResult = "failure";
      authMethod = "password";
    } else if ((m = SU_FAILED_RE.exec(msg))) {
      username = cleanUsername(m[1]);
      eventType = "su_auth_failure";
      authResult = "failure";
      authMethod = "su";
    } else {
      if (isBenignNoise(msg)) {
        summary.ignored_count += 1;
      } else {
        summary.malformed_records.push({
          line_number: lineNumber,
          reason: `Unrecognized authentication message format for service '${service}'`,
          raw_snippet: sanitizeText(rawLine, 160),
        });
      }
      continue;
    }

    if (errReason || !eventType || !authResult) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: errReason ?? "Invalid event record",
        raw_snippet: sanitizeText(rawLine, 160),
      });
      continue;
    }

    const fingerprint = await sha256Hex(
      [
        deviceId,
        eventTimestamp,
        username ?? "",
        sourceIp ?? "",
        eventType,
        rawEvent,
        `${sourceFormat}:${lineNumber}`,
      ].join("|"),
    );

    summary.events.push({
      device_id: deviceId,
      event_timestamp: eventTimestamp,
      username,
      source_ip: sourceIp,
      event_type: eventType,
      auth_result: authResult,
      auth_method: sanitizeOptional(authMethod, 40),
      service,
      raw_event: rawEvent,
      event_fingerprint: fingerprint,
      is_simulated: isSimulated,
    });
  }

  return summary;
}

function splitCsvRow(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      fields.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

export async function parseCsvContent(
  text: string,
  deviceId: string,
  isSimulated = false,
): Promise<ParseSummary> {
  const summary: ParseSummary = {
    source_format: "csv",
    total_lines: 0,
    events: [],
    ignored_count: 0,
    malformed_records: [],
  };

  const nonEmpty = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (nonEmpty.length === 0) return summary;

  const headers = splitCsvRow(nonEmpty[0]).map((h) => h.trim());
  const required = ["event_timestamp", "event_type", "auth_result"];
  const missing = required.filter((col) => !headers.includes(col));
  if (missing.length > 0) {
    summary.total_lines = nonEmpty.length;
    summary.malformed_records.push({
      line_number: 1,
      reason: `Missing required CSV columns: ${missing.join(", ")}`,
      raw_snippet: sanitizeText(nonEmpty[0], 160),
    });
    return summary;
  }

  for (let i = 1; i < nonEmpty.length; i++) {
    const lineNumber = i + 1;
    summary.total_lines += 1;
    const cols = splitCsvRow(nonEmpty[i]);
    if (cols.length > headers.length) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: "CSV row has more columns than header",
        raw_snippet: sanitizeText(nonEmpty[i], 160),
      });
      continue;
    }

    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = (cols[idx] ?? "").trim();
    });

    const eventTimestamp = parseTimestampToUtcIso(row.event_timestamp ?? "");
    if (!eventTimestamp) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: `Unrecognized timestamp format: ${row.event_timestamp ?? ""}`,
        raw_snippet: sanitizeText(nonEmpty[i], 160),
      });
      continue;
    }

    const eventType = sanitizeOptional(row.event_type, 64);
    if (!eventType) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: "Missing event_type",
        raw_snippet: sanitizeText(nonEmpty[i], 160),
      });
      continue;
    }

    const authResult = (row.auth_result ?? "").toLowerCase();
    if (!["success", "failure", "unknown"].includes(authResult)) {
      summary.malformed_records.push({
        line_number: lineNumber,
        reason: `Invalid auth_result '${authResult}'`,
        raw_snippet: sanitizeText(nonEmpty[i], 160),
      });
      continue;
    }

    let sourceIp: string | null = null;
    if (row.source_ip) {
      sourceIp = validateIp(row.source_ip);
      if (!sourceIp) {
        summary.malformed_records.push({
          line_number: lineNumber,
          reason: `Invalid source_ip '${row.source_ip}'`,
          raw_snippet: sanitizeText(nonEmpty[i], 160),
        });
        continue;
      }
    }

    const username = cleanUsername(row.username);
    const authMethod = sanitizeOptional(row.auth_method, 40);
    const service = sanitizeOptional(row.service, 40) ?? "csv_import";
    const rawEvent = sanitizeText(
      row.raw_event ||
        `csv event_type=${eventType} user=${username ?? "-"} ip=${sourceIp ?? "-"} result=${authResult}`,
      512,
    );

    const fingerprint = await sha256Hex(
      [
        deviceId,
        eventTimestamp,
        username ?? "",
        sourceIp ?? "",
        eventType,
        rawEvent,
        `csv:${lineNumber}`,
      ].join("|"),
    );

    summary.events.push({
      device_id: deviceId,
      event_timestamp: eventTimestamp,
      username,
      source_ip: sourceIp,
      event_type: eventType,
      auth_result: authResult as "success" | "failure" | "unknown",
      auth_method: authMethod,
      service,
      raw_event: rawEvent,
      event_fingerprint: fingerprint,
      is_simulated: isSimulated,
    });
  }

  return summary;
}
