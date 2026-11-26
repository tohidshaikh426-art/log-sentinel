const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export interface AuthenticatedDevice {
  id: string;
  status: string;
  is_simulated: boolean;
  events_received_count: number;
}

export interface CollectorAuthResult {
  ok: boolean;
  status: number;
  error?: string;
  device?: AuthenticatedDevice;
}

export async function authenticateCollector(
  req: Request,
  // deno-lint-ignore no-explicit-any
  adminClient: any,
): Promise<CollectorAuthResult> {
  const deviceId = req.headers.get("x-device-id")?.trim() ?? "";
  const token = req.headers.get("x-collector-token")?.trim() ?? "";

  if (!UUID_RE.test(deviceId) || token.length < 16 || token.length > 256) {
    return { ok: false, status: 401, error: "Missing or invalid collector credentials" };
  }

  const { data: cred, error: credErr } = await adminClient
    .from("device_credentials")
    .select("device_id, token_hash")
    .eq("device_id", deviceId)
    .maybeSingle();

  if (credErr || !cred?.token_hash) {
    return { ok: false, status: 401, error: "Invalid collector credentials" };
  }

  const incomingHash = await sha256Hex(token);
  if (!timingSafeEqual(incomingHash, String(cred.token_hash))) {
    return { ok: false, status: 401, error: "Invalid collector credentials" };
  }

  const { data: device, error: devErr } = await adminClient
    .from("monitored_devices")
    .select("id, status, is_simulated, events_received_count")
    .eq("id", deviceId)
    .maybeSingle();

  if (devErr || !device) {
    return { ok: false, status: 401, error: "Monitored device not found" };
  }

  if (device.status === "paused") {
    return { ok: false, status: 403, error: "Monitoring is paused for this device" };
  }

  return { ok: true, status: 200, device: device as AuthenticatedDevice };
}

export interface AdminAuthResult {
  ok: boolean;
  status: number;
  error?: string;
  userId?: string;
}

export async function authenticateAdminUser(
  req: Request,
  // deno-lint-ignore no-explicit-any
  anonClient: any,
): Promise<AdminAuthResult> {
  const authHeader = req.headers.get("authorization") ?? "";
  if (!authHeader.toLowerCase().startsWith("bearer ")) {
    return { ok: false, status: 401, error: "Missing bearer authorization token" };
  }

  const jwt = authHeader.slice(7).trim();
  if (!jwt) {
    return { ok: false, status: 401, error: "Empty bearer token" };
  }

  const { data, error } = await anonClient.auth.getUser(jwt);
  if (error || !data?.user?.id) {
    return { ok: false, status: 401, error: "Invalid or expired user session" };
  }

  return { ok: true, status: 200, userId: data.user.id };
}
