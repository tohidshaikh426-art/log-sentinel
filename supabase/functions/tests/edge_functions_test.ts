import assert from "node:assert/strict";
import test from "node:test";

import { sha256Hex } from "../_shared/auth.ts";
import { handleAnalyzeUploadRequest } from "../analyze-upload/handler.ts";
import { handleHeartbeatRequest } from "../collector-heartbeat/handler.ts";
import { handleIngestRequest } from "../ingest-events/handler.ts";
import { handleRunSimulationRequest } from "../run-simulation/handler.ts";

const DEVICE_ID = "11111111-1111-4111-8111-111111111111";
const VALID_TOKEN = "super-secret-collector-token-123456";

function createMockClients(opts: {
  deviceStatus?: string;
  tokenHash?: string;
  existingFingerprints?: Set<string>;
  authUserId?: string | null;
}) {
  const storedEvents = new Map<string, { id: string; event_fingerprint: string }>();
  for (const fp of opts.existingFingerprints ?? []) {
    storedEvents.set(fp, { id: `evt-${fp.slice(0, 8)}`, event_fingerprint: fp });
  }
  const rpcCalls: Array<{ fn: string; args: Record<string, unknown> }> = [];
  const deviceUpdates: Array<Record<string, unknown>> = [];
  const uploadRows: Array<Record<string, unknown>> = [];
  let seq = 1;

  const adminClient = {
    from(table: string) {
      if (table === "device_credentials") {
        return {
          select() {
            return {
              eq(_col: string, val: string) {
                return {
                  async maybeSingle() {
                    if (val !== DEVICE_ID || !opts.tokenHash) {
                      return { data: null, error: null };
                    }
                    return {
                      data: { device_id: DEVICE_ID, token_hash: opts.tokenHash },
                      error: null,
                    };
                  },
                };
              },
            };
          },
          async upsert() {
            return { data: null, error: null };
          },
        };
      }

      if (table === "monitored_devices") {
        return {
          select() {
            return {
              eq(_col: string, val: string) {
                return {
                  async maybeSingle() {
                    if (val === DEVICE_ID || val === "historical-log-analyzer") {
                      return {
                        data: {
                          id: DEVICE_ID,
                          status: opts.deviceStatus ?? "offline",
                          is_simulated: false,
                          events_received_count: 10,
                        },
                        error: null,
                      };
                    }
                    return { data: null, error: null };
                  },
                };
              },
            };
          },
          update(payload: Record<string, unknown>) {
            deviceUpdates.push(payload);
            return {
              async eq() {
                return { error: null };
              },
            };
          },
          insert() {
            return {
              select() {
                return {
                  async single() {
                    return { data: { id: DEVICE_ID }, error: null };
                  },
                };
              },
            };
          },
        };
      }

      if (table === "authentication_events") {
        return {
          upsert(rows: Array<Record<string, unknown>>) {
            const newlyInserted: Array<{ id: string; event_fingerprint: string }> = [];
            for (const row of rows) {
              const fp = String(row.event_fingerprint);
              if (!storedEvents.has(fp)) {
                const record = { id: `evt-${seq++}`, event_fingerprint: fp };
                storedEvents.set(fp, record);
                newlyInserted.push(record);
              }
            }
            return {
              async select() {
                return { data: newlyInserted, error: null };
              },
            };
          },
          select() {
            return {
              async in(_col: string, fps: string[]) {
                const found = fps
                  .map((fp) => storedEvents.get(fp))
                  .filter(Boolean);
                return { data: found, error: null };
              },
            };
          },
        };
      }

      if (table === "analysis_uploads") {
        return {
          insert(payload: Record<string, unknown>) {
            uploadRows.push(payload);
            return {
              select() {
                return {
                  async single() {
                    return { data: { id: "upload-001" }, error: null };
                  },
                };
              },
            };
          },
        };
      }

      throw new Error(`Unexpected table: ${table}`);
    },
    async rpc(fn: string, args: Record<string, unknown>) {
      rpcCalls.push({ fn, args });
      return { data: "inc-001", error: null };
    },
  };

  const anonClient = {
    auth: {
      async getUser(jwt: string) {
        if (opts.authUserId && jwt === "valid-admin-jwt") {
          return { data: { user: { id: opts.authUserId } }, error: null };
        }
        return { data: { user: null }, error: { message: "invalid jwt" } };
      },
    },
  };

  return { adminClient, anonClient, rpcCalls, deviceUpdates, uploadRows };
}

test("ingest-events rejects missing or invalid collector credentials", async () => {
  const tokenHash = await sha256Hex(VALID_TOKEN);
  const { adminClient } = createMockClients({ tokenHash });

  const noCredsReq = new Request("http://localhost/ingest-events", {
    method: "POST",
    body: JSON.stringify({ events: [] }),
  });
  const res1 = await handleIngestRequest(noCredsReq, adminClient);
  assert.equal(res1.status, 401);

  const wrongTokenReq = new Request("http://localhost/ingest-events", {
    method: "POST",
    headers: {
      "x-device-id": DEVICE_ID,
      "x-collector-token": "wrong-collector-token-00000000",
    },
    body: JSON.stringify({ events: [] }),
  });
  const res2 = await handleIngestRequest(wrongTokenReq, adminClient);
  assert.equal(res2.status, 401);
});

test("ingest-events rejects paused device and malformed payloads", async () => {
  const tokenHash = await sha256Hex(VALID_TOKEN);
  const paused = createMockClients({ tokenHash, deviceStatus: "paused" });

  const pausedReq = new Request("http://localhost/ingest-events", {
    method: "POST",
    headers: {
      "x-device-id": DEVICE_ID,
      "x-collector-token": VALID_TOKEN,
    },
    body: JSON.stringify({ events: [] }),
  });
  const resPaused = await handleIngestRequest(pausedReq, paused.adminClient);
  assert.equal(resPaused.status, 403);

  const active = createMockClients({ tokenHash, deviceStatus: "online" });
  const badIpReq = new Request("http://localhost/ingest-events", {
    method: "POST",
    headers: {
      "x-device-id": DEVICE_ID,
      "x-collector-token": VALID_TOKEN,
    },
    body: JSON.stringify({
      events: [
        {
          device_id: DEVICE_ID,
          event_timestamp: "2026-11-26T16:12:38Z",
          event_type: "ssh_failed_password",
          auth_result: "failure",
          source_ip: "999.999.999.999",
          event_fingerprint: "a".repeat(64),
        },
      ],
    }),
  });
  const resBadIp = await handleIngestRequest(badIpReq, active.adminClient);
  assert.equal(resBadIp.status, 400);
});

test("ingest-events persists deduplicated events and correlates incidents", async () => {
  const tokenHash = await sha256Hex(VALID_TOKEN);
  const fp1 = "1".repeat(64);
  const fp2 = "2".repeat(64);
  const { adminClient, rpcCalls, deviceUpdates } = createMockClients({
    tokenHash,
    existingFingerprints: new Set([fp1]),
  });

  const req = new Request("http://localhost/ingest-events", {
    method: "POST",
    headers: {
      "x-device-id": DEVICE_ID,
      "x-collector-token": VALID_TOKEN,
    },
    body: JSON.stringify({
      collector_version: "1.0.0",
      events: [
        {
          device_id: DEVICE_ID,
          event_timestamp: "2026-11-26T16:12:00Z",
          username: "admin",
          source_ip: "203.0.113.55",
          event_type: "ssh_failed_password",
          auth_result: "failure",
          event_fingerprint: fp1,
        },
        {
          device_id: DEVICE_ID,
          event_timestamp: "2026-11-26T16:12:05Z",
          username: "admin",
          source_ip: "203.0.113.55",
          event_type: "ssh_failed_password",
          auth_result: "failure",
          event_fingerprint: fp2,
        },
      ],
      incidents: [
        {
          device_id: DEVICE_ID,
          rule_id: "RULE_001",
          incident_title: "Possible brute-force attempts from 203.0.113.55",
          description: "Repeated failed auth attempts",
          source_ip: "203.0.113.55",
          username: "admin",
          severity: "high",
          risk_score: 51,
          dedup_key: `live:${DEVICE_ID}:RULE_001:203.0.113.55`,
          first_observed: "2026-11-26T16:12:00Z",
          last_observed: "2026-11-26T16:12:05Z",
          event_count: 5,
          evidence: { rule_id: "RULE_001" },
          supporting_fingerprints: [fp1, fp2],
        },
      ],
    }),
  });

  const res = await handleIngestRequest(req, adminClient);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.accepted_count, 1);
  assert.equal(body.duplicate_count, 1);
  assert.equal(body.incidents_upserted, 1);
  assert.equal(rpcCalls.length, 1);
  assert.equal(rpcCalls[0].fn, "upsert_security_incident");
  assert.equal((rpcCalls[0].args.p_event_ids as string[]).length, 2);
  assert.equal(deviceUpdates[0].events_received_count, 11);
});

test("collector-heartbeat updates device online status and timestamp", async () => {
  const tokenHash = await sha256Hex(VALID_TOKEN);
  const { adminClient, deviceUpdates } = createMockClients({ tokenHash });

  const req = new Request("http://localhost/collector-heartbeat", {
    method: "POST",
    headers: {
      "x-device-id": DEVICE_ID,
      "x-collector-token": VALID_TOKEN,
    },
    body: JSON.stringify({ collector_version: "1.0.0", os_info: "Ubuntu 24.04" }),
  });

  const res = await handleHeartbeatRequest(req, adminClient);
  assert.equal(res.status, 200);
  assert.equal(deviceUpdates.length, 1);
  assert.equal(deviceUpdates[0].status, "online");
  assert.equal(deviceUpdates[0].collector_version, "1.0.0");
});

test("analyze-upload rejects unauthorized callers and unsafe files, and detects brute force on valid upload", async () => {
  const { adminClient, anonClient, rpcCalls, uploadRows } = createMockClients({
    authUserId: "admin-user-123",
  });

  const unauthReq = new Request("http://localhost/analyze-upload", {
    method: "POST",
    body: JSON.stringify({ filename: "auth.log", file_format: "auth_log", content: "hi" }),
  });
  const resUnauth = await handleAnalyzeUploadRequest(unauthReq, adminClient, anonClient);
  assert.equal(resUnauth.status, 401);

  const binaryReq = new Request("http://localhost/analyze-upload", {
    method: "POST",
    headers: { authorization: "Bearer valid-admin-jwt" },
    body: JSON.stringify({
      filename: "evil.bin",
      file_format: "auth_log",
      content: "abc\u0000def",
    }),
  });
  const resBin = await handleAnalyzeUploadRequest(binaryReq, adminClient, anonClient);
  assert.equal(resBin.status, 400);

  const sampleAuthLog = [
    "Nov 26 21:41:01 ubuntu sshd[2110]: Failed password for admin from 203.0.113.55 port 40001 ssh2",
    "Nov 26 21:41:05 ubuntu sshd[2112]: Failed password for admin from 203.0.113.55 port 40002 ssh2",
    "Nov 26 21:41:10 ubuntu sshd[2114]: Failed password for admin from 203.0.113.55 port 40003 ssh2",
    "Nov 26 21:41:14 ubuntu sshd[2116]: Failed password for admin from 203.0.113.55 port 40004 ssh2",
    "Nov 26 21:41:18 ubuntu sshd[2118]: Failed password for admin from 203.0.113.55 port 40005 ssh2",
    "corrupted-unparseable-line",
  ].join("\n");

  const validReq = new Request("http://localhost/analyze-upload", {
    method: "POST",
    headers: { authorization: "Bearer valid-admin-jwt" },
    body: JSON.stringify({
      filename: "sample_auth.log",
      file_format: "auth_log",
      content: sampleAuthLog,
    }),
  });

  const resValid = await handleAnalyzeUploadRequest(validReq, adminClient, anonClient);
  assert.equal(resValid.status, 200);
  const data = await resValid.json();
  assert.equal(data.parsed_count, 5);
  assert.equal(data.malformed_count, 1);
  assert.equal(data.incidents_created, 1);
  assert.equal(data.incidents[0].rule_id, "RULE_001");
  assert.equal(rpcCalls.length, 1);
  assert.equal(uploadRows.length, 1);
});

test("run-simulation requires admin auth and executes normal, brute_force, and collector_offline scenarios", async () => {
  const { adminClient, anonClient, rpcCalls, deviceUpdates } = createMockClients({
    authUserId: "admin-user-123",
  });

  const unauthReq = new Request("http://localhost/run-simulation", {
    method: "POST",
    body: JSON.stringify({ scenario: "brute_force" }),
  });
  const unauthRes = await handleRunSimulationRequest(unauthReq, adminClient, anonClient);
  assert.equal(unauthRes.status, 401);

  const normalReq = new Request("http://localhost/run-simulation", {
    method: "POST",
    headers: { authorization: "Bearer valid-admin-jwt" },
    body: JSON.stringify({ scenario: "normal" }),
  });
  const normalRes = await handleRunSimulationRequest(normalReq, adminClient, anonClient);
  assert.equal(normalRes.status, 200);
  const normalData = await normalRes.json();
  assert.equal(normalData.is_simulated, true);
  assert.equal(normalData.events_generated, 4);
  assert.equal(normalData.incidents_generated, 0);

  const bfReq = new Request("http://localhost/run-simulation", {
    method: "POST",
    headers: { authorization: "Bearer valid-admin-jwt" },
    body: JSON.stringify({ scenario: "brute_force" }),
  });
  const bfRes = await handleRunSimulationRequest(bfReq, adminClient, anonClient);
  assert.equal(bfRes.status, 200);
  const bfData = await bfRes.json();
  assert.equal(bfData.events_generated, 7);
  assert.equal(bfData.incidents_generated, 1);
  assert.deepEqual(bfData.rule_ids, ["RULE_001"]);
  assert.equal(rpcCalls[0].args.p_is_simulated, true);

  const offReq = new Request("http://localhost/run-simulation", {
    method: "POST",
    headers: { authorization: "Bearer valid-admin-jwt" },
    body: JSON.stringify({ scenario: "collector_offline" }),
  });
  const offRes = await handleRunSimulationRequest(offReq, adminClient, anonClient);
  assert.equal(offRes.status, 200);
  const lastUpdate = deviceUpdates[deviceUpdates.length - 1];
  assert.equal(lastUpdate.status, "offline");
});
