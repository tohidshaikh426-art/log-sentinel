import type { ParsedEvent } from "./parser.ts";
import type { ValidatedIncidentPayload } from "./validation.ts";

function mapScoreToSeverity(score: number): "low" | "medium" | "high" | "critical" {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function calculateRiskScore(params: {
  failedAttempts: number;
  uniqueUsernames: number;
  durationSeconds: number;
  successAfterFailures: boolean;
  isRepeatOffender: boolean;
}) {
  const failurePoints = Math.min(40, Math.max(0, params.failedAttempts) * 7);
  const targetSpreadPoints = Math.min(25, Math.max(0, params.uniqueUsernames) * 6);
  const successAfterFailureBonus = params.successAfterFailures ? 30 : 0;
  const minutes = Math.max(1, params.durationSeconds / 60);
  const attemptsPerMinute = Number((Math.max(0, params.failedAttempts) / minutes).toFixed(2));
  const velocityBonus =
    params.failedAttempts >= 3 && attemptsPerMinute >= 3.0 ? 10 : 0;
  const repeatOffenderBonus = params.isRepeatOffender ? 20 : 0;

  const totalScore = Math.min(
    100,
    failurePoints +
      targetSpreadPoints +
      successAfterFailureBonus +
      velocityBonus +
      repeatOffenderBonus,
  );

  return {
    risk_score: totalScore,
    severity: mapScoreToSeverity(totalScore),
    breakdown: {
      failure_points: failurePoints,
      target_spread_points: targetSpreadPoints,
      success_after_failure_bonus: successAfterFailureBonus,
      velocity_bonus: velocityBonus,
      repeat_offender_bonus: repeatOffenderBonus,
      attempts_per_minute: attemptsPerMinute,
      total_score: totalScore,
    },
  };
}

function pruneWindow(items: ParsedEvent[], currentMs: number, windowSeconds: number): ParsedEvent[] {
  const cutoff = currentMs - windowSeconds * 1000;
  while (items.length > 0 && Date.parse(items[0].event_timestamp) < cutoff) {
    items.shift();
  }
  return [...items];
}

export function detectIncidents(events: ParsedEvent[]): ValidatedIncidentPayload[] {
  const ordered = [...events].sort(
    (a, b) => Date.parse(a.event_timestamp) - Date.parse(b.event_timestamp),
  );

  const failuresByIp = new Map<string, ParsedEvent[]>();
  const failuresByDevice = new Map<string, ParsedEvent[]>();
  const failuresByIpUser = new Map<string, ParsedEvent[]>();
  const priorOffenders = new Map<string, number>();
  const activeIncidents = new Map<string, ValidatedIncidentPayload>();

  const upsertLocal = (inc: ValidatedIncidentPayload) => {
    const existing = activeIncidents.get(inc.dedup_key);
    if (!existing) {
      activeIncidents.set(inc.dedup_key, inc);
      return;
    }
    const merged = Array.from(
      new Set([...existing.supporting_fingerprints, ...inc.supporting_fingerprints]),
    );
    existing.incident_title = inc.incident_title;
    existing.description = inc.description;
    if (inc.username && !existing.username) existing.username = inc.username;
    if (inc.risk_score >= existing.risk_score) {
      existing.risk_score = inc.risk_score;
      existing.severity = inc.severity;
    }
    if (inc.first_observed < existing.first_observed) existing.first_observed = inc.first_observed;
    if (inc.last_observed > existing.last_observed) existing.last_observed = inc.last_observed;
    existing.event_count = Math.max(existing.event_count, merged.length);
    existing.evidence = inc.evidence;
    existing.supporting_fingerprints = merged;
  };

  const isPriorOffender = (ipKey: string, currentMs: number) => {
    const prev = priorOffenders.get(ipKey);
    if (prev === undefined) return false;
    const ageSec = (currentMs - prev) / 1000;
    return ageSec >= 300 && ageSec <= 86400;
  };

  for (const ev of ordered) {
    const evMs = Date.parse(ev.event_timestamp);
    const prefix = ev.is_simulated ? "sim" : "live";

    if (ev.auth_result === "failure") {
      const devKey = `${ev.device_id}:${ev.is_simulated}`;
      const devList = failuresByDevice.get(devKey) ?? [];
      devList.push(ev);
      failuresByDevice.set(devKey, devList);

      if (ev.source_ip) {
        const ipKey = `${devKey}:${ev.source_ip}`;
        const ipList = failuresByIp.get(ipKey) ?? [];
        ipList.push(ev);
        failuresByIp.set(ipKey, ipList);

        if (ev.username) {
          const ipUserKey = `${ipKey}:${ev.username}`;
          const ipUserList = failuresByIpUser.get(ipUserKey) ?? [];
          ipUserList.push(ev);
          failuresByIpUser.set(ipUserKey, ipUserList);
        }

        const repeat = isPriorOffender(ipKey, evMs);

        // RULE_001: >= 5 failures from same IP within 120s
        const evs1 = pruneWindow(ipList, evMs, 120);
        if (evs1.length >= 5) {
          const users1 = Array.from(
            new Set(evs1.map((e) => e.username).filter((u): u is string => Boolean(u))),
          ).sort();
          const firstTs = evs1[0].event_timestamp;
          const lastTs = evs1[evs1.length - 1].event_timestamp;
          const durSec = (Date.parse(lastTs) - Date.parse(firstTs)) / 1000;
          const score = calculateRiskScore({
            failedAttempts: evs1.length,
            uniqueUsernames: Math.max(1, users1.length),
            durationSeconds: durSec,
            successAfterFailures: false,
            isRepeatOffender: repeat,
          });
          const reason = `Observed ${evs1.length} failed authentication attempts from ${ev.source_ip} within 120s (threshold: 5). Possible brute-force activity.`;
          upsertLocal({
            device_id: ev.device_id,
            rule_id: "RULE_001",
            incident_title: `Possible brute-force attempts from ${ev.source_ip}`,
            description: reason,
            source_ip: ev.source_ip,
            username: users1.length === 1 ? users1[0] : null,
            severity: score.severity,
            risk_score: score.risk_score,
            dedup_key: `${prefix}:${ev.device_id}:RULE_001:${ev.source_ip}`,
            first_observed: firstTs,
            last_observed: lastTs,
            event_count: evs1.length,
            evidence: {
              rule_id: "RULE_001",
              rule_name: "Repeated Failed Authentication (Possible Brute Force)",
              threshold: 5,
              window_seconds: 120,
              observed_count: evs1.length,
              source_ip: ev.source_ip,
              sample_usernames: users1.slice(0, 10),
              trigger_reason: reason,
              score_breakdown: score.breakdown,
            },
            supporting_fingerprints: evs1.map((e) => e.event_fingerprint),
            is_simulated: ev.is_simulated,
          });
          priorOffenders.set(ipKey, evMs);
        }

        // RULE_002: >= 4 distinct usernames from same IP within 300s
        const evs2 = pruneWindow([...ipList], evMs, 300);
        const users2 = Array.from(
          new Set(evs2.map((e) => e.username).filter((u): u is string => Boolean(u))),
        ).sort();
        if (users2.length >= 4) {
          const firstTs = evs2[0].event_timestamp;
          const lastTs = evs2[evs2.length - 1].event_timestamp;
          const durSec = (Date.parse(lastTs) - Date.parse(firstTs)) / 1000;
          const score = calculateRiskScore({
            failedAttempts: evs2.length,
            uniqueUsernames: users2.length,
            durationSeconds: durSec,
            successAfterFailures: false,
            isRepeatOffender: repeat,
          });
          const reason = `Source IP ${ev.source_ip} failed authentication against ${users2.length} distinct usernames within 300s (threshold: 4). Potential password spraying or account enumeration.`;
          upsertLocal({
            device_id: ev.device_id,
            rule_id: "RULE_002",
            incident_title: `Potential password spraying from ${ev.source_ip}`,
            description: reason,
            source_ip: ev.source_ip,
            username: null,
            severity: score.severity,
            risk_score: score.risk_score,
            dedup_key: `${prefix}:${ev.device_id}:RULE_002:${ev.source_ip}`,
            first_observed: firstTs,
            last_observed: lastTs,
            event_count: evs2.length,
            evidence: {
              rule_id: "RULE_002",
              rule_name: "Multiple Target Accounts (Potential Password Spraying)",
              threshold: 4,
              window_seconds: 300,
              observed_count: evs2.length,
              unique_username_count: users2.length,
              source_ip: ev.source_ip,
              sample_usernames: users2.slice(0, 15),
              trigger_reason: reason,
              score_breakdown: score.breakdown,
            },
            supporting_fingerprints: evs2.map((e) => e.event_fingerprint),
            is_simulated: ev.is_simulated,
          });
          priorOffenders.set(ipKey, evMs);
        }

        // RULE_005: Repeat offender (>= 3 new failures after 300s cooldown)
        if (repeat) {
          const evs5 = pruneWindow([...ipList], evMs, 300);
          if (evs5.length >= 3) {
            const users5 = Array.from(
              new Set(evs5.map((e) => e.username).filter((u): u is string => Boolean(u))),
            ).sort();
            const firstTs = evs5[0].event_timestamp;
            const lastTs = evs5[evs5.length - 1].event_timestamp;
            const durSec = (Date.parse(lastTs) - Date.parse(firstTs)) / 1000;
            const score = calculateRiskScore({
              failedAttempts: evs5.length,
              uniqueUsernames: Math.max(1, users5.length),
              durationSeconds: durSec,
              successAfterFailures: false,
              isRepeatOffender: true,
            });
            const reason = `Previously flagged source IP ${ev.source_ip} generated ${evs5.length} additional failed attempts within 300s.`;
            upsertLocal({
              device_id: ev.device_id,
              rule_id: "RULE_005",
              incident_title: `Repeat offender activity from ${ev.source_ip}`,
              description: reason,
              source_ip: ev.source_ip,
              username: users5.length === 1 ? users5[0] : null,
              severity: score.severity,
              risk_score: score.risk_score,
              dedup_key: `${prefix}:${ev.device_id}:RULE_005:${ev.source_ip}`,
              first_observed: firstTs,
              last_observed: lastTs,
              event_count: evs5.length,
              evidence: {
                rule_id: "RULE_005",
                rule_name: "Repeat Offender Activity",
                threshold: 3,
                window_seconds: 300,
                observed_count: evs5.length,
                source_ip: ev.source_ip,
                sample_usernames: users5.slice(0, 10),
                trigger_reason: reason,
                score_breakdown: score.breakdown,
              },
              supporting_fingerprints: evs5.map((e) => e.event_fingerprint),
              is_simulated: ev.is_simulated,
            });
          }
        }
      }

      // RULE_004: >= 20 failures on device within 300s
      const evs4 = pruneWindow(devList, evMs, 300);
      if (evs4.length >= 20) {
        const ips4 = Array.from(
          new Set(evs4.map((e) => e.source_ip).filter((x): x is string => Boolean(x))),
        ).sort();
        const users4 = Array.from(
          new Set(evs4.map((e) => e.username).filter((u): u is string => Boolean(u))),
        ).sort();
        const firstTs = evs4[0].event_timestamp;
        const lastTs = evs4[evs4.length - 1].event_timestamp;
        const durSec = (Date.parse(lastTs) - Date.parse(firstTs)) / 1000;
        const score = calculateRiskScore({
          failedAttempts: evs4.length,
          uniqueUsernames: Math.max(1, users4.length),
          durationSeconds: durSec,
          successAfterFailures: false,
          isRepeatOffender: false,
        });
        const reason = `Device recorded ${evs4.length} failed authentication events across ${ips4.length} source IP(s) within 300s (threshold: 20).`;
        upsertLocal({
          device_id: ev.device_id,
          rule_id: "RULE_004",
          incident_title: "High-volume authentication failures detected",
          description: reason,
          source_ip: ips4.length === 1 ? ips4[0] : null,
          username: null,
          severity: score.severity,
          risk_score: score.risk_score,
          dedup_key: `${prefix}:${ev.device_id}:RULE_004:${ev.device_id}`,
          first_observed: firstTs,
          last_observed: lastTs,
          event_count: evs4.length,
          evidence: {
            rule_id: "RULE_004",
            rule_name: "High-Volume Authentication Failures",
            threshold: 20,
            window_seconds: 300,
            observed_count: evs4.length,
            distinct_source_ips: ips4.slice(0, 15),
            sample_usernames: users4.slice(0, 15),
            trigger_reason: reason,
            score_breakdown: score.breakdown,
          },
          supporting_fingerprints: evs4.map((e) => e.event_fingerprint),
          is_simulated: ev.is_simulated,
        });
      }
    } else if (ev.auth_result === "success" && ev.source_ip && ev.username) {
      const ipKey = `${ev.device_id}:${ev.is_simulated}:${ev.source_ip}`;
      const ipUserKey = `${ipKey}:${ev.username}`;
      const priorFailures = pruneWindow(failuresByIpUser.get(ipUserKey) ?? [], evMs, 600);
      if (priorFailures.length >= 3) {
        const supporting = [...priorFailures, ev];
        const firstTs = supporting[0].event_timestamp;
        const lastTs = ev.event_timestamp;
        const durSec = (Date.parse(lastTs) - Date.parse(firstTs)) / 1000;
        const repeat = isPriorOffender(ipKey, evMs);
        const score = calculateRiskScore({
          failedAttempts: priorFailures.length,
          uniqueUsernames: 1,
          durationSeconds: durSec,
          successAfterFailures: true,
          isRepeatOffender: repeat,
        });
        const reason = `Successful login for '${ev.username}' from ${ev.source_ip} followed ${priorFailures.length} failed attempts within 600s. This pattern may indicate a compromised account, though it does not prove compromise.`;
        upsertLocal({
          device_id: ev.device_id,
          rule_id: "RULE_003",
          incident_title: `Suspicious login after failures for '${ev.username}' from ${ev.source_ip}`,
          description: reason,
          source_ip: ev.source_ip,
          username: ev.username,
          severity: score.severity,
          risk_score: score.risk_score,
          dedup_key: `${prefix}:${ev.device_id}:RULE_003:${ev.source_ip}:${ev.username}`,
          first_observed: firstTs,
          last_observed: lastTs,
          event_count: supporting.length,
          evidence: {
            rule_id: "RULE_003",
            rule_name: "Suspicious Success After Failures",
            threshold: 3,
            window_seconds: 600,
            prior_failures_count: priorFailures.length,
            source_ip: ev.source_ip,
            username: ev.username,
            trigger_reason: reason,
            score_breakdown: score.breakdown,
          },
          supporting_fingerprints: supporting.map((e) => e.event_fingerprint),
          is_simulated: ev.is_simulated,
        });
        priorOffenders.set(ipKey, evMs);
      }
    }
  }

  return Array.from(activeIncidents.values());
}
