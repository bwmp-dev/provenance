// Executable contract vectors, not authentication or production enforcement.
// "reject" also requires fail-closed withdrawal for an admitted enabled job.
const uuid = (v) =>
  typeof v === "string" &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v) &&
  v !== "00000000-0000-0000-0000-000000000000";
const exact = (v, keys) =>
  v !== null &&
  typeof v === "object" &&
  !Array.isArray(v) &&
  Object.keys(v).sort().join(",") === [...keys].sort().join(",");
const leaseKeys = ["leaseId", "jobId", "executionId"];
const attemptKeys = [
  "attemptId",
  "attemptNumber",
  "releaseCandidateId",
  "matrixEntryId",
];
export function instant(value) {
  if (typeof value !== "string") return null;
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!m || m[1].startsWith("0000-")) return null;
  const ms = Date.parse(m[1] + "Z");
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== m[1])
    return null;
  return BigInt(ms) * 1000000n + BigInt((m[2] || "").padEnd(9, "0"));
}
export function reconcileAuthority(c) {
  const deny = { action: "reject" };
  if (
    !Array.isArray(c.features) ||
    c.features.some(
      (f, i) =>
        !Number.isInteger(f) || f < 1 || f > 10 || c.features.indexOf(f) !== i,
    )
  )
    return deny;
  const negotiated = c.features.includes(10);
  if (negotiated && ![1, 3, 9].every((f) => c.features.includes(f)))
    return deny;
  if (
    typeof c.enabled !== "boolean" ||
    ![1, 2, 3, 4, 5, 6, 7].includes(c.status) ||
    typeof c.cancelling !== "boolean"
  )
    return deny;
  if (
    !exact(c.expectedLease, leaseKeys) ||
    !leaseKeys.every((k) => uuid(c.expectedLease[k])) ||
    !exact(c.lease, [...leaseKeys, "expiresAt"]) ||
    !leaseKeys.every((k) => c.lease[k] === c.expectedLease[k])
  )
    return deny;
  if (
    !exact(c.expectedAttempt, attemptKeys) ||
    !["attemptId", "releaseCandidateId", "matrixEntryId"].every((k) =>
      uuid(c.expectedAttempt[k]),
    ) ||
    !Number.isInteger(c.expectedAttempt.attemptNumber) ||
    c.expectedAttempt.attemptNumber < 1 ||
    c.expectedAttempt.attemptNumber > 3 ||
    !exact(c.attempt, attemptKeys) ||
    !attemptKeys.every((k) => c.attempt[k] === c.expectedAttempt[k])
  )
    return deny;
  const now = instant(c.now),
    leaseExpiry = instant(c.lease.expiresAt),
    credentialExpiry = instant(c.credentialExpiresAt);
  const acknowledgedExpiry =
    c.acknowledgedLeaseExpiresAt == null
      ? leaseExpiry
      : instant(c.acknowledgedLeaseExpiresAt);
  if (
    now === null ||
    leaseExpiry === null ||
    credentialExpiry === null ||
    acknowledgedExpiry === null ||
    !/^[a-f0-9]{64}$/.test(c.policySha256)
  )
    return deny;
  const needs = c.enabled && [2, 3].includes(c.status) && !c.cancelling;
  if (!needs)
    return c.observation == null
      ? { action: c.status >= 4 || c.cancelling ? "withdraw" : "no-grant" }
      : deny;
  if (!negotiated) return deny;
  const o = c.observation;
  if (
    !o ||
    ![1, 2].includes(o.state) ||
    !exact(
      o,
      o.state === 1
        ? ["policy", "state", "checkedAt", "expiresAt"]
        : ["policy", "state", "checkedAt"],
    )
  )
    return deny;
  if (
    !exact(o.policy, ["algorithm", "value"]) ||
    o.policy.algorithm !== 1 ||
    typeof o.policy.value !== "string"
  )
    return deny;
  const policy = Buffer.from(o.policy.value, "base64");
  if (
    policy.length !== 32 ||
    policy.toString("base64") !== o.policy.value ||
    policy.toString("hex") !== c.policySha256
  )
    return deny;
  const checked = instant(o.checkedAt);
  if (checked === null || checked > now + 5000000000n) return deny;
  if (o.state === 2) return { action: "withdraw" };
  const expiry = instant(o.expiresAt);
  if (
    expiry === null ||
    expiry <= now ||
    expiry <= checked ||
    expiry > checked + 60000000000n ||
    expiry >
      (leaseExpiry > acknowledgedExpiry ? leaseExpiry : acknowledgedExpiry) ||
    expiry > credentialExpiry
  )
    return deny;
  if (c.prior?.withdrawn === true) return { action: "withdraw" };
  if (c.prior != null) {
    if (
      !exact(c.prior, ["checkedAt", "expiresAt", "withdrawn"]) ||
      c.prior.withdrawn !== false
    )
      return deny;
    const priorCheck = instant(c.prior.checkedAt),
      priorExpiry = instant(c.prior.expiresAt);
    if (
      priorCheck === null ||
      priorExpiry === null ||
      priorExpiry <= priorCheck
    )
      return deny;
    if (priorExpiry <= now) return { action: "withdraw" };
    if (checked === priorCheck && expiry !== priorExpiry) return deny;
    if (checked <= priorCheck)
      return {
        action: "keep",
        checkedAt: c.prior.checkedAt,
        expiresAt: c.prior.expiresAt,
      };
  }
  return { action: "current", checkedAt: o.checkedAt, expiresAt: o.expiresAt };
}
