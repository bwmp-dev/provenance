// Contract oracle only: does not authenticate sources or enforce networking.
function closed(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === [...keys].sort().join(",")
  );
}

function bounded(value, maximum) {
  return Number.isInteger(value) && value > 0 && value <= maximum;
}

export function hostname(value) {
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    !value.includes(".") ||
    !/[a-z]/.test(value)
  )
    return false;
  const labels = value.split(".");
  return (
    labels.every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    ) && !labels.every((label) => /^(?:[0-9]+|0x[0-9a-f]+)$/.test(label))
  );
}

function compare(a, b) {
  return a.hostname < b.hostname
    ? -1
    : a.hostname > b.hostname
      ? 1
      : a.port - b.port || a.transport - b.transport;
}

export function validPolicy(policy) {
  if (
    !closed(policy, [
      "mode",
      "permissions",
      "maximumConnections",
      "maximumBytesPerSecond",
    ]) ||
    !Array.isArray(policy.permissions)
  )
    return false;
  const { mode, permissions, maximumConnections, maximumBytesPerSecond } =
    policy;
  if (mode === 1)
    return (
      permissions.length === 0 &&
      maximumConnections === 0 &&
      maximumBytesPerSecond === 0
    );
  return (
    (mode === 2 || mode === 3) &&
    permissions.length > 0 &&
    permissions.length <= 128 &&
    bounded(maximumConnections, 4294967295) &&
    bounded(maximumBytesPerSecond, 4294967295) &&
    permissions.every(
      (p, i) =>
        closed(p, ["hostname", "port", "transport"]) &&
        hostname(p.hostname) &&
        bounded(p.port, 65535) &&
        ![25, 53, 465, 587, 853].includes(p.port) &&
        [1, 2].includes(p.transport) &&
        (i === 0 || compare(permissions[i - 1], p) < 0),
    )
  );
}

export function withinMaximum(effective, maximum) {
  if (!validPolicy(effective) || !validPolicy(maximum)) return false;
  if (effective.mode === 1) return true;
  return (
    maximum.mode !== 1 &&
    effective.maximumConnections <= maximum.maximumConnections &&
    effective.maximumBytesPerSecond <= maximum.maximumBytesPerSecond &&
    effective.permissions.every((p) =>
      maximum.permissions.some((m) => compare(p, m) === 0),
    )
  );
}

// Context booleans below are independently authenticated facts supplied by a
// consumer, never values copied from an offered job or runner labels.
export function admitV2({
  features,
  effective,
  maximum,
  legacyPresent,
  correlationValid,
  messageBytes,
}) {
  return (
    Array.isArray(features) &&
    new Set(features).size === features.length &&
    features.every((f) => Number.isInteger(f) && f >= 1 && f <= 9) &&
    [1, 3, 9].every((f) => features.includes(f)) &&
    legacyPresent === false &&
    correlationValid === true &&
    bounded(messageBytes, 65536) &&
    withinMaximum(effective, maximum)
  );
}
