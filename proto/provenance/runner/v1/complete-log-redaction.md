# Complete-log redaction metadata

`LogObject.redacted` (field 10) carries the trusted collector's observation that
at least one retained log line was redacted. It follows that exact archive through
normal upload, terminal delivery, journal replay and restart recovery. The gateway
persists the fact with the exact execution's immutable object descriptor and
projects it as the existing HTTP `wasRedacted` field.

Do not infer this fact from literal `[REDACTED]` text supplied by a workload, from
the presence of selected secrets, or from a lossy live-log projection. Redaction
must still happen before either archive or live output is exposed.

This is additive metadata, not new authority to release secrets. Fields 5–9 stay
reserved. Legacy messages omit field 10 and decode to false; false is not proof
that output contained no secrets. Deploy consuming persistence before activating
new producers. Historical terminal messages and object descriptors stay immutable.
The existing complete-archive policy still refuses truncated archives; this change
does not authorize publishing incomplete logs or change truncation semantics.
