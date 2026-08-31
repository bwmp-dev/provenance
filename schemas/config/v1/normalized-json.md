# Provenance configuration v1 normalization

Validation happens after parsing `provenance.yml` with the YAML 1.2 core schema. Parsers must reject duplicate mapping keys, aliases, non-string mapping keys, custom tags, non-finite numbers, timestamps promoted to native date types, and every value that cannot be represented by the JSON data model. The resulting JSON value must validate against `schema.json` with format validation enabled.

Normalization is intentionally lossless and does not supply defaults. Every required policy decision is explicit in the source file. A conforming normalizer:

1. preserves array order and JSON scalar types;
2. preserves strings byte-for-byte after YAML decoding and performs no Unicode normalization;
3. emits object members in ascending UTF-16 code-unit order;
4. emits no insignificant whitespace and uses the shortest JSON spelling for integers;
5. emits decimal CPU values using the JSON number serialization rules in RFC 8785; and
6. encodes the result as UTF-8 without a byte-order mark or trailing newline.

The SHA-256 configuration hash is the lowercase hexadecimal digest of those exact bytes. `schemas/fixtures/config/valid/hosted.yml` and `hosted.normalized.json` are equivalent; compacting the latter according to these rules gives the hashing input. Its expected digest is recorded in `hosted.normalized.sha256`. Durations are already normalized as integer seconds, memory and disk as integer MiB, and CPU as decimal cores, so unit conversion is never implicit.

`network.mode: unrestricted` is part of the public contract but is only an admissible request. Runtime policy must reject it unless an explicit self-hosted administrator policy permits it. Host allowlists accept DNS hostnames only; resolution and private-address protection remain runtime responsibilities.
