# Pinned regex grammar dependency

Unmodified `index.js` from `@eslint-community/regexpp` 4.12.2 is retained as
`regexpp.cjs`, with its MIT license. The fixed parser runs in Goja without host,
filesystem, network or module-loader bindings; caller text is passed as a value.
Patterns are limited to 1000 Unicode scalar values by the schema (4000 UTF-8
bytes), with a 100 ms VM interruption timer. Parser validation does not execute
the submitted regex. There is no Node runtime dependency.

- Upstream: https://github.com/eslint-community/regexpp
- Archive: https://registry.npmjs.org/@eslint-community/regexpp/-/regexpp-4.12.2.tgz
- npm SHA-512: `EriSTlt5OC9/7SXkRSCAhfSxxoSUgBm33OH+IkwbdpgoqsSsUg7y3uh+IICI/Qg4BBWr3U2i39RpmycbxMq4ew==`
- Source SHA-256: `8f9526195a26cb0d47a48528e61f0083596d397092296a44fc1c1ac470aba336`
- License SHA-256: `fcf6eabf68ca96988a6b506b4fdc6cc32535d80eb2e11c79724af5ac6f50262b`

Go tests check exact source/license hashes and compare acceptance to the actual
Node 24 Unicode regex constructor and released configuration normalizer.
Do not run a formatter over the pinned source. Go dependencies and their
versions/checksums remain in the CLI module inventory and vulnerability check;
this vendored JavaScript dependency is listed here separately, not represented
as a Go module or added to unrelated contract release archives.
