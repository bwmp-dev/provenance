# Public toolkit repository instructions

- Public contracts are authoritative: OpenAPI for HTTP, Protobuf for runner communication, and JSON Schema for configuration and attestations.
- Never manually edit generated clients or protocol output.
- Keep the CLI, Action, SDK, schemas, fixtures, and probe free of private platform credentials and implementation details.
- Preserve backward compatibility unless the assigned work explicitly changes a versioned contract.
- Unknown configuration fields must fail validation.
- Fixture attacks must be isolated from ordinary test execution and clearly opt-in.
- Add contract/golden tests for every schema or protocol behavior change.
- Never request, tag, invoke, or mention an external automated pull-request reviewer unless the user explicitly names and authorizes that exact service.
- Claude Code invoked locally through `bin/claude-review` is an authorized in-harness independent reviewer. It runs read-only and never tags, comments on, or posts to a pull request. External review bots and pull-request tagging remain prohibited.
