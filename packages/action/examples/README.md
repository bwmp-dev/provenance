# Public or private repository submission

The same flow applies to either repository visibility. First authorize the exact
numeric repository/project/workflow policy on the platform. Replace every uppercase
placeholder and pin the reviewed Action commit; this snippet is not a deployed
configuration. Build the JAR before this step. The platform origin/audience/project
are explicit nonsecret repository variables, not defaults supplied by the Action.

```yaml
name: Submit to Provenance
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
  id-token: write
  statuses: write
jobs:
  submit:
    runs-on: ubuntu-latest
    steps:
      # Checkout/build steps go here, pinned according to repository policy.
      - uses: bwmp-dev/provenance/packages/action@REVIEWED_FULL_COMMIT
        with:
          artifact: build/libs/plugin.jar
          configuration: provenance.yml
          version: ${{ github.ref_name }}
          project: ${{ vars.PROVENANCE_PROJECT }}
          platform-origin: ${{ vars.PROVENANCE_ORIGIN }}
          audience: ${{ vars.PROVENANCE_AUDIENCE }}
          repository: ${{ github.repository }}
          source-commit: ${{ github.sha }}
          source-ref: ${{ github.ref }}
          max-artifact-bytes: "67108864"
          wait: "true"
          report: status
          github-token: ${{ github.token }}
```

For submission only, choose `wait: "false"`. To omit GitHub reporting, use
`report: none`, omit `github-token`, and remove `statuses: write`. Neither mode
claims a matrix result merely because candidate creation succeeded. Do not use a
long-lived Provenance token, a PAT or a forked event to bypass authority failures.
