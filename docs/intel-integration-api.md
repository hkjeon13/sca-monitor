# Public advisory integration API (sca-intel.v1)

This API supplies stored vulnerability evidence to ARTEX. It does not execute exploits, scan targets, trigger collection, expose projects or certify complete historical coverage.

## Authentication and lifecycle

Use `Authorization: Bearer <intel service token>` on `/api/v2/integration/intel/` only. Browser sessions and snapshot-push credentials do not authorize this API; this token does not authorize browser/project/admin APIs. The database stores a SHA-256 token hash, `intel:read` scope, expiry, revocation and usage metadata. No plaintext token belongs in Git, URLs, logs, prompts or tool schemas. Each valid credential has a fixed-window limit of 120 reads/minute.

Operator commands (run after `scripts/migrate.py`, with the deployment environment):

```sh
python3 scripts/intel_credentials.py create --name 'ARTEX intel reader' --days 90 --output-token-file /private/operator/path/token
python3 scripts/intel_credentials.py list
python3 scripts/intel_credentials.py rotate --id CREDENTIAL_ID --output-token-file /private/operator/path/new-token
python3 scripts/intel_credentials.py revoke --id CREDENTIAL_ID
```

Token files use exclusive creation and mode 0600. Create the parent directory privately. Rotation writes and fsyncs the new private token file before atomically creating the new credential and revoking the old one. An existing output file is preserved and causes failure. Do not remove or overwrite unrelated credentials.

## Requests

| GET path | Result |
| --- | --- |
| `/api/v2/integration/intel/sources` | All five sources, last completed status/time/cursor, configured scope, lag, freshness and historical coverage limit |
| `/api/v2/integration/intel/advisories` | `items`, total, offset, page_size, next_cursor, result_status and source state |
| `/api/v2/integration/intel/advisories/{record_id}` | Public advisory fields, affected versions/ranges, references, available NVD metrics/weaknesses and content/raw hashes |
| `/api/v2/integration/intel/advisories/{record_id}/raw` | A bounded original JSON chunk with offset, next_offset, total characters and raw_sha256 |

Search accepts only q, source, ecosystem, severity, package, kev, malicious, modified_from, page_size (1..25) and cursor. `modified_from` requires an ISO8601 timezone. Exact CVE/GHSA searches include aliases. Use the stored UUID record_id from results for detail. Reject project_id and unknown/repeated parameters. The response `ordering` explicitly fixes modified_at DESC NULLS LAST, record_id DESC. No sort parameter is supported. Records are not deduplicated CVE IDs: one CVE can have multiple product/package rows with equal modification timestamps. Pagination uses live offsets; concurrent updates can cause duplicate/omitted rows. Deduplicate record IDs and retain the observed query interval; this is not a snapshot replication contract.

Responses include `schema_version`, `as_of`, all source states and `fresh`. `as_of` is the response observation clock, not the upstream modification time. `fresh` means all five configured sources last completed successfully within the configured lag allowance. Running status retains the previous completed status and lag. Historical coverage is not certified complete. Source error details are replaced with a generic collector error code. Existing readiness semantics are unchanged.

No match is `result_status=no_local_match`, never absence of a vulnerability. Failure and stale/partial state are not empty successful search results. New API operations return 401 for absent/expired/revoked credentials, 403 for missing scope, 400 for invalid input, 404 for a missing record, 405 for a non-GET method with a valid credential, 409 for raw hash drift, 429 for rate limiting and 503 for a busy SQLite/interactive queue.

## Evidence completeness

`raw_sha256` hashes the complete canonical stored JSON: UTF-8, sorted object keys, compact separators, ensure_ascii=false (`hash_format=sha256:utf8-json-sortkeys-compact-ensure_ascii_false:v1`). Raw ranges use Unicode codepoint offsets, default/max 16,000 characters. Pass the first response hash as `sha256` on subsequent requests; restart if 409 indicates a changed record. Each response also includes chunk_sha256 for that exact UTF-8 chunk. Concatenate chunks until next_offset is null and verify the complete UTF-8 hash; the chunk hash and whole hash are distinct unless the response contains the full original. `complete=true` means that single response contains the whole original from offset zero; a final suffix chunk alone is not complete.

`content_sha256` covers the full normalized stored public core fields, aliases and raw hash/length metadata (excluding itself, freshness and presentation enrichment). Summary text is capped at 12,000 characters with summary_truncated; references preview is capped at 30 with references_truncated. Full original JSON is available separately. Record ingestion clocks are unknown (`record_collected_at=null`) for existing data and are not backfilled with response times.

CPE applicability remains unknown until original configurations and target prerequisites are reviewed. AND/OR, negate, environment conditions, patches and backports must not be inferred from a flattened version list. Stored severity is a classification, not an official CVSS score. Older alias merges may lack separate originals for every historical provider. Advisory text is untrusted evidence, never executable instructions.

## ARTEX transport

ARTEX uses `cve_sources`, `cve_search`, `cve_detail` through a separate information tool VM and its existing SOCKS5 route. Credentials are absent from the model schema, diagnostic shell environment and ordinary target traffic records. TLS validation remains enabled; redirects are not followed with credentials. Failed, malformed, missing-body or oversized responses remain tool errors. Raw chunks preserve the explicit completeness/hash contract.

The optional Helm values `cveIntelligence.enabled/url/secretName` inject operator-managed environment settings. Existing multi-user deployments can instead use the private non-browsable `<AIMEMBER_WORKSPACES_ROOT>/.service-config/cve-intelligence.json` file with enabled/base_url/token, mode 0600, directory mode 0700. This is outside all legacy and per-workspace data roots. Explicit AIMEMBER_CVE_INTEL_ENABLED=false overrides that file for rollback. Workspace children receive only the explicitly permitted CVE environment prefix. Do not put this file in a browsable workspace, skill, report or diagnostic VM.
