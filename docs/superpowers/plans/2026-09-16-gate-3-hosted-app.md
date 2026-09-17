# Gate 3 Hosted GitHub App Private Beta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and validate a private-beta GitHub App that receives authenticated pull-request events, schedules tenant-scoped ProofRail analysis in ephemeral workers, stores canonical artifacts with strict isolation, and publishes results through separately scoped credentials.

**Architecture:** A public webhook API verifies GitHub signatures and installation/repository authorization before creating an idempotent durable job in PostgreSQL. A read worker leases the job, mints a short-lived read-only installation token, materializes exact revisions into a per-job workspace, runs the promoted offline engine, and writes a tenant-prefixed canonical artifact; a distinct publisher leases the result, mints a checks/publication token, verifies the artifact identity, and publishes without access to source checkout credentials.

**Tech Stack:** Go 1.27.1, PostgreSQL 18, `github.com/jackc/pgx/v5 v5.11.0`, AWS SDK for Go v2 core `v1.47.0`, config `v1.33.5`, S3 `v1.113.1`, Docker/OCI, OpenTofu, AWS ECS Fargate, RDS PostgreSQL, S3, KMS, Secrets Manager, CloudWatch, private subnets with controlled egress.

**Spec:** `docs/superpowers/specs/2026-09-16-proofrail-design.md`

## Global Constraints

- Gate 2 must be promoted before any hosted runtime is deployed.
- Hosted code never changes Gate 1 analysis semantics; it binds inputs and invokes the promoted engine.
- Every persistent row, object key, log field, cache key, quota, and identifier is tenant-scoped.
- Installation/repository authorization is checked on every webhook and again before work and publication.
- Read and publish capabilities use separate short-lived tokens and separate processes/IAM roles.
- One fresh workspace per job; no cross-job source cache, dependency cache, or credential reuse.
- Deny-default egress. Webhook API reaches PostgreSQL only; reader reaches GitHub and artifact storage; publisher reaches GitHub and artifact storage; analysis subprocess has network namespace/egress denied.
- No raw source, patch, secret, or webhook payload appears in logs. Canonical artifacts follow the approved redaction rules.
- Private-beta retention is 30 days for canonical results/audit, 7 days for failure diagnostics, and zero retention for workspaces; tenant deletion completes within 24 hours and is auditable.
- Private beta requires five invited installations, at least 500 analyses, zero confirmed cross-tenant leaks, and 99.5% service completion over 30 days.

---

## Exact hosted contracts

```go
// internal/hosted/tenant/model.go
type ID string
type Context struct { TenantID ID; InstallationID int64; RepositoryID int64 }
func (c Context) Validate() error
```

```go
// internal/hosted/webhook/handler.go
type Handler struct { Secrets SecretProvider; Authorizer Authorizer; Jobs JobCreator; Clock Clock }
func (h Handler) ServeHTTP(http.ResponseWriter, *http.Request)
```

```go
// internal/hosted/jobs/api.go
type Store interface {
    Create(context.Context, CreateRequest) (Job, bool, error)
    Lease(context.Context, tenant.ID, WorkerKind, time.Duration) (Job, error)
    Heartbeat(context.Context, tenant.Context, JobID, LeaseToken, time.Duration) error
    Complete(context.Context, tenant.Context, JobID, LeaseToken, Completion) error
    Fail(context.Context, tenant.Context, JobID, LeaseToken, Failure) error
}
```

```go
// internal/hosted/githubapp/api.go
type TokenBroker interface { ReadToken(context.Context, tenant.Context) (Token, error); PublishToken(context.Context, tenant.Context) (Token, error) }
type SourceClient interface { Archive(context.Context, Token, Repository, SHA) (io.ReadCloser, int64, error) }
type CheckPublisher interface { Upsert(context.Context, Token, CheckRequest) (CheckResult, error) }
```

```go
// internal/hosted/store/api.go
type ObjectStore interface {
    Put(context.Context, tenant.Context, Object) (Digest, error)
    Get(context.Context, tenant.Context, Key, Digest) (io.ReadCloser, error)
    DeleteTenant(context.Context, tenant.ID) error
}
```

## Task 1: Gate 3 threat-model delta and service contracts

**Files:**
- Modify: `docs/threat-model.md`
- Modify: `docs/architecture.md`
- Create: `docs/decisions/0002-hosted-private-beta.md`
- Create: `internal/hosted/tenant/model.go`
- Create: `internal/hosted/tenant/model_test.go`

**Interfaces:**
- Produces the exact hosted trust boundaries, retention policy, service identities, and validated `tenant.Context` required by every later package.

- [ ] **Step 1: Document the hosted data-flow and authority matrix**

ADR 0002 must enumerate webhook/API, PostgreSQL, reader worker, analysis subprocess, artifact store, publisher, GitHub, KMS/secrets, operator, and tenant boundaries. For each component record inbound/outbound protocols, credentials, accessible data, retention, failure behavior, quotas, and kill switch.

- [ ] **Step 2: Write failing tenant-context tests**

Test empty tenant, nonpositive installation/repository IDs, mismatched installation/repository authorization, serialization, log attributes, and explicit refusal to derive tenant identity from owner/repository names alone.

- [ ] **Step 3: Verify RED, implement, and review**

Run RED: `go test ./internal/hosted/tenant -v`.

Implement opaque tenant IDs as 128-bit random lowercase hex generated server-side; use numeric GitHub installation and repository IDs as bound attributes, never tenancy keys. Run GREEN and obtain design review of ADR 0002 before database work.

- [ ] **Step 4: Commit**

Commit: `docs: define hosted private beta boundaries`

## Task 2: PostgreSQL schema, migrations, and row-level isolation

**Files:**
- Create: `migrations/0001_hosted_core.up.sql`
- Create: `migrations/0001_hosted_core.down.sql`
- Create: `internal/hosted/store/postgres.go`
- Create: `internal/hosted/store/postgres_test.go`
- Create: `internal/hosted/store/migrate.go`
- Create: `internal/hosted/store/migrate_test.go`

**Interfaces:**
- Produces transaction-scoped tenant storage for installations, repositories, deliveries, jobs, artifacts, checks, audit events, quotas, and deletion requests.

- [ ] **Step 1: Write failing migration and isolation tests against PostgreSQL 18**

Start a disposable PostgreSQL service. Apply up/down/up migrations, run two tenants, and assert tenant A cannot select, insert, update, delete, reference, lease, or infer counts/timing for tenant B. Test each table and every composite foreign key.

- [ ] **Step 2: Define the schema with tenant-leading keys**

Every table uses `tenant_id text not null`; tenant-owned primary keys are composite `(tenant_id, id)`. Required tables are `tenants`, `installations`, `repositories`, `deliveries`, `jobs`, `artifacts`, `check_publications`, `audit_events`, `tenant_quotas`, and `deletion_requests`. Store GitHub IDs as `bigint`, SHAs as constrained lowercase hex text, digests as `sha256:` text, timestamps as `timestamptz`, and job payload as typed columns rather than raw webhook JSON.

- [ ] **Step 3: Add database-enforced containment**

Enable and force RLS on every tenant table. Policies require `tenant_id = current_setting('proofrail.tenant_id', true)` and reject a missing setting. Each transaction begins with `SET LOCAL proofrail.tenant_id = $1`; connection-pool acquisition resets session state. Composite foreign keys include tenant ID so cross-tenant references cannot exist even if application checks fail.

- [ ] **Step 4: Implement serialized migrations**

Use `pg_advisory_lock` with a fixed project key, embedded migration checksums, one transaction per migration, and refusal when an applied checksum differs. The service role cannot bypass RLS; a separate migration role owns schema changes and is unavailable to runtime tasks.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/hosted/store -run 'TestMigration|TestTenantIsolation' -v -count=3 && go test ./...`.

Commit: `feat: enforce tenant isolation in postgres`

## Task 3: Webhook authenticity, replay defense, and authorization

**Files:**
- Create: `internal/hosted/webhook/signature.go`
- Create: `internal/hosted/webhook/signature_test.go`
- Create: `internal/hosted/webhook/handler.go`
- Create: `internal/hosted/webhook/handler_test.go`
- Create: `internal/hosted/authz/authorizer.go`
- Create: `internal/hosted/authz/authorizer_test.go`

**Interfaces:**
- Handles `POST /github/webhooks`; accepts only supported pull-request and installation/repository events.

- [ ] **Step 1: Write failing signature tests**

Test `X-Hub-Signature-256` HMAC-SHA256 over exact raw bytes with `hmac.Equal`, current and previous rotated secret, missing/malformed/multiple headers, SHA-1 header only, body over 1 MiB, compressed body, chunked body, and timing-insensitive failure behavior.

- [ ] **Step 2: Write failing handler tests**

Test required headers, content type, delivery UUID, supported event/action allow-list, redelivery deduplication, installation suspension/deletion, repository transfer/removal, unknown installation/repository, pull requests with missing base/head, and duplicate delivery with different payload digest. Successful responses return `202`; invalid signatures return `401`; unauthorized installations return `404`; malformed data returns `400`; temporary storage failure returns `503`.

- [ ] **Step 3: Verify RED and implement bounded decoding**

Read through `http.MaxBytesReader`, verify signature before JSON decoding, use `json.Decoder.DisallowUnknownFields` only on the narrow local envelope, bind installation ID/repository ID/base SHA/head SHA/PR number, and discard raw payload after the transaction. Insert delivery digest with a unique `(tenant_id, delivery_id)` constraint and create at most one job.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/webhook ./internal/hosted/authz -v -race && go test ./...`.

Commit: `feat: authenticate and authorize github webhooks`

## Task 4: Separate GitHub App token capabilities

**Files:**
- Create: `internal/hosted/githubapp/jwt.go`
- Create: `internal/hosted/githubapp/jwt_test.go`
- Create: `internal/hosted/githubapp/tokens.go`
- Create: `internal/hosted/githubapp/tokens_test.go`
- Create: `internal/hosted/githubapp/client.go`
- Create: `internal/hosted/githubapp/client_test.go`

**Interfaces:**
- Reader requests installation token permissions `{contents: read, metadata: read}`.
- Publisher requests `{checks: write, security_events: write, metadata: read}` and has no contents permission.

- [ ] **Step 1: Write failing JWT/token tests**

Use synthetic RSA keys. Assert JWT algorithm RS256, issued-at no more than 60 seconds in the past, expiry no more than 9 minutes, exact app issuer, no key bytes in errors, TLS-only GitHub base URL, response cap, token expiry handling, and no token persistence or logging.

- [ ] **Step 2: Write failing capability tests**

Fake GitHub endpoints and assert reader and publisher request exact non-overlapping permissions and repository scoping. Prove the read client cannot call Checks/SARIF methods and publisher has no archive/content method in its interface.

- [ ] **Step 3: Implement with KMS-backed signer interface**

Define `Signer.Sign(ctx, sha256Digest) ([]byte, error)` so production uses KMS asymmetric signing and local tests use an in-memory key. Keep installation tokens only in process memory until expiry-minus-60-seconds; cache keys include installation, repository, and capability; never share read/publish tokens.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/githubapp -v -race && go test ./...`.

Commit: `feat: separate github read and publish credentials`

## Task 5: Durable idempotent jobs, leases, retries, and quotas

**Files:**
- Create: `internal/hosted/jobs/model.go`
- Create: `internal/hosted/jobs/store.go`
- Create: `internal/hosted/jobs/store_test.go`
- Create: `internal/hosted/jobs/quota.go`
- Create: `internal/hosted/jobs/quota_test.go`

**Interfaces:**
- Job states: `queued`, `reading`, `analyzing`, `ready_to_publish`, `publishing`, `complete`, `failed`, `cancelled`.
- Unique idempotency key: `(tenant_id, repository_id, base_sha, head_sha, engine_version, policy_source_revision)`.

- [ ] **Step 1: Write failing state-machine tests**

Test every allowed transition and reject all others. Test concurrent creation, lease stealing after expiry, stale lease token, heartbeat, cancellation, retry count, backoff, poison job, duplicate completion, and publisher idempotency.

- [ ] **Step 2: Write failing quota tests**

Enforce per-tenant queued, concurrent, daily analysis, stored bytes, and GitHub request limits. Defaults are 100 queued, 5 concurrent readers, 5 concurrent publishers, 1,000 analyses/day, and 10 GiB stored artifacts. Quota exhaustion returns a tenant-scoped retryable status and never consumes another tenant's capacity.

- [ ] **Step 3: Implement transactional leasing**

Use `SELECT ... FOR UPDATE SKIP LOCKED`, tenant filter, random 256-bit lease tokens stored as SHA-256 digests, 2-minute leases with 30-second heartbeats, maximum 3 attempts, and bounded exponential retry delays of 30 seconds, 2 minutes, and 10 minutes. Permanent identity/integrity failures do not retry.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/jobs -v -race -count=5 && go test ./...`.

Commit: `feat: add durable tenant-scoped job leases`

## Task 6: Ephemeral source reader and offline analysis worker

**Files:**
- Create: `internal/hosted/worker/workspace.go`
- Create: `internal/hosted/worker/workspace_test.go`
- Create: `internal/hosted/worker/reader.go`
- Create: `internal/hosted/worker/reader_test.go`
- Create: `internal/hosted/worker/analyze.go`
- Create: `internal/hosted/worker/analyze_test.go`
- Create: `cmd/proofrail-worker/main.go`

**Interfaces:**
- Reader downloads exact base/head archives using read token and hands a local, read-only input set to the offline engine.
- Analysis child has no network and no GitHub credential in environment/filesystem.

- [ ] **Step 1: Write failing workspace lifecycle tests**

Assert a unique directory under an empty worker root, mode `0700`, no symlink/hardlink/device/FIFO escape on archive extraction, normalized path limits, content limits, immediate cleanup on success/failure/cancellation, zero shared cache, and cleanup sweeper for abandoned workspaces older than 15 minutes.

- [ ] **Step 2: Write failing immutable archive tests**

Fake GitHub archive responses and assert repository/install authorization before each request, exact SHA endpoint, 50 MiB compressed and 200 MiB expanded caps, 5,000-file cap, digest record, redirect host allow-list, and rejection when archive identity cannot be proven. Extract base policy/waivers only from the base archive.

- [ ] **Step 3: Write failing sandbox tests**

Launch the analysis child with a scrubbed allow-list environment, read-only input mount, writable bounded output directory, no token/private key, CPU/memory/process/file limits, 120-second timeout, and denied outbound network. Attempted socket/process/file escape must make the job incomplete and retain bounded diagnostics.

- [ ] **Step 4: Implement worker pipeline**

Reader and analyzer run as separate ECS tasks or containers with distinct roles. Reader writes only normalized bounded inputs and deletes its token before analysis. Analyzer invokes the promoted engine by immutable image digest and returns canonical JSON/SARIF; it cannot call GitHub or object storage directly.

- [ ] **Step 5: Verify and commit**

Run: `go test ./internal/hosted/worker -v -race && go test ./...`; run container integration with egress denied and record attempted-connect results.

Commit: `feat: isolate hosted analysis workspaces`

## Task 7: Tenant-bound encrypted artifact storage

**Files:**
- Create: `internal/hosted/store/object.go`
- Create: `internal/hosted/store/object_test.go`
- Create: `internal/hosted/store/s3.go`
- Create: `internal/hosted/store/s3_test.go`

**Interfaces:**
- Keys are generated internally as `tenants/<tenant-id>/runs/<job-id>/<artifact-kind>`; caller-supplied keys are forbidden.

- [ ] **Step 1: Write failing object-contract tests**

Test tenant prefix generation, traversal/control bytes, content type allow-list, 50 MiB object cap, SHA-256 verification on put/get, conditional create, immutable metadata, cross-tenant reads/deletes, partial upload cleanup, and context cancellation.

- [ ] **Step 2: Implement S3 adapter with exact dependency pins**

Pin AWS SDK core `v1.47.0`, config `v1.33.5`, and S3 `v1.113.1`. Require TLS, bucket allow-list, path-style disabled in production, SSE-KMS with the tenant's approved key context, bucket-owner enforced object ownership, blocked public access, versioning, and lifecycle deletion at 30 days. IAM limits each task role to its operation and tenant prefix supplied by job claims.

- [ ] **Step 3: Add integrity binding**

Persist object digest, byte count, engine commit, base/head/policy/waiver digests, and creation time in PostgreSQL in the same logical completion transaction. Publisher must supply the expected digest when fetching and reject any mismatch.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/store -run 'TestObject|TestS3' -v && go test ./...` plus an integration test against an isolated test bucket/account.

Commit: `feat: store tenant-bound canonical artifacts`

## Task 8: Separate idempotent check and SARIF publisher

**Files:**
- Create: `internal/hosted/publisher/publisher.go`
- Create: `internal/hosted/publisher/publisher_test.go`
- Create: `internal/hosted/publisher/checks.go`
- Create: `internal/hosted/publisher/checks_test.go`
- Create: `internal/hosted/publisher/sarif.go`
- Create: `internal/hosted/publisher/sarif_test.go`
- Create: `cmd/proofrail-publisher/main.go`

**Interfaces:**
- Consumes only canonical artifact + SARIF + bound identity; no source checkout.
- Check external ID is `proofrail:<tenant-id>:<job-id>` and is idempotently upserted.

- [ ] **Step 1: Write failing artifact verification tests**

Reject digest mismatch, wrong tenant/repository/base/head/engine/policy/waiver identity, invalid schema, missing analyzer ledger, oversized text, or canonical/SARIF decision mismatch before any GitHub call.

- [ ] **Step 2: Write failing publication tests**

Map terminal states exactly: pass/warn to successful neutral/success policy, require-review/block to failure/action-required as approved, incomplete to failure with bounded diagnostic. Test retry-safe check creation/update, duplicate delivery, rate limit, abuse limit, 404 installation removal, 422 SARIF rejection, and timeout.

- [ ] **Step 3: Implement separated publication**

Mint publisher-only token, reauthorize installation/repository, publish Check Run first, then SARIF if enabled. Store separate analysis and publication statuses. Publication failure retries independently and never changes the canonical decision.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/publisher -v -race -count=5 && go test ./...`.

Commit: `feat: publish hosted results with separate capability`

## Task 9: Audit, redacted observability, retention, and deletion

**Files:**
- Create: `internal/hosted/audit/event.go`
- Create: `internal/hosted/audit/event_test.go`
- Create: `internal/hosted/audit/logger.go`
- Create: `internal/hosted/audit/logger_test.go`
- Create: `internal/hosted/store/retention.go`
- Create: `internal/hosted/store/retention_test.go`
- Create: `internal/hosted/store/deletion.go`
- Create: `internal/hosted/store/deletion_test.go`

**Interfaces:**
- Audit events include tenant, actor kind/ID, action, resource type/ID, outcome, request/job/delivery correlation IDs, timestamp, and redacted metadata digest.

- [ ] **Step 1: Write failing log-safety tests**

Feed tokens, private keys, webhook secrets, source fragments, URLs with credentials, newline/ANSI injection, and hostile repository names through every structured log/audit path. Assert redaction, field length caps, UTF-8, no raw payload, and tenant correlation.

- [ ] **Step 2: Write failing retention/deletion tests**

Advance an injected clock and assert workspace zero-retention, diagnostics 7 days, canonical/audit 30 days, legal hold unavailable in private beta, installation uninstall schedules deletion, deletion finishes within 24 hours, S3 versions/delete markers removed, database tenant rows removed, and a non-sensitive tombstone records completion.

- [ ] **Step 3: Implement immutable audit sequence**

Use per-tenant monotonic sequence plus hash chain over canonical audit fields. Audit is evidence of application events, not a cryptographic proof of human identity. Export requires owner authorization and remains tenant-scoped.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/audit ./internal/hosted/store -run 'TestAudit|TestRetention|TestDeletion' -v && go test ./...`.

Commit: `feat: add hosted audit and deletion controls`

## Task 10: API/service entry points, health, rate limits, and kill switch

**Files:**
- Create: `cmd/proofrail-api/main.go`
- Create: `internal/hosted/server/server.go`
- Create: `internal/hosted/server/server_test.go`
- Create: `internal/hosted/server/config.go`
- Create: `internal/hosted/server/config_test.go`
- Create: `internal/hosted/server/health.go`
- Create: `internal/hosted/server/health_test.go`

**Interfaces:**
- Public routes: `POST /github/webhooks`, `GET /livez`, `GET /readyz`.
- Administrative kill switch is not an HTTP public route; it is a signed configuration value read from the deployment secret/config channel.

- [ ] **Step 1: Write failing configuration tests**

Reject unknown environment keys under the `PROOFRAIL_` prefix, missing database/KMS/bucket/app identifiers, plaintext private key, wildcard origin, debug mode, non-TLS public URL, invalid retention, excessive body/timeout values, and mixed production/test endpoints.

- [ ] **Step 2: Write failing server tests**

Test header/body/read/write/idle timeouts, maximum headers, no request-body logging, generic server banner, graceful shutdown, readiness dependency checks, liveness independence, per-IP and per-installation webhook rate limits, and kill-switch behavior that accepts/verifies events but creates no work and publishes a bounded maintenance response.

- [ ] **Step 3: Implement hardened server startup**

Use explicit `http.Server` timeouts, injected dependencies, structured redacted logger, panic boundary returning correlation ID, TLS terminated at the load balancer with authenticated private hop, and 30-second graceful shutdown. Refuse startup if migrations are ahead/behind or credentials are overbroad.

- [ ] **Step 4: Verify and commit**

Run: `go test ./internal/hosted/server -v -race && go test ./... && go vet ./...`.

Commit: `feat: expose hardened hosted service endpoints`

## Task 11: Reference AWS deployment and supply-chain controls

**Files:**
- Create: `Dockerfile.api`
- Create: `Dockerfile.worker`
- Create: `Dockerfile.publisher`
- Create: `deploy/opentofu/modules/{network,database,ecs,iam,objectstore,secrets}/*.tf`
- Create: `deploy/opentofu/environments/private-beta/*.tf`
- Create: `deploy/compose/compose.yml`
- Create: `deploy/tests/policy_test.go`
- Create: `.github/workflows/hosted-images.yml`

**Interfaces:**
- Three runtime images and four task roles: API, reader, analyzer, publisher. Analyzer role has no network credential or AWS/GitHub permission.

- [ ] **Step 1: Write failing infrastructure policy tests**

Parse OpenTofu plans and assert private subnets, no public database/S3, RDS encryption/backups/deletion protection, TLS enforcement, S3 public-block/versioning/lifecycle/KMS, secrets encryption/rotation, distinct IAM roles, no `*` actions/resources where resource scoping exists, ECS read-only root filesystems, non-root users, dropped Linux capabilities, CPU/memory limits, and per-service security groups/egress.

- [ ] **Step 2: Implement reproducible images**

Use a pinned Go 1.27.1 builder image by digest and `scratch` or distroless nonroot runtime by digest. Build with `CGO_ENABLED=0`, `-trimpath`, version/commit flags, no package manager, and no shell in runtime. Generate SBOM and provenance; sign image digests with keyless CI identity only after the release workflow security review.

- [ ] **Step 3: Implement network and IAM separation**

API: load balancer ingress, PostgreSQL egress only. Reader: GitHub HTTPS through controlled NAT/proxy, PostgreSQL, S3 put. Analyzer: no egress, ephemeral storage only. Publisher: GitHub HTTPS, PostgreSQL, S3 get. Migration task: database only with schema-owner secret, invoked manually through approved deployment workflow.

- [ ] **Step 4: Implement backup, rollback, and kill switch**

RDS point-in-time recovery at least 7 days, daily snapshots, S3 versioning, immutable image digests, blue/green ECS deployment, one-command desired-count zero for workers/publisher, and signed config kill switch. Rollback never migrates down destructively; database changes are expand/contract across releases.

- [ ] **Step 5: Verify and commit**

Run `tofu fmt -check`, `tofu validate`, plan-policy tests, container image scans, SBOM validation, and a disposable-environment deployment smoke test.

Commit: `build: define private beta hosted environment`

## Task 12: Cross-tenant, credential, webhook, egress, and recovery campaign

**Files:**
- Create: `testdata/hosted/tenants/`
- Create: `internal/hosted/security/crosstenant_test.go`
- Create: `internal/hosted/security/credentials_test.go`
- Create: `internal/hosted/security/webhook_fuzz_test.go`
- Create: `internal/hosted/security/recovery_test.go`
- Create: `docs/evidence/gate-3/tests/summary.json`

**Interfaces:**
- Produces machine-readable Gate 3 adversarial evidence with synthetic tenants only.

- [ ] **Step 1: Run systematic cross-tenant tests**

For database rows, object keys, job leases, logs, caches, tokens, identifiers, quotas, audit exports, check IDs, deletion, and error timing, attempt tenant A access to tenant B through every public/internal interface. Require zero disclosure and verify both application checks and database/storage policies.

- [ ] **Step 2: Run webhook and identifier fuzzing**

Fuzz signature headers, delivery IDs, event/action values, installation/repository IDs, JSON depth/size/types, Unicode, duplicate fields, archive metadata, object keys, and GitHub response bodies. Require bounded memory/time, no panic, no unauthorized job, and stable redacted errors.

- [ ] **Step 3: Exercise credential compromise**

Simulate leaked read token, publish token, webhook secret, database runtime credential, and KMS permission. Confirm each blast radius matches its capability; rotate/revoke; verify cached tokens expire; inspect audit; and record detection/containment time. No synthetic credential may be valid outside the disposable environment.

- [ ] **Step 4: Exercise recovery and rollback**

Restore RDS snapshot into isolation, verify artifact/database consistency, replay idempotent pending jobs, test region/service outage behavior, roll back one image version, activate/deactivate kill switch, and verify no duplicate check or cross-tenant result.

- [ ] **Step 5: Independent security review**

Review tenant scoping, RLS, S3/IAM, webhook verification, token capabilities, archive extraction, worker sandbox, egress, redaction, deletion, and deployment workflows. Resolve every blocking finding before invitations.

Commit: `test: record hosted security campaign`

## Task 13: Invited private beta and Gate 3 evidence

**Files:**
- Create: `docs/evidence/gate-3/{README.md,environment.json,commands.txt,limitations.md,promotion.md}`
- Create: `docs/evidence/gate-3/private-beta/metrics.json`
- Create: `docs/evidence/gate-3/private-beta/incidents.ndjson`
- Create: `docs/evidence/gate-3/private-beta/installations.json`

**Interfaces:**
- Evidence contains pseudonymous installation IDs and aggregate metrics; no private source, tenant names, or secrets.

- [ ] **Step 1: Invite and authorize five installations**

Record explicit maintainer authorization, repository IDs, enabled features, retention notice, support contact, uninstall/deletion procedure, and shadow-only status. Do not enable broad public installation.

- [ ] **Step 2: Operate for at least 30 calendar days**

Collect at least 500 analyses. Measure end-to-end completion, queue delay, analysis duration, publication status, false blocks, quota events, retries, deletion SLA, and incident response. Require 99.5% service completion and zero confirmed cross-tenant leak.

- [ ] **Step 3: Exercise incident targets with named responders**

Run tabletop or live-safe exercises for decision integrity, credential exposure, cross-tenant isolation, availability/false blocking, and presentation defect using the targets in `docs/validation-gates.md`. Record detection, containment, communication, recovery, and follow-up.

- [ ] **Step 4: Verify retention and uninstall**

Uninstall one synthetic/test installation, confirm work stops immediately, tokens fail, deletion completes within 24 hours, artifacts/database/log views no longer expose tenant data, and the non-sensitive deletion tombstone remains.

- [ ] **Step 5: Request Gate 3 promotion**

Map every Gate 3 criterion to evidence, attach release/image digests, infrastructure plan hash, independent verdict, known limitations, rollback target, and kill-switch exercise. Owner approval closes Gate 3 private beta only; it does not authorize public production or compliance claims.

Commit: `test: record gate 3 private beta evidence`

## Gate 3 completion checkpoint

Gate 3 is complete only after the 30-day window, 500 analyses, five installations, isolation evidence, completion target, security review, rollback/deletion/incident exercises, and explicit owner approval. The next stage is Gate 4 production readiness and must be separately planned and approved.
