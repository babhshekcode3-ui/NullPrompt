# NullPrompt Architecture Decisions

## Status

Approved baseline for the 12-week MVP. Implementation remains subject to separate approval.

## Selected technology stack

- **Python 3.12:** implementation language for the local prototype, parsers, evaluation harness, and experiment scripts.
- **pytest:** unit, integration, and scenario tests.
- **Pydantic:** typed schemas for normalized events, provenance references, policy decisions, and model outputs.
- **SQLite:** local structured storage for event metadata, provenance links, policy decisions, approvals, and audit events. Original evidence is retained separately as immutable files.
- **Structured JSON audit records:** readable, locally inspectable event records with stable field names and references.
- **CLI-first interface:** keeps the MVP small and supports repeatable experiments. A lightweight local UI is optional if time allows.
- **Model client interface plus stub:** isolates provider-specific calls and enables deterministic testing. Use a stub for core tests; use one selected model configuration for experiments when data-handling requirements permit.
- **Git:** versions application code, policy configuration, scenario definitions, and experiment settings. Real or sensitive operational logs must not be committed.

No message broker, container orchestration, service mesh, or separately operated database is required for the MVP.

## Architecture decisions

### AD-1: Use a modular monolith

**Decision:** Implement the MVP as one local application with explicit module boundaries.

**Rationale:** The project needs clear separations for research, testing, and future changes, but not the operational complexity of microservices. A modular monolith is suitable for a 12-week student project and makes end-to-end enforcement easier to inspect.

### AD-2: Limit MVP ingestion to two log families

**Decision:** Initially support prepared files containing traditional Linux `auth.log` and Apache access/error logs.

**Rationale:** This bounds parsing and evaluation while covering security-relevant and potentially attacker-influenced text. New sources require explicit scope and provenance work.

### AD-3: Preserve evidence independently of derived data

**Decision:** Store original evidence separately from parsed and transformed records. Hash the exact retained original bytes. Do not overwrite originals during parsing, normalization, redaction, quarantine, or replay.

**Rationale:** Security analysis requires the ability to recover and verify the source evidence. Derived data can change as parsers and policies evolve.

### AD-4: Treat application policy as the security boundary

**Decision:** Deterministic application policy is the final authority for context inclusion, tool permissions, and downstream actions.

**Rationale:** Prompt formatting, delimiters, and model instructions do not provide enforceable access control. All relevant paths must be mediated by application code. Missing policy inputs or provenance should fail closed for protected operations.

### AD-5: Keep contextual detection non-authoritative

**Decision:** The detector produces evidence and a risk signal. It cannot independently authorize privileged context access, tools, or actions.

**Rationale:** Detection can produce false positives and false negatives. The evaluation must include false-negative cases to test whether policy enforcement still contains the attack.

### AD-6: Quarantine without deletion

**Decision:** Suspicious evidence remains in the original record store and is marked as quarantined for AI processing. Policy may permit a constrained safe representation, but the original remains available for review.

**Rationale:** Quarantine limits exposure while preserving forensic value. Any redaction, escaping, or summarization is a recorded transformation, not a replacement for the original.

### AD-7: Validate model output before use

**Decision:** Treat model output as untrusted. Validate it against a constrained schema and policy before displaying it as a recommendation, invoking a tool, or proposing an action.

**Rationale:** Even a policy-approved prompt can produce an invalid or unsafe response. Schema validation is necessary for controlled handling but is not itself authorization.

### AD-8: Require human approval for sensitive actions

**Decision:** A simulated IP-block proposal is the MVP sensitive action. It requires a policy decision and explicit human approval bound to the specific proposal and its evidence. No real network block is executed.

**Rationale:** The MVP should demonstrate controlled action handling without autonomous sensitive response. Approval does not bypass policy.

### AD-9: Use four separate experimental configurations

**Decision:** Evaluate the following configurations against the same validated scenario set:

1. Direct LLM baseline.
2. Policy-only enforcement.
3. Detection-only without enforcement.
4. Combined contextual detection and deterministic enforcement.

Start with a pilot evaluation dataset. Validate its labels, source coverage, and suitability, then finalize the main experiment sample size before the main evaluation. Detection-only is an isolated experimental condition; disable all real tool and action execution in that configuration.

**Rationale:** These configurations help distinguish the effects of policy enforcement and detection. Record model and prompt settings to make comparisons interpretable. Pilot validation reduces the risk of basing the main study on unsuitable or inconsistently labeled cases.

### AD-10: Keep audit records linked and reconstructable

**Decision:** Emit structured audit events for ingestion, transformations, detections, policy decisions, model interactions, output validation, and approval. Link records by stable identifiers.

**Rationale:** The dissertation needs verifiable experiment outcomes and the ability to reconstruct why each case was handled as it was. Avoid unnecessary duplication of raw content in audit records.

## Module responsibilities and boundaries

| Module | Responsibility, inputs, and outputs | Trust boundary | Security requirements | Testing |
|---|---|---|---|---|
| **Ingestion** *(MVP)* | Reads prepared files containing supported logs; emits original record references and ingestion metadata. | All source content is untrusted. | Preserve exact retained evidence; handle malformed lines explicitly; do not interpret text as instructions. | Format, encoding, boundary, malformed-input, and duplicate-ingestion tests. |
| **Evidence store and provenance** *(MVP)* | Stores originals and tracks stable identifiers, hashes, source location, and transformations; emits verifiable references. | Raw records are evidence; metadata is application-generated but must be checked for consistency. | Prevent silent overwrite; verify hashes; preserve lineage through derived records. | Hash verification, tampering detection, stable ID, lineage, and transformation-history tests. |
| **Parsing and normalization** *(MVP)* | Converts supported records to typed normalized events and links them to originals. | Parsed fields remain untrusted. | Preserve source linkage and parse errors; do not upgrade trust based on successful parsing. | Parser unit tests, malformed-data tests, and prompt-like payload preservation tests. |
| **Contextual detector** *(MVP, bounded)* | Scores or labels suspicious content and returns evidence references. | Detector output is fallible evidence. | No authorization side effects; output must be validated and traceable. | Benign/adversarial scenarios, false-positive and false-negative cases, reproducibility checks. |
| **Policy engine** *(MVP; final authority)* | Decides context inclusion, quarantine, tool permissions, and action eligibility using policy and evidence. | Policy execution is the authorization boundary. | Deny by default on missing required facts; mediate every protected path; do not treat detector confidence as permission. | Rule tests, deny-by-default tests, and integration tests proving no unmediated path exists. |
| **Context builder and model gateway** *(MVP)* | Builds context only from policy-approved records and invokes the configured model or stub. | Model input and output are untrusted; telemetry remains data. | Include only approved content; preserve source references; keep model access and tools constrained by policy. | Inspect built contexts; assert quarantined material is absent; test gateway permissions and provenance links. |
| **Output validator and action mediator** *(MVP)* | Validates model responses and routes permitted proposals through policy and approval. | Model output is untrusted. | Reject invalid or unauthorized outputs; never execute solely on model recommendation. | Invalid-schema, prohibited-action, false-negative, and unauthorized-action tests. |
| **Human approval** *(MVP)* | Captures approve/reject decisions for the simulated IP-block proposal. | Human decision applies only to a specific proposal and evidence. | Bind approval to proposal identity; require policy eligibility first; record decision; never execute a real IP block. | No-approval, rejection, changed-proposal, and approval-replay tests. |
| **Audit log** *(MVP)* | Records event references and decisions across modules. | Audit data may be sensitive and must not become a path to alter policy. | Record enough to reconstruct decisions; protect integrity; audit failure must not imply authorization. | Event coverage, linkage, missing-event, and reconstruction tests. |
| **Evaluation harness and demo** *(MVP)* | Runs versioned scenarios in the four configurations and reports outcomes. | Scenario content is adversarial and must not cause real actions. | Isolate tests; use stubs or safe simulated actions; record configurations and results. | Pilot validation, repeat-run consistency, expected decisions, metric generation, and false-negative containment tests. |

## Evidence integrity strategy

Each original record receives:

- A **stable record identifier** that remains constant across processing and evaluation.
- A **SHA-256 digest** computed over the exact retained original bytes.
- Source metadata such as source type, file identity, and record offset or sequence where available.
- A reference to the original retained evidence.

The MVP initially reads prepared files. Record-boundary handling must be documented for each supported input. The initial assumption is one physical log line per record, with the retained byte slice defined before decoding or normalization. Line endings are included in the exact byte slice if they are part of the retained record. Apache access/error records are handled as individual physical lines. Traditional `auth.log` records are also treated as individual physical lines; multiline or continuation formats are outside the initial supported format and must be rejected or explicitly flagged rather than silently joined. If representative prepared data requires another boundary rule, document it before main evaluation and use it consistently.

For every transformation, record a transformation event containing at least:

- Input record identifier(s) and hash reference(s).
- Transformation name and version.
- Output record identifier and hash, where the output is persisted.
- Timestamp and relevant parser or configuration version.
- Links to resulting detection, policy, or context decisions as applicable.

Integrity verification recomputes the SHA-256 digest from retained original evidence and compares it with the recorded digest. A mismatch is an integrity failure and must be surfaced and audited; it must not be silently repaired by replacing the recorded value. Hashes support change detection, while storage access controls and backups are still needed to protect availability and the integrity of the hash records themselves.

## Enforcement model

The application must mediate all protected operations:

1. **Context access:** The context builder requests an explicit policy decision for every record or field it would include. Quarantined material is excluded unless a specific policy permits a safe derivative.
2. **Tool access:** The model gateway exposes only tools granted by policy for the current task. The model cannot expand its own tool permissions.
3. **Downstream actions:** A proposed action is schema-validated, checked by deterministic policy, and routed to human approval when designated sensitive. The MVP action is a simulated IP-block proposal only; no real block is performed.
4. **Detector interaction:** Detector output is evidence supplied to policy. Detector confidence alone never grants access or permission.
5. **Detection-only isolation:** This experimental configuration cannot invoke tools or execute actions. Its output is observed and recorded for comparison only.
6. **Failure handling:** Missing, invalid, or inconsistent provenance or policy inputs result in denial or quarantine for protected operations.
7. **Audit:** Each decision records the relevant evidence references, policy version, detector evidence if present, and resulting disposition.

XML delimiters, prompt formatting, and system prompt wording may help model behavior but are not enforcement controls and are not counted as security guarantees.

## Rationale and MVP/future boundary

The MVP prioritizes evidence integrity, policy enforcement, bounded detection, output validation, auditability, and a measurable experiment. The pilot dataset is validated before finalizing the main evaluation sample size. Future extensions should be added only when the initial implementation demonstrates the end-to-end security properties and there is enough time to evaluate them.

Future extensions include additional sources, live SOC integration, advanced provenance storage, multiple production model providers, retrieval or long-term memory, a full dashboard, multi-user authorization, and automated response actions.
