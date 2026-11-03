# NullPrompt Project Charter

## Purpose

NullPrompt is a research prototype for protecting LLM-assisted Security Operations Center (SOC) workflows from indirect prompt injection embedded in untrusted security telemetry.

The system will preserve source evidence, track its provenance, apply deterministic policy controls to LLM context and downstream actions, and use contextual detection to provide additional risk evidence. The detector may inform policy, but it cannot grant permissions or authorize actions.

## Problem statement

SOC analysts increasingly use LLMs to summarize, correlate, or act on security telemetry. Telemetry may contain attacker-controlled strings, including text that attempts to redirect model behavior. If those strings are treated as trusted instructions, they may influence model responses, tool use, or response actions.

Prompt formatting alone cannot establish a security boundary. The system needs application-enforced controls over which data enters model context, which tools are available, and which actions can proceed. It must also preserve the original evidence and make its transformations and decisions reviewable.

## Objectives

1. Preserve original telemetry as immutable evidence and verify its integrity.
2. Maintain stable record identifiers, provenance links, and transformation history.
3. Enforce deterministic policy over LLM context access, tool permissions, and downstream actions.
4. Quarantine suspicious content from AI processing while retaining it as evidence.
5. Use contextual adversarial detection as policy evidence, never as an authorization mechanism.
6. Validate model outputs and require human approval for designated sensitive actions.
7. Evaluate the controls using repeatable benign and adversarial scenarios, including detector false negatives.
8. Document a small prototype and its limitations in a way that supports reproducible dissertation evaluation.

## Scope

### MVP requirements

- Ingest prepared log files containing traditional Linux `auth.log` records and Apache access/error records.
- Preserve the exact retained original bytes and verify their integrity using SHA-256 hashes. Document record-boundary handling.
- Assign stable record identifiers and record transformations and provenance links.
- Parse supported records into a normalized event format without losing the link to original evidence.
- Detect suspicious instruction-like content and emit evidence with source references.
- Quarantine suspicious content from AI context according to deterministic policy.
- Apply deterministic policy as the final authority for:
  - Context inclusion and exclusion.
  - Model and tool permissions.
  - Downstream action authorization.
- Validate model output against a constrained schema and policy.
- Require explicit human approval for a simulated IP-block proposal as the sensitive action.
- Produce an audit trail that links source evidence to transformations, detections, policy decisions, model interactions, validation, and approval.
- Provide a local, repeatable evaluation harness and a small end-to-end demonstration.
- Use a stub model for automated tests. Use synthetic or sanitized data for model-backed experiments.
- Begin with a pilot evaluation dataset, validate its labels, coverage, and suitability, then finalize the main experiment sample size before running the main evaluation.
- Compare four configurations:
  - **A. Direct LLM baseline:** telemetry is sent to the LLM without NullPrompt enforcement or contextual detection.
  - **B. Policy-only enforcement:** deterministic policy and provenance controls, without contextual detection.
  - **C. Detection-only:** contextual detection is observed without enforcement using its output to gate context, tools, or actions. This is an isolated experimental configuration with no real tool or action execution.
  - **D. Combined:** contextual detection supplies evidence and deterministic policy enforces context, tool, and action boundaries.
- Include detector false-negative cases and verify that combined deterministic enforcement still prevents prohibited context access and unauthorized actions.

### Future extensions

- Additional telemetry sources and live SOC/SIEM integrations.
- Retrieval, long-term memory, cross-event correlation, or streaming processing.
- Multiple model providers or local model deployment.
- Production-grade web interface, identity management, and multi-user roles.
- External tamper-evident audit storage, signed records, or advanced provenance graphs.
- Automated response actions beyond a controlled demonstration.
- Broader attack coverage and larger-scale operational evaluations.

## Non-goals

- Production deployment or direct connection to a live SOC.
- General protection for every LLM application, telemetry type, or attack technique.
- Autonomous execution of sensitive response actions.
- Treating XML delimiters, prompt wording, or other formatting conventions as security controls.
- Treating detector confidence as authorization or proof of safety.
- Claiming research novelty before a literature review establishes the relevant prior art.
- Building a microservice platform or introducing infrastructure that is not required by the research questions.

## Threat model summary

### Assets to protect

- Integrity and traceability of original telemetry evidence.
- The contents of the LLM context.
- Tool permissions and downstream response actions.
- Auditability and reproducibility of system decisions.

### Adversary and capabilities

Assume an attacker can cause attacker-controlled text to appear in one or more supported log sources. The text may contain instructions aimed at an LLM, misleading context, or content intended to induce an unsafe recommendation. It may be malformed or crafted to evade the contextual detector.

The attacker does not control the application policy, the trusted application code, or the human approval step. Compromise of the host, model provider, or policy authoring process is outside the initial MVP threat model.

### Security principles

- Treat telemetry and model output as untrusted data.
- Preserve original evidence; never silently delete or overwrite suspicious content.
- Quarantine suspicious content from AI processing according to policy.
- Enforce permissions in application code at every context, tool, and action boundary.
- Require deterministic policy approval for actions; require human approval for designated sensitive actions.
- Keep detection as fallible evidence. Test false negatives explicitly.

## Research questions

1. How reliably can a provenance-aware pipeline preserve and trace Linux authentication and Apache telemetry through parsing and transformation?
2. How do policy-only, detection-only, and combined configurations compare with direct LLM processing in containing indirect prompt injection in the selected telemetry?
3. In detector false-negative scenarios, does deterministic policy enforcement still prevent prohibited context access and unauthorized actions?
4. What security and operational trade-offs arise among attack containment, detector performance, false positives, latency, and human review burden?
5. Can audit records support reconstruction of the evidence, context, and decisions for each evaluated scenario?

## Success criteria

The MVP is successful if it can demonstrate and measure the following:

- Original evidence is retained, has a stable identifier and SHA-256 hash over its exact retained bytes, and can be integrity-verified.
- Record-boundary handling is documented, and transformations and derived records link back to original evidence.
- Quarantined content is retained but excluded from AI context when policy requires exclusion.
- All paths into model context, tool use, and downstream actions pass through deterministic enforcement.
- Detector output or confidence alone cannot authorize privileged actions.
- Sensitive simulated IP-block proposals cannot proceed without policy authorization and the required human approval.
- False-negative scenarios show whether enforcement still blocks prohibited access and actions.
- The four experimental configurations produce reproducible, comparable results on a documented scenario set. Detection-only runs have no real tool or action execution.
- The pilot dataset is validated before the main experiment sample size is finalized and the main evaluation is run.
- The dissertation reports attack containment, detection outcomes, false positives and negatives, latency, review counts, and limitations.
- Project claims are bounded by the implemented sources, scenarios, and evaluation.

## 12-week constraints

The project is limited to a student dissertation schedule. The MVP should use a local modular application, two log families, a bounded scenario set, and a small demonstration. Research questions, threat model, pilot dataset validation, main experiment sample size, and metrics should be fixed early enough to allow implementation, comparative evaluation, analysis, and dissertation writing. Additional sources, production integrations, or infrastructure should not displace the core evaluation.
