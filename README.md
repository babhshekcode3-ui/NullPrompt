# NullPrompt

NullPrompt is a local research prototype for protecting LLM-assisted Security Operations Center (SOC) workflows from indirect prompt injection embedded in untrusted security telemetry.

The project focuses on preserving source evidence, tracking provenance, enforcing deterministic policy over model context and downstream actions, and evaluating contextual detection as fallible risk evidence. Detection does not authorize actions. The prototype is scoped to a dissertation MVP and is not intended for production SOC deployment.

## Project status

The repository contains the approved project charter and architecture baseline, initial project structure and packaging configuration, byte-preserving evidence ingestion, SHA-256 evidence storage and first-pass parsers for the approved log families. Unsupported or malformed records remain linked to their evidence as explicit parse failures.

## Requirements

- Python 3.12
- Pydantic 2
- pytest 9 for development and tests

## Local setup

Create and activate a virtual environment, then install the project with its development tools:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run the test suite with:

```powershell
python -m pytest
```

## Repository layout

- `src/nullprompt/` contains the future modular application package.
- `tests/` is divided into unit, integration, and security tests, with fixtures kept separately.
- `data/` separates raw, processed, and quarantined evidence.
- `experiments/` separates configurations, datasets, and results.
- `docs/` holds research, architecture, and security documentation.
- `scripts/` is reserved for project support scripts.
- `.github/workflows/` is reserved for automation configuration.
- `PROJECT_CHARTER.md` and `ARCHITECTURE_DECISIONS.md` define the approved scope and baseline.

Raw, processed, and quarantined data, experiment datasets and results, local environments, credentials, secrets, databases, caches, and generated build artifacts are excluded from Git by default. Use synthetic or sanitized data for experiments; do not place operational or sensitive evidence in the repository.

## Security and evidence handling

Treat telemetry and model output as untrusted. Preserve original evidence separately from derived records, record provenance for transformations, and ensure deterministic application policy mediates context access, tool permissions, and downstream actions. Keep suspicious evidence available for review while excluding it from model processing when policy requires quarantine. Never use model output or detector confidence alone to authorize an action.

See `PROJECT_CHARTER.md` for scope and `ARCHITECTURE_DECISIONS.md` for the approved architectural baseline.
