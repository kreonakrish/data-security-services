# Data security platform — service specification
### Home lending domain · JPMorgan Chase

---

## How to read this document

This document is structured top-down. The first half builds a mental model — what the jargon means, why each technique exists, and how they relate to each other. The second half translates that model into a precise implementation specification. A reader who understands the first half will find every decision in the second half obvious rather than arbitrary.

Any LLM generating code from this spec must read both halves. Do not skip to the service contracts. Do not improvise decisions not stated here — instead flag the gap.

---

## Part 1 — The mental model

### What is data protection and why does it need many techniques?

Data protection is the practice of making sensitive data useless to anyone who should not have it, while keeping it useful to those who should. The tension between "useless to attackers" and "useful to the system" is why so many techniques exist. Each one occupies a different position on that spectrum.

The field is full of jargon — masking, encryption, tokenization, hashing, pseudonymization — that is used loosely and often interchangeably in conversation. For building software, the distinctions are precise and consequential. The wrong choice for a field breaks either security or functionality.

The single most useful question to ask about any technique is: **can the original value be recovered, and if so, by whom?**

---

### The technique map — one table to orient everything

| Technique | Reversible? | Requires a key/secret? | Output looks like input? | Primary use |
|---|---|---|---|---|
| **Masking** | No | No | Partially | Hiding values for display or dev access |
| **Hashing** | No | No (but salted) | No — fixed-length digest | Surrogate keys, deduplication, pseudonymization |
| **Encryption (AES-GCM)** | Yes — with key | Yes | No — unreadable ciphertext | Storing sensitive data at rest or in transit |
| **Encryption (FPE / FF3-1)** | Yes — with key | Yes | Yes — same format as plaintext | Fields that participate in database joins |
| **Tokenization** | Yes — with vault | No key, but vault access | No — random surrogate | High-value identifiers (SSN, account numbers) |
| **Synthetic generation** | N/A — no real data | No | Yes — realistic fake data | UAT, ML training, vendor handoffs |

Read this table before anything else. Every service in this platform corresponds to one column or a combination of columns in this table.

---

### Technique-by-technique explanation

#### Masking

Masking replaces part or all of a real value with a placeholder. It is **not reversible** and requires **no key**. This makes it operationally simple — there is nothing to protect except the policy itself.

The value `123-45-6789` becomes `XXX-XX-6789`. The value `Jane Doe` becomes `XXXX XXX`. The loan amount `$450,000` becomes `$447,230` (noise-injected).

Masking is the right technique when:
- The downstream consumer needs to know a value exists and roughly what shape it is, but not the actual value.
- The field is for display or debugging, not for joins or lookups.
- Irreversibility is acceptable — no production system will ever need to recover the original.

Masking is the **wrong** technique when a field participates in joins across tables. Masking SSN breaks any query that joins on SSN across two datasets. For those cases, use tokenization or format-preserving encryption.

Sub-techniques within masking:

- **Character masking** — replace characters with a fixed pattern (`XXX-XX-{last4}`)
- **Nullification** — replace with NULL entirely
- **Shuffling** — swap values across rows within a batch (preserves distribution, destroys linkage)
- **Noise injection** — add a random delta (±N%) to a numeric field (preserves statistical shape)
- **Generalization** — reduce precision (date of birth → birth year; full ZIP → 3-digit prefix)

#### Hashing

Hashing runs a value through a one-way mathematical function to produce a fixed-length digest. It is **not reversible** and requires no key (though a **salt** is mandatory in practice to prevent precomputed lookup attacks).

The value `123-45-6789` + salt `home-lending-2024` always produces the same digest: `a3f9b2c1...`. The same input always produces the same output — this determinism is the point.

Hashing is the right technique when:
- You need a consistent surrogate key for a real value that you can use across environments (UAT, dev) without revealing the real value.
- You need to deduplicate records across datasets without seeing the actual values.
- You want to confirm that two records refer to the same person without storing the person's identifiers.

Hashing is the **wrong** technique when the downstream system ever needs to recover the original value. Hashes are one-way by definition. If recovery is needed, use tokenization or encryption.

#### Encryption — AES-GCM

Standard symmetric encryption. A key encrypts plaintext into unreadable ciphertext; the same key decrypts ciphertext back into plaintext. **Reversible with the key. Requires a key.**

The output looks nothing like the input — it is a block of random-looking bytes (usually base64-encoded for transport). This means **AES-GCM ciphertext cannot be used as a join key** in a database. You cannot write `WHERE encrypted_ssn = encrypt('123-45-6789')` and have it work across databases unless both sides encrypt with the same key and nonce, which is dangerous.

AES-GCM is the right technique when:
- A field must be stored encrypted at rest and only decrypted when needed by an authorised system.
- The field does not participate in joins.
- Examples: stored email addresses, phone numbers, full addresses, document content.

Key management is the hard part. Keys must never live in application code, config files, or environment variables. They must be managed by a key management service (AWS KMS or HashiCorp Vault) and rotated on a schedule.

#### Encryption — Format-Preserving (FPE / FF3-1)

A specialised form of encryption where the ciphertext has the same format as the plaintext. A 9-digit SSN encrypts to a 9-digit ciphertext. A 16-digit card number encrypts to a 16-digit ciphertext. **Reversible with the key. Requires a key.**

The critical property is that **FPE output can be used as a join key** across tables, because the shape and length are preserved. This is the only technique that gives you both encryption (reversibility with a key) and join compatibility.

FPE is the right technique when:
- A field is sensitive enough to require key-based reversible protection.
- The field participates in joins across tables or datasets.
- Examples: SSN joining borrower to loan, loan number joining origination to servicing, account ID joining across systems.

FPE is the **wrong** technique for free-text fields (names, addresses) — those have no fixed format to preserve.

#### Tokenization

Tokenization replaces a real value with a randomly generated surrogate (a token) stored in a separate secure vault. The vault holds the mapping. **Reversible with vault access — no cryptographic key needed.** 

The value `123-45-6789` gets a token `TKN-a3f9b2c1-...`. That token is stored everywhere the SSN used to be. The vault privately maps `TKN-a3f9b2c1-...` back to `123-45-6789`. Only systems with vault access can detokenize.

Tokenization is the right technique when:
- The field is extremely high-value (SSN, account numbers, card numbers).
- The token needs to be used as a stable identifier across systems — the same real value always maps to the same token within a namespace.
- You want to completely decouple the data from the system that processes it — even a full database breach reveals only tokens, not real values.
- PCI-DSS or similar compliance mandates it for card data.

Tokenization is the **wrong** technique for high-volume, low-sensitivity fields — the vault becomes a bottleneck. It is also the wrong choice for fields that don't need to be looked up individually (bulk analytical fields).

#### Synthetic data generation

Synthetic data generation creates entirely new, realistic-looking records that were never real. **There is no original value to recover — no real data was used in the output.** This makes it the safest possible technique for downstream environments.

Three approaches exist, ordered by realism:

- **Rule-based (Faker)** — generates values from domain rules and a fake-data library. Fast. Fully safe. Realistic enough for basic functional testing. A loan amount is a random number between $50k and $3M with a matching LTV and property value.
- **Statistical sampling** — extracts only aggregate statistics from production (means, standard deviations, percentiles, correlations) and generates synthetic rows that match those distributions. No row-level production data ever leaves. Preserves the statistical shape of the data.
- **ML-based (CTGAN)** — trains a generative model on sanitised production data to learn complex joint distributions. The most realistic output. The most expensive to run. Generates data that reflects edge cases and correlations a rules engine would miss.
- **Hybrid** — keeps real financial structure (loan amount, rate, DTI, credit score) from production but replaces all PII with synthetic values. The best approach for UAT regression testing because real edge cases from production are preserved without any data exposure.

#### Why generation alone is not enough — the four integrity layers

Generating rows that look realistic is not the same as generating a dataset that behaves like production. A business analyst running a query like *"what is our current foreclosure rate by product type?"* on a synthetic dataset will get a meaningful answer only if the dataset was built with the same portfolio-level characteristics as production. Without that, the query returns a number that bears no relationship to any real business scenario — and UAT sign-off on that query is worthless.

This is the problem the four integrity layers solve. They operate on top of whichever generation mode is chosen (rule-based, statistical, CTGAN, or hybrid) and constrain the output so it is not just row-level plausible but dataset-level coherent.

**Layer 1 — Business Rules Integrity**

Business rules integrity ensures the generated dataset reflects real-world portfolio metrics and macroeconomic conditions. These are aggregate-level constraints that apply across the entire generated population, not just to individual rows.

Examples in the home lending domain:
- Foreclosure rate across all generated loans: 1.2% (matches current portfolio)
- Employment rate of borrowers at origination: 96% (4% unemployed)
- FHA loan share: 18% of total originations
- Refinance vs purchase split: 35% / 65%
- Average days-to-close: 42 days
- 90-day delinquency rate: 3.8%
- ARM loan share: 12% of originations
- Percentage of loans with co-borrower: 44%

These rates are not enforced row-by-row — they are enforced by controlling how many rows of each type are generated and then shuffled into the population. If 50,000 loans are requested and the foreclosure rate target is 1.2%, exactly 600 loans must be generated in the `foreclosure` status, with the remaining 49,400 distributed across active, paid-off, and other statuses in their correct proportions.

**Layer 2 — Relationship Integrity Across Tables and Datasets**

Relationship integrity ensures that values are consistent across multiple generated tables or datasets. A single row can look internally valid but break the moment it is joined to another table.

Examples:
- A borrower marked as `employment_status = unemployed` must have a `dti` that reflects absence of earned income — not the DTI of a fully employed borrower.
- A loan in `foreclosure` status must have a delinquency history table showing at least 90 days of missed payments before the foreclosure date.
- A borrower with `credit_score < 580` must not have a conventional loan product — only FHA or subprime products are valid for that score range.
- A property in state `FL` with flood zone `AE` must have a flood insurance premium in the escrow table.
- A loan with `loan_purpose = refinance` must have a prior loan record for the same property in the origination history.
- An MSR record must reference a loan that exists in the origination table and has a `funded` status.

These constraints are expressed as cross-table rules: if field A on table X has value V, then field B on table Y must satisfy condition C. They cannot be satisfied by generating each table independently — the generation must be orchestrated so parent records are generated first and child records are derived from them.

**Layer 3 — Valid Values Integrity**

Valid values integrity ensures every generated field contains a value that is legally, regulatorily, or domain-valid — not just numerically in range. This is stricter than the field-level domain constraints in the rule-based mode.

Examples:
- `loan_purpose` must be one of the HMDA-defined enumeration: `home_purchase`, `refinancing`, `cash_out_refinancing`, `home_improvement`, `other`
- `property_type` must be one of: `single_family`, `condo`, `co_op`, `manufactured_housing`, `multifamily_2_4`, `multifamily_5_plus`
- `lien_status` must be consistent with loan type — a HELOC cannot have `first_lien` status if a primary mortgage exists on the same property
- ABA routing numbers must pass the standard checksum algorithm — not just be a 9-digit number
- State codes must be valid USPS two-letter abbreviations
- ZIP codes must exist in the USPS database and must be consistent with the state field
- `rate_type` of `arm` must have a populated `initial_fixed_period_months` and a valid `rate_cap` structure
- NMLS IDs for loan officers must be in the correct numeric format and plausible range

Valid values integrity is implemented as a validation pass over the generated output before it is written to the output destination. It is not a generation concern — it is a post-generation quality gate.

**Layer 4 — Referential Integrity**

Referential integrity ensures that primary keys and foreign keys are consistent across all generated tables — exactly as they would be enforced by database constraints in production. Without this, joins in UAT queries silently return no rows or wrong row counts, making the synthetic dataset useless for testing SQL, Spark jobs, or dbt models.

Examples:
- Every `loan_id` in the `servicing` table must exist as a primary key in the `origination` table
- Every `borrower_id` in the `loan` table must exist in the `borrower` table
- Every `property_id` in the `loan` table must exist in the `property` table
- Every `servicer_id` in the `loan` table must exist in the `servicer` table
- A `payment` record's `loan_id` must exist and the `payment_date` must be after the loan's `funded_date`
- An `escrow` record's `loan_id` must match a loan with `escrow_required = true`
- Deleted or paid-off loans must not have open `delinquency` records

Referential integrity is enforced through generation order: parent tables are generated first, primary keys are registered in a generation context, and child tables draw foreign keys exclusively from that context. No foreign key is fabricated independently.

---

#### The relationship between the four layers

The layers are applied in order, not independently. A row passes through all four before it is valid:

```
Raw generation (Faker / statistical / CTGAN / hybrid)
        │
        ▼  Layer 1 — Business Rules Integrity
        │  Control population-level rates and distributions
        │
        ▼  Layer 2 — Relationship Integrity
        │  Derive cross-table fields from parent record values
        │
        ▼  Layer 3 — Valid Values Integrity
        │  Validate enumerations, checksums, geographic consistency
        │
        ▼  Layer 4 — Referential Integrity
        │  Confirm all FK references resolve to generated PK records
        │
        ▼
   Output — dataset that behaves like production
```

A dataset that passes all four layers will correctly answer business queries that production would answer correctly. A dataset that passes only row-level generation will answer row-level queries correctly and fail on any query involving aggregation, joins, or business logic.

---

### Why one technique is never enough

A single borrower record in the home lending domain contains fields that belong to four different categories simultaneously:

| Field | Technique | Reason |
|---|---|---|
| SSN | Tokenization | Join key across systems; high regulatory sensitivity |
| Loan number | FPE (FF3-1) | Join key; numeric format must be preserved |
| Borrower name | Character masking | Display only; no join; irreversibility fine |
| Date of birth | Generalization | Partial visibility acceptable; year is useful for segmentation |
| Email | Nullification | Not needed in lower environments at all |
| Loan amount | Noise injection | Statistical shape preserved; financial modelling still valid |
| Credit score | Noise injection | Distribution preserved; scoring models still valid |
| Property address | AES-GCM | Must be recoverable for title/appraisal workflows |

A single service with a `technique` argument can handle this record. But when that single service also handles CTGAN model training (which takes 20 minutes and 16GB of RAM), a slow training job will starve the masking requests that need sub-100ms latency. This is why the platform decomposes into isolated services — each technique has a completely different operational profile.

---

### The isolation principle

Each service in this platform corresponds to one row from the technique map. The isolation boundary is drawn not by domain (not "borrower service" or "loan service") but by **operational profile**:

- How long does a request take? (milliseconds vs minutes)
- Does it hold secrets? (keys, vault connections)
- How does it scale? (CPU, memory, I/O)
- What fails independently? (KMS outage should not affect masking)

This is why isolation is the architectural principle here. A KMS outage should not take down masking. A CTGAN job running for 20 minutes should not queue up character-masking requests. An encryption service compromise should be contained — it should not expose the token vault.

---

## Part 2 — The implementation specification

Everything in Part 2 follows directly from Part 1. If a decision here seems arbitrary, re-read the corresponding technique explanation above.

---

### System architecture

```
UI / pipeline caller
        │
        ▼
   API Gateway              ← auth, rate limiting, routing, request logging
        │
        ▼
Orchestration Service       ← pipeline composition, async job tracking, audit trail
        │
   ┌────┼──────────────────────┐
   ▼    ▼        ▼       ▼     ▼
Masking  Encryption  Tokenization  Synthetic-Data  Hashing
Service  Service     Service       Service         Service

  [ Shared: Token Vault · KMS · Audit Log · Config Store ]
```

The UI and all batch pipelines call only the orchestration service. The orchestration service composes atomic calls to the five technique services. The five technique services are not publicly reachable — they only accept traffic from the orchestration service (and masking → encryption for hybrid flows).

**A single service with a `task` or `operation` switch is explicitly rejected.** This is the monolith pattern. It is not implemented here regardless of how a generation prompt is framed.

---

### Service inventory

| Service | Technique | Reversible | Key/secret | Operational profile |
|---|---|---|---|---|
| `masking-service` | Char mask · nullify · shuffle · noise · generalize | No | No | Stateless · fast · horizontal scale |
| `encryption-service` | AES-GCM · FPE FF3-1 | Yes — with key | Yes — KMS | Stateful (KMS-proxied) · medium scale |
| `tokenization-service` | Tokenize · detokenize | Yes — with vault | Vault access | I/O bound · scale by vault throughput |
| `synthetic-data-service` | Rule-based · statistical · CTGAN · hybrid | N/A | No | CPU+memory heavy · async jobs |
| `hashing-service` | SHA-256 · HMAC-SHA256 | No | Salt only | Stateless · negligible load |
| `orchestration-service` | Pipeline composition | N/A | N/A | Stateful (job store) · 2 pods |

---

### Technology stack

- **Language:** Python 3.11+
- **Framework:** FastAPI with `uvicorn` — async throughout, no sync blocking calls
- **Validation:** Pydantic v2 for all request/response contracts
- **Inter-service calls:** `httpx.AsyncClient` — never the synchronous `requests` library
- **Retry logic:** `tenacity` with exponential backoff
- **Secrets:** AWS KMS for key management; HashiCorp Vault for token vault — never in env vars or config files
- **Logging:** `structlog` with JSON output — never `print()`
- **Observability:** OpenTelemetry tracing; Prometheus `/metrics` endpoint
- **Testing:** `pytest` + `pytest-asyncio`; 100% coverage on business logic
- **Dependencies:** `pyproject.toml` — never `requirements.txt`

---

### Universal code conventions

These apply identically to every service. A code generator must not deviate from any of these.

#### Project layout (every service)

```
{service-name}/
├── app/
│   ├── main.py              # FastAPI app factory and lifespan
│   ├── api/v1/routes.py     # route handlers only — no business logic
│   ├── models/
│   │   ├── request.py       # Pydantic request models
│   │   └── response.py      # Pydantic response models
│   ├── core/
│   │   ├── config.py        # pydantic-settings — all env vars here
│   │   ├── logging.py       # structlog JSON configuration
│   │   └── exceptions.py    # AppError hierarchy + handler registration
│   ├── services/{domain}.py # pure business logic — no FastAPI imports
│   └── dependencies.py      # FastAPI Depends() providers
├── tests/unit/
├── tests/integration/
├── Dockerfile
├── pyproject.toml
└── k8s/
    ├── deployment.yaml
    ├── service.yaml
    ├── hpa.yaml
    └── networkpolicy.yaml
```

#### App factory — `main.py`

Use `lifespan` context manager. Never `@app.on_event`.

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.api.v1.routes import router
from app.core.logging import configure_logging
from app.core.exceptions import register_exception_handlers

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    # initialise clients (KMS, vault, etc.) here
    yield
    # teardown here

def create_app() -> FastAPI:
    app = FastAPI(title="{Service Name}", version="1.0.0",
                  lifespan=lifespan, docs_url="/docs", redoc_url=None)
    register_exception_handlers(app)
    app.include_router(router, prefix="/api/v1")
    return app

app = create_app()
```

#### Logging — structlog, JSON, no PII

Every log line carries `service`, `trace_id`, `correlation_id`. Never log field values — only field names and record counts.

```python
import structlog
logger = structlog.get_logger()

# correct — field names and counts only
logger.info("masking.complete", fields_masked=3, record_count=1000, duration_ms=42)

# wrong — never log actual values
logger.info(f"masked ssn: {ssn}")
```

#### Error handling

All domain errors inherit from `AppError`. A single handler on the app converts them to structured JSON.

```python
# core/exceptions.py
class AppError(Exception):
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

class ValidationError(AppError):
    status_code = 422
    error_code = "VALIDATION_ERROR"

class EncryptionError(AppError):
    status_code = 500
    error_code = "ENCRYPTION_FAILED"

class TokenNotFoundError(AppError):
    status_code = 404
    error_code = "TOKEN_NOT_FOUND"

def register_exception_handlers(app):
    @app.exception_handler(AppError)
    async def handler(request, exc):
        return JSONResponse(status_code=exc.status_code, content={
            "error_code": exc.error_code,
            "message": exc.message,
            "trace_id": request.state.trace_id,
        })
```

#### Request / response models

All Pydantic models use `ConfigDict(frozen=True)`. Field names in `snake_case`. Every response includes `request_id`, `service`, `duration_ms`.

```python
class BaseResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    request_id: str
    service: str
    duration_ms: int
```

#### Health endpoints — every service

```python
@app.get("/health")   # liveness — is the process alive?
async def health():
    return {"status": "ok"}

@app.get("/ready")    # readiness — can it serve traffic?
async def ready():
    # check KMS, vault, config store reachability
    return {"status": "ready", "checks": {...}}
```

---

### Service 1 — masking-service

**What it does:** Applies irreversible, key-free transforms to fields. The fastest and simplest service. Zero external dependencies beyond the config store.

**Supported techniques:**

| Technique | What it does | Example |
|---|---|---|
| `character_mask` | Replaces characters with pattern, keeps partial value | `123-45-6789` → `XXX-XX-6789` |
| `nullify` | Replaces value with NULL | `jane@example.com` → `null` |
| `shuffle` | Swaps values across rows in a batch | Loan amounts reordered across borrowers |
| `noise_inject` | Adds random ±N% delta to numeric field | `450000` → `447230` |
| `generalize` | Reduces precision of date or numeric field | `1978-04-12` → `1978` |

**API:**

```
POST /api/v1/mask
```

```json
{
  "records": [
    {"ssn": "123-45-6789", "loan_amount": 450000, "dob": "1978-04-12"}
  ],
  "policy": {
    "ssn":         {"technique": "character_mask", "pattern": "XXX-XX-{last4}"},
    "loan_amount": {"technique": "noise_inject", "delta_pct": 5},
    "dob":         {"technique": "generalize", "granularity": "year"}
  }
}
```

```json
{
  "request_id": "uuid", "service": "masking-service", "duration_ms": 12,
  "records_processed": 1,
  "result": [{"ssn": "XXX-XX-6789", "loan_amount": 447230, "dob": "1978"}]
}
```

**Implementation rules:**
- Each technique is a **pure function** in `services/masking.py` — no class hierarchy, just functions.
- `shuffle` operates on a batch, not a single record. Validate `len(records) > 1` when shuffle is requested.
- Use `secrets.SystemRandom()` for noise injection — never `random.random()`.
- Never log field values.

**Scale:** HPA targeting 60% CPU. Min 2, max 8 replicas.

---

### Service 2 — encryption-service

**What it does:** Reversible field encryption. All key operations proxy through AWS KMS — no key material persists in memory beyond a single request lifecycle.

**Why two algorithms exist:**
- **AES-GCM** — for fields that do not participate in joins. Output is unreadable ciphertext. Stronger security. Use for email, phone, address.
- **FPE (FF3-1)** — for fields that must remain usable as join keys. Output preserves input format. A 9-digit SSN encrypts to a 9-digit ciphertext. Use for SSN, loan number, account ID.

**API:**

```
POST /api/v1/encrypt
POST /api/v1/decrypt
```

```json
{
  "fields": {
    "ssn":   {"value": "123456789",      "algorithm": "fpe", "key_alias": "home-lending-prod"},
    "email": {"value": "jane@acme.com",  "algorithm": "aes", "key_alias": "home-lending-prod"}
  }
}
```

```json
{
  "request_id": "uuid", "service": "encryption-service", "duration_ms": 18,
  "result": {
    "ssn":   "847291043",
    "email": "base64-encoded-ciphertext"
  }
}
```

**Implementation rules:**
- Use the `ff3` library for FF3-1. The tweak must be derived deterministically from a stable field identifier (field name + table name) — not random — so the same plaintext always produces the same ciphertext for join compatibility.
- Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` for AES-GCM. Never `PyCrypto` or `pycryptodome`.
- Fetch the data key from AWS KMS per request using `boto3`. Cache the **wrapped** (encrypted) key, never the plaintext key. `del` the plaintext key immediately after use.
- Prefix all ciphertexts with a version byte so the decrypt endpoint can validate provenance.
- NetworkPolicy: only `orchestration-service` and `masking-service` may call this service.

**Scale:** Min 2, max 6 replicas. `PodDisruptionBudget` with `minAvailable: 1`.

---

### Service 3 — tokenization-service

**What it does:** Maps real values to random surrogate tokens stored in HashiCorp Vault. The same real value always maps to the same token within a namespace. Only authorised callers can reverse the mapping.

**API:**

```
POST /api/v1/tokenize      # real value → token
POST /api/v1/detokenize    # token → real value (restricted callers only)
GET  /api/v1/token/{token} # confirm token exists without revealing value
```

```json
{
  "records": [
    {"field": "ssn",            "value": "123-45-6789",  "namespace": "home-lending"},
    {"field": "account_number", "value": "ACC-9871234",  "namespace": "home-lending"}
  ]
}
```

```json
{
  "request_id": "uuid", "service": "tokenization-service", "duration_ms": 9,
  "tokens": [
    {"field": "ssn",            "token": "TKN-a3f9b2c1-..."},
    {"field": "account_number", "token": "TKN-d7e4a1f0-..."}
  ]
}
```

**Implementation rules:**
- Tokens are UUID4 prefixed with `TKN-` and namespaced by domain. The prefix makes tokens identifiable in logs without being reversible.
- Idempotent within namespace: `(namespace, field, value)` always maps to the same token. Derive the Vault key as `HMAC-SHA256(namespace + field + value, hmac_key)`. Look up before generating.
- Vault path convention: `secret/home-lending/{environment}/tokens/{namespace}/{hmac_of_value}`
- `detokenize` checks the caller's service identity (header injected by API gateway). Only `orchestration-service` or allowlisted services may detokenize. Return `403` for all others.
- Vault writes are transactional. If the write fails, return `503` — no partial tokens.

**Scale:** 2 replicas with connection pooling to Vault.

---

### Service 4 — synthetic-data-service

**What it does:** Generates entirely fake but realistic records for UAT, ML training, vendor handoffs, and stress testing. All generation is **async** — callers submit a job and poll for completion. Never runs synchronously.

**Generation modes:**

| Mode | Description | When to use | Typical duration |
|---|---|---|---|
| `rule_based` | Faker + home lending domain constraints | Vendor testing, basic functional UAT | < 5 seconds |
| `statistical` | Sample from column-level stat summaries — no row-level prod data | ML training corpus, large-scale UAT | 10–60 seconds |
| `ctgan` | Train or load a CTGAN model; generate rows matching complex distributions | High-fidelity UAT, model validation | 2–30 minutes |
| `hybrid` | Keep real financial structure; replace all PII with Faker | Regression UAT — real edge cases, no exposure | 5–30 seconds |

**API — async job pattern:**

```
POST   /api/v1/jobs                  # submit → returns job_id immediately
GET    /api/v1/jobs/{job_id}         # poll status
GET    /api/v1/jobs/{job_id}/result  # download (only when status=completed)
DELETE /api/v1/jobs/{job_id}         # cancel
```

```json
{
  "mode": "hybrid",
  "row_count": 50000,
  "schema": {
    "loan_amount":   {"type": "numeric", "source": "keep_real"},
    "ltv":           {"type": "numeric", "source": "keep_real"},
    "credit_score":  {"type": "numeric", "source": "keep_real"},
    "borrower_name": {"type": "string",  "source": "faker", "faker_provider": "name"},
    "ssn":           {"type": "string",  "source": "faker", "faker_provider": "ssn"},
    "email":         {"type": "string",  "source": "faker", "faker_provider": "email"}
  },
  "source_data_ref":    "s3://home-lending-prod-stats/originations_stats_2024.json",
  "output_format":      "parquet",
  "output_destination": "s3://home-lending-uat/synthetic/run-{job_id}/"
}
```

```json
{
  "job_id": "uuid", "status": "running", "mode": "hybrid",
  "progress_pct": 42,
  "submitted_at": "2024-01-15T10:00:00Z",
  "estimated_completion": "2024-01-15T10:03:00Z"
}
```

**Implementation rules:**
- Do not run generation on the FastAPI event loop. Offload to `ProcessPoolExecutor` or Celery workers.
- Job state persists in Redis — not in memory. Pod restarts must not lose job state.
- `source_data_ref` must be validated against an allowlist of S3 prefixes before reading. It points to pre-computed stats JSON only — never to raw production data.
- CTGAN model artefacts are cached in S3, not in the pod filesystem.
- Write output to S3 in Parquet using `pyarrow`. Stream row groups — do not buffer full datasets in memory.
- Home lending domain constraints for `rule_based` mode:
  - `loan_amount`: $50,000 – $3,000,000
  - `ltv`: 0.50 – 0.97
  - `loan_amount` must equal `property_value × ltv` (rounded to nearest $1,000)
  - `credit_score`: 500 – 850
  - `dti`: 0.10 – 0.57
  - `rate`: 2.5% – 9.5%
  - `term_months`: one of 60, 120, 180, 240, 300, 360

---

#### Adapting to different data models, SCD types, and rule variations

The four integrity layers described below would be brittle if they referenced column names or values directly in code. A hardcoded `r["loan_status"] == "foreclosure"` breaks the instant a second company calls the field `LOAN_STAT_CD` with value `"FC"`, or a third calls it `status_code` with value `"4"`. The adaptation model separates three things that are currently fused in naive implementations:

| Layer | What varies | How it is handled |
|---|---|---|
| Business concept | Universal — "a loan is in foreclosure" is true everywhere | Canonical concept registry |
| Business rule | Company-variant — JPMC targets 1.2%; another lender targets 0.8% | Rule registry, overridable per run |
| Schema mapping | Data-model variant — field name, value encoding, SCD type | Schema adapter, registered per data model |

A code generator must implement all three registries as separate, independently loadable Python modules. Hardcoding any of the three is a specification violation.

---

##### Concept registry (`services/integrity/concepts.py`)

The concept registry defines canonical names for every business concept the integrity layers understand. Concepts are strings in a controlled vocabulary. They never reference column names, table names, or value encodings.

```python
# Canonical concept names — the only strings the integrity layers use internally
class Concept:
    LOAN_IN_FORECLOSURE      = "loan.in_foreclosure"
    LOAN_DELINQUENT_90D      = "loan.delinquent_90d"
    BORROWER_UNEMPLOYED      = "borrower.unemployed_at_origination"
    LOAN_TYPE_FHA            = "loan.type_fha"
    LOAN_TYPE_VA             = "loan.type_va"
    LOAN_TYPE_CONVENTIONAL   = "loan.type_conventional"
    LOAN_PURPOSE_PURCHASE    = "loan.purpose_purchase"
    LOAN_PURPOSE_REFI        = "loan.purpose_refinance"
    RATE_TYPE_ARM            = "loan.rate_type_arm"
    ESCROW_REQUIRED          = "loan.escrow_required"
    CO_BORROWER_PRESENT      = "borrower.co_borrower_present"
    FLOOD_ZONE_AE            = "property.flood_zone_ae"
    CREDIT_SCORE_SUBPRIME    = "borrower.credit_score_subprime"   # < 580
    CREDIT_SCORE_PRIME       = "borrower.credit_score_prime"      # >= 660
    HAS_PRIOR_LOAN           = "borrower.has_prior_loan_same_property"
```

---

##### Rule registry (`services/integrity/rules.py`)

The rule registry maps each concept to a target rate or constraint value. Rules are loaded from the config store at job submission time, not hardcoded. Every rule has a global default. A job request can override any rule in its `business_rules` block.

```python
# Default rule targets — loaded from SSM, overridable per job
DEFAULT_RULES: dict[str, float | int] = {
    Concept.LOAN_IN_FORECLOSURE:    0.012,   # 1.2%
    Concept.LOAN_DELINQUENT_90D:    0.038,   # 3.8%
    Concept.BORROWER_UNEMPLOYED:    0.040,   # 4.0%
    Concept.LOAN_TYPE_FHA:          0.180,   # 18%
    Concept.LOAN_TYPE_VA:           0.080,   # 8%
    Concept.LOAN_PURPOSE_REFI:      0.350,   # 35%
    Concept.RATE_TYPE_ARM:          0.120,   # 12%
    Concept.ESCROW_REQUIRED:        0.820,   # 82%
    Concept.CO_BORROWER_PRESENT:    0.440,   # 44%
}

def resolve_rules(job_overrides: dict) -> dict:
    """Merge defaults with per-job overrides. Overrides win."""
    return DEFAULT_RULES | job_overrides
```

---

##### Schema adapter (`services/integrity/schema_adapter.py`)

The schema adapter translates a concept and its resolved value into the concrete field name and encoded value that exist in a specific company's data model. One adapter class per registered data model. The adapter is selected by the `data_model` field in the job request.

```python
from abc import ABC, abstractmethod

class SchemaAdapter(ABC):
    """Translate canonical concepts to this data model's field names and value encodings."""

    @abstractmethod
    def field_for(self, concept: str) -> str:
        """Return the column name for this concept in this data model."""

    @abstractmethod
    def value_for(self, concept: str, canonical_value: str) -> str | int | bool:
        """Return the encoded value for this concept in this data model."""

    @abstractmethod
    def scd_type_for(self, table: str) -> int:
        """Return the SCD type (1, 2, 3, 4, or 6) used for this table in this data model."""


# JPMC home lending — canonical field names, SCD2 for loan and borrower
class JPMCHomeLendingAdapter(SchemaAdapter):
    _FIELD_MAP = {
        Concept.LOAN_IN_FORECLOSURE:   ("loan_status",        "foreclosure"),
        Concept.LOAN_DELINQUENT_90D:   ("loan_status",        "delinquent"),
        Concept.BORROWER_UNEMPLOYED:   ("employment_status",  "unemployed"),
        Concept.LOAN_TYPE_FHA:         ("loan_type",          "fha"),
        Concept.LOAN_TYPE_VA:          ("loan_type",          "va"),
        Concept.LOAN_TYPE_CONVENTIONAL:("loan_type",          "conventional"),
        Concept.RATE_TYPE_ARM:         ("rate_type",          "arm"),
        Concept.ESCROW_REQUIRED:       ("escrow_required",    True),
        Concept.CREDIT_SCORE_SUBPRIME: ("credit_score",       580),   # threshold
    }
    _SCD_MAP = {"loan": 2, "borrower": 2, "property": 1, "payment_history": 4}

    def field_for(self, concept):
        return self._FIELD_MAP[concept][0]

    def value_for(self, concept, canonical_value=None):
        return self._FIELD_MAP[concept][1]

    def scd_type_for(self, table):
        return self._SCD_MAP.get(table, 1)


# Example of a second company's adapter — different naming, different encodings
class AcmeMortgageAdapter(SchemaAdapter):
    _FIELD_MAP = {
        Concept.LOAN_IN_FORECLOSURE:   ("LOAN_STAT_CD",       "FC"),
        Concept.LOAN_DELINQUENT_90D:   ("LOAN_STAT_CD",       "DL"),
        Concept.BORROWER_UNEMPLOYED:   ("EMPL_STAT_CD",       "U"),
        Concept.LOAN_TYPE_FHA:         ("PROD_TYPE_CD",       "FHA"),
        Concept.LOAN_TYPE_VA:          ("PROD_TYPE_CD",       "VA"),
        Concept.LOAN_TYPE_CONVENTIONAL:("PROD_TYPE_CD",       "CONV"),
        Concept.RATE_TYPE_ARM:         ("RATE_TYPE_CD",       "A"),
        Concept.ESCROW_REQUIRED:       ("ESCROW_IND",         "Y"),
        Concept.CREDIT_SCORE_SUBPRIME: ("FICO_SCORE",         580),
    }
    _SCD_MAP = {"loan": 2, "borrower": 3, "property": 1, "payment_history": 4}

    def field_for(self, concept):
        return self._FIELD_MAP[concept][0]

    def value_for(self, concept, canonical_value=None):
        return self._FIELD_MAP[concept][1]

    def scd_type_for(self, table):
        return self._SCD_MAP.get(table, 1)


# Registry — keyed by data_model identifier in the job request
ADAPTER_REGISTRY: dict[str, type[SchemaAdapter]] = {
    "jpmc_home_lending":  JPMCHomeLendingAdapter,
    "acme_mortgage":      AcmeMortgageAdapter,
}

def get_adapter(data_model: str) -> SchemaAdapter:
    cls = ADAPTER_REGISTRY.get(data_model)
    if not cls:
        raise ValueError(f"No schema adapter registered for data_model='{data_model}'")
    return cls()
```

---

##### SCD resolver (`services/integrity/scd_resolver.py`)

Different data models use different SCD (Slowly Changing Dimension) types for the same table. The SCD type changes how historical records are generated — not what business rules apply, but how many rows are emitted per entity and what surrogate key and effectivity columns are populated.

```python
from enum import IntEnum
from dataclasses import dataclass
from datetime import date, timedelta
import secrets

class SCDType(IntEnum):
    TYPE_1 = 1   # Overwrite — one row per entity, no history
    TYPE_2 = 2   # Add new row with effectivity dates — full history
    TYPE_3 = 3   # Add columns for current + prior value — one prior version
    TYPE_4 = 4   # History table — current in main, all history in separate table
    TYPE_6 = 6   # Hybrid SCD2 + SCD3 — effectivity dates + current/prior columns

@dataclass
class SCDRecord:
    natural_key: str
    surrogate_key: str
    effective_from: date
    effective_to: date | None     # None = current record
    is_current: bool
    prior_value_cols: dict        # SCD3/6 only

def expand_scd(row: dict, table: str, adapter: SchemaAdapter,
               history_depth: int = 2) -> list[dict]:
    """
    Given a single generated row, expand it into the correct number of SCD records
    for the data model's SCD type for this table. Returns 1 row for SCD1,
    history_depth rows for SCD2/4, 1 row with extra columns for SCD3, etc.
    """
    scd_type = adapter.scd_type_for(table)
    rng = secrets.SystemRandom()
    base_date = date(2018, 1, 1)
    today = date.today()

    if scd_type == SCDType.TYPE_1:
        return [row]

    elif scd_type == SCDType.TYPE_2:
        records = []
        start = base_date + timedelta(days=rng.randint(0, 1800))
        for i in range(history_depth):
            end = start + timedelta(days=rng.randint(90, 720))
            is_current = (i == history_depth - 1)
            records.append({
                **row,
                "surrogate_key":  f"SK-{row['natural_key']}-{i}",
                "effective_from": start.isoformat(),
                "effective_to":   None if is_current else end.isoformat(),
                "is_current_flag": is_current,
            })
            start = end
        return records

    elif scd_type == SCDType.TYPE_3:
        # Add prior_* columns for tracked fields
        tracked = ["loan_status", "credit_score", "dti"]
        prior_cols = {f"prior_{f}": row.get(f) for f in tracked if f in row}
        return [{**row, **prior_cols, "record_version": 2}]

    elif scd_type == SCDType.TYPE_4:
        # Main table gets current row; history table rows returned tagged
        history = []
        start = base_date + timedelta(days=rng.randint(0, 1800))
        for i in range(history_depth - 1):
            end = start + timedelta(days=rng.randint(90, 720))
            history.append({**row, "hist_effective_from": start.isoformat(),
                            "hist_effective_to": end.isoformat(), "_table": f"{table}_history"})
            start = end
        current = {**row, "_table": table}
        return [current] + history

    elif scd_type == SCDType.TYPE_6:
        # SCD2 rows with SCD3 current/prior columns added
        scd2_rows = expand_scd(row, table,
                               type(adapter)(), history_depth)  # get SCD2 first
        tracked = ["loan_status", "credit_score"]
        for r in scd2_rows:
            for f in tracked:
                r[f"current_{f}"] = row.get(f)
                r[f"prior_{f}"]   = row.get(f)           # simplified — real impl tracks transitions
        return scd2_rows

    return [row]
```

---

##### How the layers consume the adapter

Every integrity layer receives the adapter as a constructor argument. Layers never reference column names or value strings directly — they always go through the adapter. This is the contract a code generator must enforce.

```python
# Correct — adapter-mediated field access
class BusinessRulesPartitioner:
    def __init__(self, adapter: SchemaAdapter, rules: dict):
        self.adapter = adapter
        self.rules = rules

    def foreclosure_field_and_value(self):
        return (
            self.adapter.field_for(Concept.LOAN_IN_FORECLOSURE),
            self.adapter.value_for(Concept.LOAN_IN_FORECLOSURE),
        )  # returns ("loan_status", "foreclosure") for JPMC
           # returns ("LOAN_STAT_CD", "FC") for Acme

# Wrong — never do this in integrity layer code
def bad_partitioner(row):
    return row["loan_status"] == "foreclosure"   # hardcoded — breaks on Acme's model
```

---

##### Extended job request — with data model and integrity configuration

```json
{
  "mode": "hybrid",
  "row_count": 50000,
  "data_model": "jpmc_home_lending",
  "schema": { ... },
  "source_data_ref": "s3://home-lending-prod-stats/originations_stats_2024.json",
  "output_format": "parquet",
  "output_destination": "s3://home-lending-uat/synthetic/run-{job_id}/",

  "integrity": {
    "business_rules": {
      "loan.in_foreclosure":    0.012,
      "loan.delinquent_90d":    0.038,
      "borrower.unemployed_at_origination": 0.040,
      "loan.type_fha":          0.18,
      "loan.purpose_refinance": 0.35
    },
    "relationship_rules": "default",
    "valid_values": "default",
    "referential_integrity": "strict",
    "tolerance_pct": 0.5,
    "scd_history_depth": 2
  },

  "tables": ["borrower", "property", "loan", "delinquency_history",
             "payment_history", "escrow", "msr_record"]
}
```

Note that `business_rules` now uses canonical concept names (`"loan.in_foreclosure"`) rather than field names (`"loan_status"`). The adapter translates these to the correct field names and value encodings for the specified `data_model` at runtime. Switching the entire generation to a different company's data model requires only changing `"data_model": "acme_mortgage"` in the request — no changes to integrity layer code.

---

#### Four-layer integrity pipeline — mandatory for all generation modes

Every generation job — regardless of mode — must pass all four integrity layers before output is written to the destination. A job that fails any layer is marked `failed` with a structured validation report. It is never silently truncated or partially written.

The layers execute in sequence inside the worker process, not as separate service calls. They are implemented in `services/integrity/` as four independent modules called in order by the generation orchestrator in `services/synthetic.py`.

---

##### Layer 1 — Business Rules Integrity (`services/integrity/business_rules.py`)

**Purpose:** Control portfolio-level rates and distributions across the entire generated population. These are aggregate targets, not row-level constraints.

**How it works:** The generator does not generate rows randomly and then check whether the aggregate rates landed correctly — that produces drift at large row counts. Instead, the total row count is partitioned upfront according to the business rule targets, and each partition is generated as a typed cohort. The cohorts are then shuffled into a single output dataset.

```python
# Example: partitioning 50,000 loans by business rules
{
  "total_rows": 50000,
  "partitions": [
    {"status": "active",      "count": 45100},   # 90.2%
    {"status": "delinquent",  "count": 1900},    # 3.8%
    {"status": "foreclosure", "count": 600},     # 1.2%
    {"status": "paid_off",    "count": 2400}     # 4.8%
  ]
}
```

**Business rule targets — home lending defaults (overridable per job):**

| Rule | Default target | Field(s) affected |
|---|---|---|
| Foreclosure rate | 1.2% | `loan_status = foreclosure` |
| 90-day delinquency rate | 3.8% | `loan_status = delinquent`, `days_past_due >= 90` |
| Borrower unemployment rate at origination | 4.0% | `employment_status = unemployed` |
| FHA loan share | 18% | `loan_type = fha` |
| VA loan share | 8% | `loan_type = va` |
| Conventional loan share | 74% | `loan_type = conventional` |
| Refinance share | 35% | `loan_purpose = refinancing` or `cash_out_refinancing` |
| Purchase share | 65% | `loan_purpose = home_purchase` |
| ARM loan share | 12% | `rate_type = arm` |
| Co-borrower present | 44% | `co_borrower_present = true` |
| Average days-to-close | 42 days (±5) | `application_date` to `funded_date` delta |
| Escrow required | 82% | `escrow_required = true` |

Business rule targets are passed as a `business_rules` object in the job request. When not supplied, defaults above apply. A code generator must implement this as a `BusinessRulesConfig` Pydantic model with all fields optional and defaulted.

```python
class BusinessRulesConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    foreclosure_rate: float = 0.012
    delinquency_rate_90d: float = 0.038
    unemployment_rate: float = 0.040
    fha_share: float = 0.18
    va_share: float = 0.08
    refinance_share: float = 0.35
    arm_share: float = 0.12
    co_borrower_rate: float = 0.44
    avg_days_to_close: int = 42
    escrow_required_rate: float = 0.82
```

After generation, a `BusinessRulesValidator` computes the actual rates from the generated dataset and compares them to targets within a configurable tolerance (default ±0.5 percentage points). Validation failure writes a structured report to the job's audit record and marks the job `failed`.

---

##### Layer 2 — Relationship Integrity Across Tables (`services/integrity/relationship.py`)

**Purpose:** Ensure that field values are consistent with each other across the generated record and across related generated tables. A borrower with `employment_status = unemployed` must have a DTI that reflects that reality. A loan in foreclosure must have a delinquency history that precedes it.

**How it works:** Relationship rules are applied as a post-generation transformation pass over the raw generated rows. Each rule is a function that receives a record (or a pair of related records) and either transforms it to be consistent or raises a `RelationshipViolation` that is logged to the validation report.

**Mandatory cross-field relationship rules — home lending:**

```python
RELATIONSHIP_RULES = [
    # Employment status drives DTI range
    # Unemployed borrowers cannot have the DTI of employed borrowers
    Rule("unemployed_dti",
         condition=lambda r: r["employment_status"] == "unemployed",
         transform=lambda r: r | {"dti": round(secrets.SystemRandom()
                                   .uniform(0.45, 0.57), 2)}),

    # Credit score gates loan product type
    # Subprime scores cannot have conventional loans
    Rule("credit_score_to_loan_type",
         condition=lambda r: r["credit_score"] < 580,
         transform=lambda r: r | {"loan_type": "fha",
                                   "rate": r["rate"] + round(secrets.SystemRandom()
                                            .uniform(0.5, 1.5), 3)}),

    # Foreclosure loans must have delinquency history
    # Handled during child table generation — see cross-table rules below

    # ARM loans must have rate cap and initial fixed period
    Rule("arm_requires_cap",
         condition=lambda r: r["rate_type"] == "arm",
         transform=lambda r: r | {
             "initial_fixed_period_months": secrets.SystemRandom().choice([60, 84]),
             "rate_cap_initial": 2.0,
             "rate_cap_periodic": 1.0,
             "rate_cap_lifetime": 5.0,
         }),

    # Flood zone AE requires flood insurance in escrow
    Rule("flood_zone_escrow",
         condition=lambda r: r.get("flood_zone") == "AE",
         transform=lambda r: r | {"escrow_required": True,
                                   "flood_insurance_required": True}),
]
```

**Cross-table relationship rules — generation order:**

Tables must be generated in dependency order. The generation context carries the set of generated primary keys and typed metadata so child table generators can draw from it.

```
Generation order:
  1. borrower            → generates borrower_id (PK)
  2. property            → generates property_id (PK)
  3. loan                → draws borrower_id, property_id (FK); generates loan_id (PK)
  4. delinquency_history → draws loan_id where loan_status = foreclosure or delinquent
  5. payment_history     → draws loan_id; payment_date > funded_date
  6. escrow              → draws loan_id where escrow_required = true
  7. msr_record          → draws loan_id where loan_status = active or paid_off
```

Each step receives the generation context from the previous step. A code generator must implement this as a `GenerationContext` dataclass that is threaded through the pipeline.

```python
@dataclass
class GenerationContext:
    borrower_ids:      list[str]
    property_ids:      list[str]
    loan_records:      list[dict]          # full records, needed for FK derivation
    foreclosure_ids:   set[str]            # loan_ids with foreclosure status
    delinquent_ids:    set[str]            # loan_ids with delinquency status
    escrow_loan_ids:   set[str]            # loan_ids requiring escrow
    active_loan_ids:   set[str]            # loan_ids eligible for MSR
```

---

##### Layer 3 — Valid Values Integrity (`services/integrity/valid_values.py`)

**Purpose:** Validate that every generated field contains a value that is domain-valid beyond just being in a numeric range. This is a post-generation quality gate — not a generation constraint.

**Implementation:** A `ValidValuesValidator` runs a suite of field-level validators over the generated DataFrame using `pandera` for schema-level validation and custom validators for checksum and geographic checks.

**Mandatory validators — home lending:**

```python
VALID_VALUE_RULES = {

    # HMDA-defined loan purpose enumeration
    "loan_purpose": EnumValidator([
        "home_purchase", "refinancing", "cash_out_refinancing",
        "home_improvement", "other"
    ]),

    # HMDA property type enumeration
    "property_type": EnumValidator([
        "single_family", "condo", "co_op", "manufactured_housing",
        "multifamily_2_4", "multifamily_5_plus"
    ]),

    # ABA routing number checksum (standard 9-digit weighted checksum)
    "aba_routing_number": ChecksumValidator(algorithm="aba"),

    # USPS state codes
    "property_state": EnumValidator(VALID_USPS_STATE_CODES),

    # ZIP code must exist and match state
    "zip_code": GeoConsistencyValidator(
        zip_field="zip_code",
        state_field="property_state",
        reference="usps_zip_database"
    ),

    # NMLS ID format — numeric, 7–10 digits, plausible range
    "loan_officer_nmls_id": RegexValidator(r"^\d{7,10}$"),

    # Lien status consistency — HELOC cannot be first lien if primary mortgage exists
    "lien_status": ConditionalValidator(
        condition=lambda r: r["loan_type"] == "heloc",
        rule=lambda r: r["lien_status"] == "second_lien"
    ),
}
```

Validation failures are collected into a `ValidationReport` — they do not raise exceptions mid-stream. After the full pass, if failure count exceeds the configurable threshold (default: 0 failures tolerated), the job is marked `failed` and the report is written to the audit log.

---

##### Layer 4 — Referential Integrity (`services/integrity/referential.py`)

**Purpose:** Confirm that every foreign key value in every generated child table resolves to a primary key that was generated in the corresponding parent table. This ensures joins work correctly in UAT.

**Implementation:** The `ReferentialIntegrityValidator` runs after all tables are generated. It operates on the `GenerationContext` and checks each FK → PK relationship.

**Mandatory FK → PK checks — home lending:**

```python
REFERENTIAL_INTEGRITY_CHECKS = [
    FKCheck(child_table="loan",              fk="borrower_id",
            parent_table="borrower",         pk="borrower_id"),

    FKCheck(child_table="loan",              fk="property_id",
            parent_table="property",         pk="property_id"),

    FKCheck(child_table="delinquency_history", fk="loan_id",
            parent_table="loan",             pk="loan_id"),

    FKCheck(child_table="payment_history",   fk="loan_id",
            parent_table="loan",             pk="loan_id"),

    FKCheck(child_table="escrow",            fk="loan_id",
            parent_table="loan",             pk="loan_id"),

    FKCheck(child_table="msr_record",        fk="loan_id",
            parent_table="loan",             pk="loan_id"),

    # Temporal constraint: payment_date must be after funded_date
    TemporalCheck(child_table="payment_history", child_field="payment_date",
                  parent_table="loan",           parent_field="funded_date",
                  constraint="child_after_parent"),

    # Status constraint: MSR records only for active or paid-off loans
    StatusCheck(child_table="msr_record",    fk="loan_id",
                parent_table="loan",         pk="loan_id",
                allowed_parent_statuses=["active", "paid_off"]),
]
```

Any FK value that does not resolve to a PK in the generation context is a hard failure. The job is marked `failed` and the report identifies which table, which field, and how many records failed. Partial output is never written.

---

#### Extended job request — with integrity configuration

The full job request schema must include the integrity configuration object:

```json
{
  "mode": "hybrid",
  "row_count": 50000,
  "schema": { ... },
  "source_data_ref": "s3://home-lending-prod-stats/originations_stats_2024.json",
  "output_format": "parquet",
  "output_destination": "s3://home-lending-uat/synthetic/run-{job_id}/",

  "integrity": {
    "business_rules": {
      "foreclosure_rate": 0.012,
      "delinquency_rate_90d": 0.038,
      "unemployment_rate": 0.040,
      "fha_share": 0.18,
      "refinance_share": 0.35
    },
    "relationship_rules": "default",
    "valid_values": "default",
    "referential_integrity": "strict",
    "tolerance_pct": 0.5
  },

  "tables": ["borrower", "property", "loan", "delinquency_history",
             "payment_history", "escrow", "msr_record"]
}
```

When `tables` contains more than one entry, the service generates all listed tables in dependency order and writes each as a separate Parquet file under the output destination. The file naming convention is `{output_destination}/{table_name}.parquet`.

**Scale:** Dedicated node pool with memory-optimized instances (`nodeSelector: workload: synthetic-data`). Min 2, max 8 replicas. HPA on custom metric: pending jobs per pod > 2.

---

### Service 5 — hashing-service

**What it does:** Produces deterministic one-way digests. The same input + salt always produces the same hash. Used for surrogate keys and pseudonymization across environments.

**API:**

```
POST /api/v1/hash
```

```json
{
  "records": [
    {"field": "ssn",   "value": "123-45-6789"},
    {"field": "email", "value": "jane@example.com"}
  ],
  "algorithm": "hmac_sha256",
  "salt": "home-lending-2024-uat"
}
```

```json
{
  "request_id": "uuid", "service": "hashing-service", "duration_ms": 2,
  "result": [
    {"field": "ssn",   "hash": "a3f9b2c1..."},
    {"field": "email", "hash": "d7e4a1f0..."}
  ]
}
```

**Implementation rules:**
- Use Python's `hashlib` only. No third-party crypto libraries.
- Salt is validated against a registered allowlist in the config store. Unknown salts → `422`. Empty salt → `422`.
- Preferred algorithm is `hmac_sha256` — it accepts an `hmac_key_alias` field that resolves to a KMS-managed key for the HMAC secret.

**Scale:** 1 replica is sufficient. Scale to 2 if p99 latency exceeds 50ms.

---

### Service 6 — orchestration-service

**What it does:** Composes multi-step pipelines from the five atomic services. This is the only service reachable from the API gateway. It owns the audit trail.

**Supported pipelines:**

| Pipeline | Steps |
|---|---|
| `prod_to_uat_refresh` | tokenize PII → mask display fields → noise-inject financials → audit |
| `ml_training_prep` | mask PII → hash surrogate keys → generate synthetic supplement → audit |
| `vendor_data_export` | generate rule-based synthetic → audit |
| `field_encrypt_pipeline` | FPE-encrypt join keys → AES-encrypt non-join fields → audit |

**API:**

```
POST /api/v1/pipelines            # submit pipeline run
GET  /api/v1/pipelines/{run_id}   # poll status
GET  /api/v1/audit                # query audit log
```

```json
{
  "pipeline": "prod_to_uat_refresh",
  "input_ref":      "s3://home-lending-prod-exports/originations_2024_01.parquet",
  "output_ref":     "s3://home-lending-uat/originations_2024_01_masked.parquet",
  "requested_by":   "krishna@jpmc.com",
  "policy_version": "v2.1"
}
```

**Implementation rules:**
- Call downstream services with `httpx.AsyncClient`, 30-second timeout per step, 3 retries with exponential backoff via `tenacity`.
- Write to the audit log after each step before proceeding. A step failure after retries → mark pipeline `failed`. No silent partial completions.
- Audit records: `run_id`, `pipeline_type`, `step_name`, `input_field_count`, `output_field_count`, `requested_by`, `policy_version`, `started_at`, `completed_at`, `status`. Never record field values.
- Circuit breaker: 3 × 5xx errors from a downstream service within 10 seconds → open circuit for 60 seconds → return `503` immediately.

**Scale:** 2 replicas.

---

### Shared infrastructure

#### Field policy config store

Path in AWS SSM: `/home-lending/masking-policies/{environment}/{version}`

```json
{
  "version": "v2.1",
  "policies": {
    "borrower.ssn":        {"service": "tokenization", "technique": "tokenize"},
    "borrower.name":       {"service": "masking",      "technique": "character_mask", "keep_chars": 0},
    "borrower.email":      {"service": "masking",      "technique": "nullify"},
    "borrower.dob":        {"service": "masking",      "technique": "generalize", "granularity": "year"},
    "loan.loan_amount":    {"service": "masking",      "technique": "noise_inject", "delta_pct": 3},
    "loan.account_number": {"service": "tokenization", "technique": "tokenize"},
    "loan.credit_score":   {"service": "masking",      "technique": "noise_inject", "delta_pct": 2}
  }
}
```

Services cache this config with a 5-minute TTL. Policy changes take effect within one TTL window without a redeploy.

#### Audit log — shared write client

```python
from data_security_audit_client import AuditEvent
await audit.record(AuditEvent(
    run_id="uuid",
    service="masking-service",
    operation="character_mask",
    fields_processed=["ssn", "name", "email"],   # names only — never values
    record_count=1000,
    requested_by="orchestration-service",
    environment="uat",
    policy_version="v2.1",
    status="completed",
    duration_ms=42,
))
```

---

### Kubernetes conventions

#### Resource sizing

| Service | CPU req | CPU limit | Memory req | Memory limit |
|---|---|---|---|---|
| masking-service | 100m | 500m | 128Mi | 512Mi |
| encryption-service | 200m | 1000m | 256Mi | 1Gi |
| tokenization-service | 100m | 500m | 256Mi | 512Mi |
| synthetic-data-service | 2000m | 8000m | 4Gi | 16Gi |
| hashing-service | 50m | 200m | 64Mi | 256Mi |
| orchestration-service | 200m | 1000m | 512Mi | 2Gi |

#### NetworkPolicy — ingress allowed from

| Service | Accepts calls from |
|---|---|
| masking-service | orchestration-service |
| encryption-service | orchestration-service · masking-service |
| tokenization-service | orchestration-service |
| synthetic-data-service | orchestration-service |
| hashing-service | orchestration-service |
| orchestration-service | API gateway only |
| All services | Prometheus scraper (port 9090) |

#### Egress allowed to

KMS endpoint · HashiCorp Vault · S3 (synthetic-data-service and orchestration-service only) · SSM config store · Audit log store. Nothing else.

#### Health probes — every service

```yaml
livenessProbe:
  httpGet: { path: /health, port: 8000 }
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  httpGet: { path: /ready, port: 8000 }
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

### What not to generate

- No single service with a `task`, `operation`, or `technique` switch that handles masking, encryption, tokenization, and generation. This is the monolith pattern and is rejected.
- No synchronous long-running calls in `synthetic-data-service`. All generation is async with a job ID.
- No `print()` anywhere. `structlog` exclusively.
- No PII or field values in any log line at any log level.
- No key material or HMAC secrets in env vars, config files, or code. All secrets come from KMS or Vault.
- No `random` module for security-relevant randomness. Use `secrets` or `secrets.SystemRandom()`.
- No global mutable state. All shared state is external (Redis, Vault, SSM, S3).
- No `requests` library. Use `httpx.AsyncClient` exclusively.
- No `requirements.txt`. Use `pyproject.toml` with `[project.dependencies]`.

---

### Code generation prompt

Use this exact prompt structure when generating a service:

```
Using data-security-services-spec.md as the authoritative specification,
generate the complete FastAPI backend for [service-name].

Deliver:
  app/main.py                       lifespan, app factory, middleware
  app/core/config.py                pydantic-settings, all env vars
  app/core/exceptions.py            AppError hierarchy, handler registration
  app/core/logging.py               structlog JSON configuration
  app/models/request.py             Pydantic request models
  app/models/response.py            Pydantic response models
  app/services/[domain].py          pure business logic, no FastAPI imports
  app/api/v1/routes.py              route handlers, Depends() injection
  app/dependencies.py               all Depends() providers
  tests/unit/test_[domain].py       pytest, 100% business logic coverage
  Dockerfile                        multi-stage, non-root user
  k8s/deployment.yaml               resource limits from spec
  k8s/hpa.yaml                      scaling policy from spec
  k8s/networkpolicy.yaml            ingress/egress rules from spec

Mandatory constraints — do not deviate:
  pydantic v2 with ConfigDict(frozen=True)
  structlog for all logging — no print()
  httpx.AsyncClient for all inter-service calls
  tenacity for retry + circuit breaker logic
  secrets.SystemRandom() for all randomness
  pyproject.toml not requirements.txt
  no global mutable state
  no logging of field values or key material
```
