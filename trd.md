# Sentinel-EDR
## Technical Requirements Document (TRD)

**Project Name:** Sentinel-EDR  
**Document Version:** 1.0  
**Status:** Initial Draft  
**Related Document:** `prd.md`

---

## 1. Purpose

This document defines the technical design and implementation requirements for Sentinel-EDR.

It establishes the technology stack, software architecture, module responsibilities, communication mechanisms, security requirements, testing expectations, and integration constraints that must be followed during development.

The implementation must remain modular, testable, and suitable for incremental development through Google Antigravity tickets.

## 2. Technical Design Principles

The implementation must follow these principles:

1. **Modular architecture:** Each major subsystem must have a clear responsibility and interface.
2. **Incremental development:** Build and test components independently before integrating them.
3. **Evidence-based detection:** Every security verdict must retain its supporting evidence.
4. **Fail-safe handling:** Analysis errors must not silently produce a Benign verdict.
5. **Least privilege:** Components must use only the permissions required for their functions.
6. **Safe response:** Destructive operations must be isolated behind explicit response policies.
7. **Reproducibility:** Model versions, feature schemas, configuration, and evaluation procedures must be documented.
8. **Technology consistency:** Antigravity must not introduce additional frameworks or replace established technologies without an approved technical decision.
9. **Testability:** OS integrations, external services, and potentially destructive operations must be replaceable with test doubles during automated testing.
10. **No fabricated capabilities:** A feature must not be presented as implemented unless its code and behavior have been verified.

## 3. Technology Stack

### 3.1 Backend and Detection Engine

| Component | Technology | Responsibility |
|---|---|---|
| Programming language | Python | Core application and detection logic |
| Web framework | FastAPI | REST API and application services |
| Asynchronous communication | WebSockets | Live security event delivery |
| Database | SQLite | Initial incident and event persistence |
| Database access | SQLAlchemy | Database models and data access |
| File hashing | Python `hashlib` | SHA-256 calculation |
| Signature scanning | YARA-compatible Python integration | Rule-based detection |
| Executable parsing | LIEF | PE metadata and structural feature extraction |
| Machine learning | LightGBM | Model training |
| Model inference | ONNX Runtime | Model inference using a compatible ONNX artifact |
| System activity | `psutil` and supported OS interfaces | Process and system monitoring |
| Encryption | Python cryptography library | Authenticated encryption of quarantined files |
| Testing | pytest | Unit, integration, and regression tests |

The exact YARA package and operating-system integration must be selected and verified during environment setup. The implementation must use a supported API rather than assume that different YARA implementations are interchangeable.

### 3.2 Frontend

| Component | Technology | Responsibility |
|---|---|---|
| UI framework | React | Dashboard components |
| Programming language | TypeScript | Type-safe frontend implementation |
| Build tool | Vite | Development server and production build |
| Styling | Tailwind CSS | Responsive dashboard interface |
| API communication | Fetch or an established HTTP client | REST communication |
| Live updates | Native WebSocket API | Receiving real-time security events |
| Testing | Vitest and React Testing Library | Component and frontend behavior tests |

The frontend must use a single consistent dependency set. Antigravity must not migrate between major framework versions or install unnecessary alternative UI libraries without an approved change.

### 3.3 Development Environment

- Google Antigravity for